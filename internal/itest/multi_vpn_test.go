//go:build integration && darwin

package itest

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMultiVPNRouteAndFailure(t *testing.T) {
	proxyPort := freePort(t)
	f := newRenderedFixtureWithTunnels(t, proxyPort, "", "  tunnels:\n    - name: secondary\n      domains: [ai.example]\n      cidrs: [192.0.2.0/24]\n")
	box := f.start(t)
	const main, secondary, byIP, gateway = "video.example:80", "chat.ai.example:80", "192.0.2.8:80", "host.intra.example:80"
	for _, test := range []struct{ target, tag string }{{main, "vpn"}, {secondary, "vpn-secondary"}, {byIP, "vpn-secondary"}, {gateway, "gateway"}} {
		conn := box.openCONNECT(t, test.target)
		t.Cleanup(func() { _ = conn.Close() })
		box.waitForOutbound(t, test.target, test.tag, time.Second)
	}
	box.waitForOutbound(t, main, "vpn", time.Second)
	f.vpn.waitForConnectCount(t, main, 1, time.Second)
	stub := f.tunnels["secondary"]
	stub.waitForConnectCount(t, secondary, 1, time.Second)
	proxy := singBoxProcess{mixedPort: proxyPort}
	conn := proxy.openCONNECT(t, secondary)
	f.vpn.waitForConnectCount(t, secondary, 1, time.Second)
	_ = conn.Close()

	stub.stop()
	const failed = "offline.ai.example:80"
	conn = box.openCONNECT(t, failed)
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Mixed SOCKS sends its IPv4 CONNECT reply before attempting the route.
	var handshake [10]byte
	if _, err := io.ReadFull(conn, handshake[:]); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	var response [1]byte
	if _, err := conn.Read(response[:]); err == nil || os.IsTimeout(err) {
		t.Fatalf("unavailable secondary should close the connection, got %v", err)
	}
	if f.vpn.ConnectCount(failed) != 0 || f.gateway.ConnectCount(failed) != 0 || f.direct.ConnectCount(failed) != 0 {
		t.Fatal("new connection fell back to another outbound")
	}
	box.waitForOutbound(t, main, "vpn", time.Second)
}

func TestMultiVPNProcessWinsAndDNSUsesSelectedDetour(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	process := strings.ReplaceAll("^"+regexp.QuoteMeta(executable)+"$", "'", "''")
	f := newRenderedFixtureWithTunnels(t, 0, "", fmt.Sprintf("  tunnels:\n    - name: domains\n      domains: [ai.example, home.arpa]\n    - name: apps\n      process_path_regex: ['%s']\n", process))
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := checkSingBox(t, data); err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, output)
	}
	box := f.start(t)
	assertOutbound(t, box, "chat.ai.example:80", "vpn-apps")
	assertOutbound(t, box, "host.intra.example:80", "gateway")
	// The DNS half below resolves this local name to a non-private address.
	// Here the matching hostname must win over both VPN selectors.
	assertOutbound(t, box, "private.home.arpa:80", "direct")
	f.direct.waitForConnectCount(t, "private.home.arpa:80", 1, time.Second)
	conn := box.openCONNECT(t, "192.0.2.19:80")
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: private.home.arpa\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	box.waitForOutbound(t, "192.0.2.19:80", "direct", time.Second)
	box.stop()

	domains, apps, local := startDNSStub(t, "tcp"), startDNSStub(t, "tcp"), startDNSStub(t, "udp")
	remote, direct := startDNSStub(t, "tcp"), startDNSStub(t, "udp")
	f.tunnels["apps"].EnableRelay()
	f.tunnels["domains"].EnableRelay()
	patchDNSServers(t, f.configPath, map[string]dnsEndpoint{
		"vpn-domains-dns": {network: "tcp", port: domains.Port(), keepDetour: true},
		"vpn-apps-dns":    {network: "tcp", port: apps.Port(), keepDetour: true},
		"local":           {network: "udp", port: local.Port()},
		"remote":          {network: "tcp", port: remote.Port()},
		"direct":          {network: "udp", port: direct.Port()},
	})
	dnsPort := freeUDPPort(t)
	patchDirectDNSInbound(t, f.configPath, dnsPort, true)
	box = f.start(t)
	queryDNS(t, dnsPort, "chat.ai.example")
	if apps.QueryCount("chat.ai.example") == 0 || domains.QueryCount("chat.ai.example") != 0 || f.tunnels["apps"].ConnectCount(net.JoinHostPort("127.0.0.1", fmt.Sprint(apps.Port()))) == 0 {
		t.Fatal("attributable DNS did not use the process tunnel and its SOCKS detour")
	}
	queryDNS(t, dnsPort, "private.home.arpa")
	if local.QueryCount("private.home.arpa") == 0 || apps.QueryCount("private.home.arpa") != 0 || domains.QueryCount("private.home.arpa") != 0 {
		t.Fatal("local DNS did not precede tunnel selectors")
	}
	output, err := exec.Command("/usr/bin/dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", "-p", fmt.Sprint(dnsPort), "chat.ai.example").CombinedOutput()
	domainResolver := net.JoinHostPort("127.0.0.1", fmt.Sprint(domains.Port()))
	if err != nil || strings.TrimSpace(string(output)) != "198.51.100.10" || domains.QueryCount("chat.ai.example") == 0 || f.tunnels["domains"].ConnectCount(domainResolver) == 0 || f.tunnels["apps"].ConnectCount(domainResolver) != 0 {
		t.Fatalf("query from another process did not select domain tunnel: %s (%v)", output, err)
	}
	// An unrelated IP-only request must not inherit the last DNS name for that IP.
	proxy := fmt.Sprintf("127.0.0.1:%d", box.mixedPort)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "/usr/bin/nc", "-d", "-w", "1", "-X", "5", "-x", proxy, "198.51.100.10", "80").Run()
	// The fixture's existing geo rule owns this IP in the absence of a hostname.
	f.direct.waitForConnectCount(t, "198.51.100.10:80", 1, time.Second)
	if f.tunnels["domains"].ConnectCount("198.51.100.10:80") != 0 {
		t.Fatal("IP-only traffic inherited the domain tunnel")
	}
	f.tunnels["domains"].stop()
	const offline = "offline.ai.example"
	output, err = exec.Command("/usr/bin/dig", "+time=1", "+tries=1", "@127.0.0.1", "-p", fmt.Sprint(dnsPort), offline).CombinedOutput()
	if err == nil && !strings.Contains(string(output), "status: SERVFAIL") {
		t.Fatalf("expected failed DNS request, got %s", output)
	}
	for _, alternate := range []*dnsStub{apps, local, remote, direct} {
		if alternate.QueryCount(offline) != 0 {
			t.Fatal("DNS request fell back to another resolver")
		}
	}
	if f.vpn.ConnectCount(domainResolver) != 0 || f.direct.ConnectCount(domainResolver) != 0 || f.gateway.ConnectCount(domainResolver) != 0 {
		t.Fatal("DNS request reached the selected resolver through a different outbound")
	}
}
