//go:build integration && darwin

package itest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/uri"
	"github.com/tiptop32/twarp/internal/xray"
)

func TestXraySidecarTrafficAndFailure(t *testing.T) {
	binary, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray executable not installed")
	}
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	decoy.EnableHTTP2 = true
	decoy.Config.ErrorLog = log.New(io.Discard, "", 0)
	decoy.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	decoy.StartTLS()
	defer decoy.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	upstreamDNS := &dnsStub{queries: make(map[string]int)}
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packet, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil || r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
			http.Error(w, "expected DoH request", http.StatusBadRequest)
			return
		}
		answer, err := upstreamDNS.response(packet)
		if err != nil {
			http.Error(w, "invalid DNS request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	}))
	defer doh.Close()
	primaryDNS := startDNSStub(t, "tcp")
	directDNS := startDNSStub(t, "udp")
	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpEcho.Close() }()
	var udpReceived atomic.Int32
	go func() {
		var data [512]byte
		for {
			n, source, err := udpEcho.ReadFrom(data[:])
			if err != nil {
				return
			}
			udpReceived.Add(1)
			_, _ = udpEcho.WriteTo(data[:n], source)
		}
	}()
	serverPort, listenPort, bridgePort := freePort(t), freePort(t), freePort(t)
	name := fmt.Sprintf("secondary-%d", listenPort)
	raw, server := realityFixture(t, serverPort, decoy.Listener.Addr().String(), udpEcho.LocalAddr().(*net.UDPAddr).Port)
	stopServer := startXrayProcess(t, binary, serverPort, server)

	f := newRenderedFixtureWithProfiles(t, 0, "", fmt.Sprintf("  tunnels:\n    - name: %s\n      domains: [ai.example]\n      xray: {listen_port: %d, bridge_port: %d}\n", name, listenPort, bridgePort), map[string]string{name: raw})
	tag := "vpn-" + name
	dohPort := doh.Listener.Addr().(*net.TCPAddr).Port
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: doh.Certificate().Raw})
	patchDNSServers(t, f.configPath, map[string]dnsEndpoint{
		tag + "-dns": {network: "https", port: dohPort, keepDetour: true, certificate: string(certificate)},
		"remote":     {network: "tcp", port: primaryDNS.Port(), keepDetour: true},
		"direct":     {network: "udp", port: directDNS.Port()},
	})
	dnsPort := freeUDPPort(t)
	patchDirectDNSInbound(t, f.configPath, dnsPort, true)
	box := f.start(t)

	cfg, err := config.Load(filepath.Join(f.home, "twarp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := uri.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := xray.ClientConfig(cfg.VPN.Tunnels[0], f.clashSecret, profile)
	if err != nil {
		t.Fatal(err)
	}
	stopClient := startXrayClient(t, f, name, binary, listenPort, clientConfig)

	dial, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", box.mixedPort), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dial.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	target := "web.ai.example:" + strconv.Itoa(origin.Listener.Addr().(*net.TCPAddr).Port)
	response, err := client.Get("http://" + target)
	if err != nil {
		t.Fatalf("TCP through Xray: %v\nsing-box: %s", err, box.Log())
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("TCP through Xray returned %s, want 204", response.Status)
	}
	queryDNS(t, dnsPort, "chat.ai.example")
	if selected, other := upstreamDNS.QueryCount("chat.ai.example"), directDNS.QueryCount("chat.ai.example"); selected == 0 || other != 0 {
		t.Fatalf("DNS detour: selected got %d, direct got %d\nsing-box: %s", selected, other, box.Log())
	}
	// A UDP/443 payload, not merely DNS transported over TCP.
	sendXrayUDP(t, box.mixedPort, true)
	if udpReceived.Load() != 1 {
		t.Fatal("UDP test did not reach the expected receiver")
	}

	assertIndependent := func(stage string) {
		t.Helper()
		response, err := client.Get("http://" + target)
		if err == nil {
			_ = response.Body.Close()
			t.Fatalf("%s: selected TCP still succeeded", stage)
		}
		if f.vpn.ConnectCount(target) != 0 || directDNS.QueryCount("web.ai.example") != 0 {
			t.Fatalf("%s: selected traffic fell back", stage)
		}
		const offline = "offline.ai.example"
		answer, err := exec.Command("/usr/bin/dig", "+time=1", "+tries=1", "@127.0.0.1", "-p", strconv.Itoa(dnsPort), offline).CombinedOutput()
		if err == nil && !strings.Contains(string(answer), "status: SERVFAIL") {
			t.Fatalf("%s: selected DNS did not fail: %s", stage, answer)
		}
		if directDNS.QueryCount(offline) != 0 || f.vpn.ConnectCount("127.0.0.1:"+strconv.Itoa(primaryDNS.Port())) != 0 || f.vpn.ConnectCount("127.0.0.1:"+strconv.Itoa(dohPort)) != 0 {
			t.Fatalf("%s: DNS fell back from the selected Xray outbound", stage)
		}
		sendXrayUDP(t, box.mixedPort, false)
		if udpReceived.Load() != 1 || f.vpn.udpAssociations.Load() != 0 || directDNS.QueryCount("udp.ai.example") != 0 {
			t.Fatalf("%s: selected UDP reached an alternate route", stage)
		}
		main := box.openCONNECT(t, "main.example:80")
		defer func() { _ = main.Close() }()
		box.waitForOutbound(t, "main.example:80", "vpn", time.Second)
	}
	stopServer()
	assertIndependent("upstream stopped with Xray still listening")
	startXrayProcess(t, binary, serverPort, server)
	stopClient()
	assertIndependent("local Xray stopped")
	wrongConfig, err := xray.ClientConfig(cfg.VPN.Tunnels[0], "unrelated synthetic fixture secret", profile)
	if err != nil {
		t.Fatal(err)
	}
	stopWrong := startXrayProcess(t, binary, listenPort, wrongConfig)
	assertIndependent("another Xray listened with the wrong key")
	stopWrong()
	foreign := startSOCKSServerAt(t, fmt.Sprintf("127.0.0.1:%d", listenPort))
	assertIndependent("unrelated proxy took over the local port")
	if foreign.ConnectCount(target) != 0 {
		t.Fatal("unrelated proxy received the selected request")
	}
}

func realityFixture(t *testing.T, port int, decoy string, udpPort int) (string, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := syntheticSecrets(t, "")
	address, err := url.Parse(seed.VPNURI)
	if err != nil {
		t.Fatal(err)
	}
	address.Host = fmt.Sprintf("127.0.0.1:%d", port)
	query := address.Query()
	query.Set("pbk", base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
	address.RawQuery = query.Encode()
	document := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": []any{map[string]string{
				"id": address.User.Username(), "flow": query.Get("flow"),
			}}},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"target": decoy, "serverNames": []string{query.Get("sni")}, "shortIds": []string{query.Get("sid")},
					"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()),
				},
			},
		}},
		"dns": map[string]any{"hosts": map[string]string{"web.ai.example": "127.0.0.1"}},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "settings": map[string]string{"targetStrategy": "ForceIPv4"}},
			map[string]any{"protocol": "freedom", "tag": "udp-receiver", "settings": map[string]string{"redirect": fmt.Sprintf("127.0.0.1:%d", udpPort)}},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"network": "udp", "port": "443", "outboundTag": "udp-receiver"}}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return address.String(), data
}

func startXrayProcess(t *testing.T, binary string, port int, configJSON []byte) func() {
	t.Helper()
	command := exec.Command(binary, "run", "-c", "stdin:", "-format", "json")
	command.Env = []string{}
	command.Stdin = bytes.NewReader(configJSON)
	log := &lockedBuffer{}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	stop := func() {
		_ = command.Process.Kill()
		<-done
	}
	t.Cleanup(stop)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		select {
		case <-done:
			t.Fatalf("Xray exited: %s", log.String())
		default:
		}
		conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return stop
		}
	}
	t.Fatalf("Xray did not start: %s", log.String())
	return nil
}

func startXrayClient(t *testing.T, f *renderedFixture, name, binary string, port int, configJSON []byte) func() {
	t.Helper()
	if os.Getenv("TWARP_TEST_XRAY_LAUNCHD") != "1" {
		return startXrayProcess(t, binary, port, configJSON)
	}
	twarp := f.buildTWARP(t)
	run := func(operation string) ([]byte, error) {
		command := exec.Command(twarp, "xray", operation, name)
		command.Env = append(os.Environ(), "HOME="+f.home, "TWARP_HOME="+f.home, "TWARP_SINGBOX="+singBoxPath)
		return command.CombinedOutput()
	}
	stop := func() {
		if output, err := run("uninstall"); err != nil {
			t.Errorf("uninstall synthetic Xray agent: %v: %s", err, output)
		}
	}
	t.Cleanup(stop)
	if output, err := run("install"); err != nil {
		t.Fatalf("install synthetic Xray agent: %v: %s", err, output)
	}
	return stop
}

func sendXrayUDP(t *testing.T, mixedPort int, wantReply bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", mixedPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("SOCKS negotiation: %v %v", method, err)
	}
	if _, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[1] != 0 {
		t.Fatalf("SOCKS UDP association: %v %v", header, err)
	}
	if _, err := readSOCKSHost(conn, header[3]); err != nil {
		t.Fatal(err)
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", binary.BigEndian.Uint16(port[:])))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	deadline := time.Second
	if wantReply {
		deadline = 3 * time.Second
	}
	_ = udp.SetDeadline(time.Now().Add(deadline))
	const target = "udp.ai.example"
	packet := append([]byte{0, 0, 0, 3, byte(len(target))}, target...)
	packet = binary.BigEndian.AppendUint16(packet, 443)
	const payload = "twarp UDP payload"
	packet = append(packet, payload...)
	if _, err := udp.Write(packet); err != nil {
		t.Fatal(err)
	}
	var response [512]byte
	n, err := udp.Read(response[:])
	if wantReply && (err != nil || !bytes.HasSuffix(response[:n], []byte(payload))) {
		t.Fatalf("UDP/443 did not return an echo: received %d bytes: %v", n, err)
	}
	if !wantReply && err == nil {
		t.Fatal("UDP/443 unexpectedly received a reply without Xray")
	}
}
