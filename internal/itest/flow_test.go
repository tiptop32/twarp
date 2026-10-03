//go:build integration

package itest

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestRenderedIPRoutingAndGatewayCLIHotReload(t *testing.T) {
	fixture := newRenderedFixture(t)
	box := fixture.start(t)

	assertOutbound(t, box, "198.51.100.10:80", "direct")
	assertOutbound(t, box, "203.0.113.10:80", "vpn")
	const dynamicDestination = "100.64.20.10:80"
	connection := box.openCONNECT(t, dynamicDestination)
	box.waitForOutbound(t, dynamicDestination, "vpn", time.Second)
	_ = connection.Close()
	box.waitForNoOutbound(t, dynamicDestination, time.Second)

	binary := fixture.buildTWARP(t)
	pid := box.command.Process.Pid
	started := time.Now()
	output := fixture.runTWARP(t, binary, "gateway", "add", "100.64.20.10")
	if !strings.Contains(output, "added 100.64.20.10/32") {
		t.Fatalf("gateway add output = %q, want added CIDR", output)
	}
	connection = waitForChangedOutbound(t, box, dynamicDestination, "gateway", started.Add(3*time.Second))
	_ = connection.Close()
	box.waitForNoOutbound(t, dynamicDestination, time.Second)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("gateway add became active in %s, want at most 3s", elapsed)
	} else {
		t.Logf("gateway add became active in %s", elapsed)
	}
	box.requireRunning(t)
	if got := box.command.Process.Pid; got != pid {
		t.Fatalf("sing-box PID changed from %d to %d during rule-set reload", pid, got)
	}

	output = fixture.runTWARP(t, binary, "gateway", "rm", "100.64.20.10")
	if !strings.Contains(output, "removed 100.64.20.10/32") {
		t.Fatalf("gateway rm output = %q, want removed CIDR", output)
	}
	connection = waitForChangedOutbound(t, box, dynamicDestination, "vpn", time.Now().Add(3*time.Second))
	_ = connection.Close()
	box.waitForNoOutbound(t, dynamicDestination, time.Second)
	box.requireRunning(t)
	if got := box.command.Process.Pid; got != pid {
		t.Fatalf("sing-box PID changed from %d to %d after gateway rm", pid, got)
	}
}

func TestRenderedDomainRouting(t *testing.T) {
	fixture := newRenderedFixture(t)
	directDNS := startDNSStub(t, "udp")
	patchDNSServers(t, fixture.configPath, map[string]dnsEndpoint{
		"direct": {network: "udp", port: directDNS.Port()},
	})
	box := fixture.start(t)

	assertOutbound(t, box, "host.intra.example:80", "gateway")
	assertOutbound(t, box, "example.com:80", "vpn")
	assertOutbound(t, box, "mail.ru:80", "direct")
}

func assertOutbound(t *testing.T, box *singBoxProcess, target, tag string) {
	t.Helper()
	connection := box.openCONNECT(t, target)
	box.waitForOutbound(t, target, tag, time.Second)
	if err := connection.Close(); err != nil {
		t.Fatalf("close %s connection: %v", target, err)
	}
}

func waitForChangedOutbound(
	t *testing.T,
	box *singBoxProcess,
	target string,
	tag string,
	deadline time.Time,
) net.Conn {
	t.Helper()
	for time.Now().Before(deadline) {
		connection := box.openCONNECT(t, target)
		if box.outboundWithin(target, tag, 150*time.Millisecond) {
			return connection
		}
		_ = connection.Close()
		box.waitForNoOutbound(t, target, 500*time.Millisecond)
	}
	t.Fatalf("did not observe outbound %q for %s before deadline; sing-box log:\n%s", tag, target, box.Log())
	return nil
}
