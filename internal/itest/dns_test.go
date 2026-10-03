//go:build integration

package itest

import (
	"net"
	"strconv"
	"testing"
)

func TestRenderedDNSRoutingUsesSelectedStub(t *testing.T) {
	fixture := newRenderedFixture(t)
	gateway := startDNSStub(t, "tcp")
	direct := startDNSStub(t, "udp")
	remote := startDNSStub(t, "udp")
	// The gateway server keeps its "detour": "gateway", so its queries must
	// travel as TCP through the SOCKS gateway, exactly as in production.
	fixture.gateway.EnableRelay()
	patchDNSServers(t, fixture.configPath, map[string]dnsEndpoint{
		"gateway": {network: "tcp", port: gateway.Port(), keepDetour: true},
		"direct":  {network: "udp", port: direct.Port()},
		"remote":  {network: "udp", port: remote.Port()},
	})
	dnsPort := freeUDPPort(t)
	patchDirectDNSInbound(t, fixture.configPath, dnsPort)
	_ = startSingBoxWithConfig(t, fixture.configPath, 0, fixture.clashPort, fixture.clashSecret)

	tests := []struct {
		domain string
		stub   *dnsStub
	}{
		{domain: "host.intra.example", stub: gateway},
		{domain: "ya.ru", stub: direct},
		{domain: "example.com", stub: remote},
	}
	gatewayResolver := net.JoinHostPort("127.0.0.1", strconv.Itoa(gateway.Port()))
	for _, test := range tests {
		queryDNS(t, dnsPort, test.domain)
		if got := test.stub.QueryCount(test.domain); got == 0 {
			t.Fatalf("DNS stub %s received %d queries for %s, want at least one", test.stub.network, got, test.domain)
		}
		if test.stub == gateway && fixture.gateway.ConnectCount(gatewayResolver) == 0 {
			t.Fatalf("gateway DNS query for %s bypassed the SOCKS gateway", test.domain)
		}
		for _, other := range []*dnsStub{gateway, direct, remote} {
			if other != test.stub && other.QueryCount(test.domain) != 0 {
				t.Fatalf("unexpected %s DNS stub query for %s", other.network, test.domain)
			}
		}
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free UDP port: %v", err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release free UDP port: %v", err)
	}
	return port
}
