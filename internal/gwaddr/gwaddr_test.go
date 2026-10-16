package gwaddr

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fixedLookup(ips ...string) LookupFunc {
	return func(context.Context, string, string) ([]net.IP, error) {
		out := make([]net.IP, len(ips))
		for index, ip := range ips {
			out[index] = net.ParseIP(ip)
		}
		return out, nil
	}
}

func TestResolve(t *testing.T) {
	failing := func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("IP literal must not be resolved")
		return nil, nil
	}
	tests := []struct {
		name    string
		lookup  LookupFunc
		input   string
		want    string
		wantErr string
	}{
		{name: "ipv4 literal", lookup: failing, input: "192.0.2.10:1080", want: "192.0.2.10:1080"},
		{name: "ipv6 literal", lookup: failing, input: "[2001:db8::10]:1080", want: "[2001:db8::10]:1080"},
		{name: "mDNS answer lists link-local first", lookup: fixedLookup("fe80::1", "192.0.2.10"), input: "proxy.local:8080", want: "192.0.2.10:8080"},
		{name: "ipv4 preferred over global ipv6", lookup: fixedLookup("2001:db8::10", "192.0.2.10"), input: "proxy.example:1080", want: "192.0.2.10:1080"},
		{name: "only global ipv6", lookup: fixedLookup("fe80::1", "2001:db8::10"), input: "proxy.example:1080", want: "[2001:db8::10]:1080"},
		{name: "ula ipv6", lookup: fixedLookup("fd00::10"), input: "proxy.example:1080", want: "[fd00::10]:1080"},
		{name: "only link-local", lookup: fixedLookup("fe80::1"), input: "proxy.local:8080", wantErr: "link-local"},
		{name: "loopback answer", lookup: fixedLookup("127.0.0.1"), input: "proxy.example:1080", wantErr: "loopback"},
		{name: "empty answer", lookup: fixedLookup(), input: "proxy.example:1080", wantErr: "no addresses"},
		{name: "bad port", lookup: failing, input: "proxy.example:0", wantErr: "invalid port"},
		{name: "no port", lookup: failing, input: "proxy.example", wantErr: "parse gateway.socks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Resolve(context.Background(), test.lookup, test.input)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Resolve(%q) error = %v, want %q", test.input, err, test.wantErr)
				}
				return
			}
			if err != nil || got != netip.MustParseAddrPort(test.want) {
				t.Fatalf("Resolve(%q) = (%v, %v), want %s", test.input, got, err, test.want)
			}
		})
	}
}

func TestResolveTimesOut(t *testing.T) {
	var deadline time.Time
	lookup := func(ctx context.Context, _, _ string) ([]net.IP, error) {
		deadline, _ = ctx.Deadline()
		return nil, context.DeadlineExceeded
	}
	_, err := Resolve(context.Background(), lookup, "missing.local:8080")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > Timeout {
		t.Fatalf("lookup deadline in %s, want within %s", remaining, Timeout)
	}
}

func TestIsLiteral(t *testing.T) {
	for input, want := range map[string]bool{
		"192.0.2.10:1080": true, "[2001:db8::10]:1080": true, "proxy.local:8080": false, "garbage": false,
	} {
		if got := IsLiteral(input); got != want {
			t.Errorf("IsLiteral(%q) = %t, want %t", input, got, want)
		}
	}
}
