package gwaddr

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func staticLookup(ips ...string) LookupFunc {
	return func(context.Context, string, string) ([]net.IP, error) {
		result := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			result = append(result, net.ParseIP(ip))
		}
		return result, nil
	}
}

func TestResolve(t *testing.T) {
	notCalled := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("lookup must not run for an IP literal")
	}
	tests := []struct {
		name     string
		lookup   LookupFunc
		hostport string
		want     string
		wantErr  error
	}{
		{name: "ipv4 literal", lookup: notCalled, hostport: "192.0.2.10:1080", want: "192.0.2.10:1080"},
		{name: "ipv6 literal", lookup: notCalled, hostport: "[2001:db8::10]:1080", want: "[2001:db8::10]:1080"},
		{name: "mdns answer", lookup: staticLookup("fe80::1c2a:3bff:fe4d:5e6f", "192.0.2.10"), hostport: "proxyhost.local:8080", want: "192.0.2.10:8080"},
		{name: "first ipv4 wins", lookup: staticLookup("192.0.2.20", "192.0.2.10"), hostport: "proxy.example:8080", want: "192.0.2.20:8080"},
		{name: "link-local only", lookup: staticLookup("fe80::1"), hostport: "proxyhost.local:8080", wantErr: ErrNoIPv4},
		{name: "global ipv6 only", lookup: staticLookup("2001:db8::10"), hostport: "proxy.example:8080", wantErr: ErrNoIPv4},
		{name: "empty answer", lookup: staticLookup(), hostport: "proxy.example:8080", wantErr: ErrNoIPv4},
		{name: "loopback", lookup: staticLookup("127.0.0.1"), hostport: "proxy.example:8080", wantErr: ErrNoIPv4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(t.Context(), tt.lookup, tt.hostport)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Resolve() = %v, %v; want %v", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != netip.MustParseAddrPort(tt.want) {
				t.Fatalf("Resolve() = %v, %v; want %s", got, err, tt.want)
			}
		})
	}
}

func TestResolveErrors(t *testing.T) {
	failing := func(context.Context, string, string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "proxy.example", IsNotFound: true}
	}
	if _, err := Resolve(t.Context(), failing, "proxy.example:8080"); err == nil {
		t.Fatal("Resolve() with a failing lookup = nil error")
	}
	for _, bad := range []string{"proxy.example", "proxy.example:0", "proxy.example:x"} {
		if _, err := Resolve(t.Context(), staticLookup("192.0.2.10"), bad); err == nil {
			t.Fatalf("Resolve(%q) = nil error, want parse error", bad)
		}
	}
}

func TestResolveTimesOut(t *testing.T) {
	var deadline time.Time
	blocking := func(ctx context.Context, _, _ string) ([]net.IP, error) {
		deadline, _ = ctx.Deadline()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := Resolve(ctx, blocking, "missing.local:8080"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Resolve() = %v, want deadline exceeded", err)
	}
	if deadline.IsZero() || time.Until(deadline) > ResolveTimeout {
		t.Fatalf("lookup deadline = %v, want at most ResolveTimeout", deadline)
	}
}
