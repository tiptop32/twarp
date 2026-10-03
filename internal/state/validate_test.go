package state

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantPrefix   string
		wantWarnings []string
		wantErr      string
	}{
		{name: "bare IPv4", input: "100.66.1.1", wantPrefix: "100.66.1.1/32"},
		{name: "bare IPv6", input: "2001:db8::1", wantPrefix: "2001:db8::1/128"},
		{
			name: "IPv4 host bits", input: "100.66.65.149/24", wantPrefix: "100.66.65.0/24",
			wantWarnings: []string{"host bits masked: 100.66.65.149/24 → 100.66.65.0/24"},
		},
		{
			name: "IPv6 host bits", input: "2001:db8:abcd:12::dead/64", wantPrefix: "2001:db8:abcd:12::/64",
			wantWarnings: []string{"host bits masked: 2001:db8:abcd:12::dead/64 → 2001:db8:abcd:12::/64"},
		},
		{name: "bare mapped IPv4", input: "::ffff:100.66.1.1", wantPrefix: "100.66.1.1/32"},
		{name: "mapped IPv4 prefix", input: "::ffff:100.66.1.0/120", wantPrefix: "100.66.1.0/24"},
		{name: "mapped prefix shorter than mapping", input: "::ffff:100.66.1.1/95", wantErr: "mapped IPv6 prefix /95 is shorter than /96"},
		{name: "invalid input", input: "not-an-address", wantErr: "parse IP or CIDR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotWarnings, err := Normalize(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalize(%q) error = %v, want error containing %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) error = %v", tt.input, err)
			}
			if got := gotPrefix.String(); got != tt.wantPrefix {
				t.Errorf("Normalize(%q) prefix = %q, want %q", tt.input, got, tt.wantPrefix)
			}
			if !reflect.DeepEqual(gotWarnings, tt.wantWarnings) {
				t.Errorf("Normalize(%q) warnings = %q, want %q", tt.input, gotWarnings, tt.wantWarnings)
			}
		})
	}
}

func TestStoreHardRulesCannotBeForced(t *testing.T) {
	allowedRanges := prefixes(t, "0.0.0.0/0", "::/0")
	corpSocks := netip.MustParseAddr("100.66.10.42")
	tests := []struct {
		name    string
		prefix  string
		wantErr string
	}{
		{name: "IPv4 shorter than 16 bits", prefix: "10.0.0.0/8", wantErr: "IPv4 prefix must be /16 or longer"},
		{name: "IPv4 default route", prefix: "0.0.0.0/0", wantErr: "IPv4 prefix must be /16 or longer"},
		{name: "IPv6 shorter than 48 bits", prefix: "2001:db8::/32", wantErr: "IPv6 prefix must be /48 or longer"},
		{name: "IPv4 loopback", prefix: "127.0.0.1/32", wantErr: "loopback"},
		{name: "IPv6 loopback", prefix: "::1/128", wantErr: "loopback"},
		{name: "IPv4 unspecified", prefix: "0.0.0.0/32", wantErr: "unspecified"},
		{name: "IPv6 unspecified", prefix: "::/128", wantErr: "unspecified"},
		{name: "IPv4 link-local unicast", prefix: "169.254.10.0/24", wantErr: "link-local unicast"},
		{name: "IPv6 link-local unicast", prefix: "fe80::/64", wantErr: "link-local unicast"},
		{name: "IPv4 link-local multicast", prefix: "224.0.0.0/24", wantErr: "link-local multicast"},
		{name: "IPv6 link-local multicast", prefix: "ff02::/64", wantErr: "link-local multicast"},
		{name: "IPv4 multicast", prefix: "239.0.0.0/24", wantErr: "multicast"},
		{name: "IPv6 multicast", prefix: "ff05::/64", wantErr: "multicast"},
		{name: "limited broadcast", prefix: "255.255.255.255/32", wantErr: "limited broadcast"},
		{name: "contains corporate SOCKS", prefix: "100.66.10.0/24", wantErr: "contains corporate SOCKS address 100.66.10.42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions(t.TempDir(), nil, nil, nil)
			opts.AllowedRanges = allowedRanges
			opts.CorpSocks = corpSocks
			_, err := New(opts).Add(context.Background(), "cli", tt.prefix, "", true)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Add(%q, force=true) error = %v, want error containing %q", tt.prefix, err, tt.wantErr)
			}
		})
	}
}

func TestStoreAllowedRanges(t *testing.T) {
	allowedRanges := prefixes(t, "100.64.0.0/10", "10.0.0.0/8")
	corpSocks := netip.MustParseAddr("192.0.2.10")
	tests := []struct {
		name    string
		prefix  string
		force   bool
		wantErr string
	}{
		{name: "inside one allowed range", prefix: "100.66.65.0/24"},
		{name: "outside allowed ranges", prefix: "8.8.0.0/16", wantErr: "prefix 8.8.0.0/16 is outside allowed ranges: 100.64.0.0/10, 10.0.0.0/8"},
		{name: "force overrides allowed ranges", prefix: "8.8.0.0/16", force: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions(t.TempDir(), nil, func() bool { return true }, nil)
			opts.AllowedRanges = allowedRanges
			opts.CorpSocks = corpSocks
			_, err := New(opts).Add(context.Background(), "cli", tt.prefix, "", tt.force)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Add(%q, force=%t) error = %v, want error containing %q", tt.prefix, tt.force, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Add(%q, force=%t) error = %v", tt.prefix, tt.force, err)
			}
		})
	}
}

func TestStoreRequiresContainmentInOneAllowedRange(t *testing.T) {
	opts := testOptions(t.TempDir(), nil, nil, nil)
	opts.AllowedRanges = prefixes(t, "10.0.0.0/17", "10.0.128.0/17")
	opts.CorpSocks = netip.MustParseAddr("192.0.2.10")
	_, err := New(opts).Add(context.Background(), "cli", "10.0.0.0/16", "", false)
	if err == nil || !strings.Contains(err.Error(), "outside allowed ranges") {
		t.Fatalf("Add() error = %v, want outside allowed ranges error", err)
	}
}

func TestStoreRequiresCorpSocksConfiguration(t *testing.T) {
	opts := testOptions(t.TempDir(), nil, nil, nil)
	opts.CorpSocks = netip.Addr{}
	_, err := New(opts).Add(context.Background(), "cli", "100.66.1.1", "", false)
	if err == nil || !strings.Contains(err.Error(), "corporate SOCKS address is not configured") {
		t.Fatalf("Add() error = %v, want missing corporate SOCKS error", err)
	}
}

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("parse test prefix %q: %v", value, err)
		}
		result = append(result, prefix)
	}
	return result
}
