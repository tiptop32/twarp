package launchd_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestDetectConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		route  string
		iface  string
		config string
		want   launchd.Conflict
	}{
		{name: "clean system", route: "route-en0.txt"},
		{
			name:   "Outline owns default route",
			route:  "route-utun-outline.txt",
			iface:  "utun7",
			config: "ifconfig-utun-outline.txt",
			want: launchd.Conflict{
				Interface: "utun7",
				Addr:      "10.8.0.2",
				Hint:      "another VPN holds the default route; quit it first",
			},
		},
		{
			name:   "twarp owns default route",
			route:  "route-utun-own.txt",
			iface:  "utun9",
			config: "ifconfig-utun-own.txt",
			want: launchd.Conflict{
				Interface: "utun9",
				Addr:      "172.19.0.1",
				OwnTUN:    true,
			},
		},
		{
			name:  "system utun interfaces without default route",
			route: "route-en0.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			expect := []sysexec.ExpectedCall{{
				Call:     sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}},
				Response: sysexec.Response{Output: fixture(t, tt.route)},
			}}
			if tt.iface != "" {
				expect = append(expect, sysexec.ExpectedCall{
					Call:     sysexec.Call{Name: "ifconfig", Args: []string{tt.iface}},
					Response: sysexec.Response{Output: fixture(t, tt.config)},
				})
			}
			runner := &sysexec.Fake{Expect: expect}

			got, err := launchd.DetectConflict(context.Background(), runner)
			if err != nil {
				t.Fatalf("DetectConflict() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("DetectConflict() = %#v, want %#v", got, tt.want)
			}
			if err := runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return contents
}
