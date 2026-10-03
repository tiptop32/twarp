package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestRunStatusReportsAllChecksOK(t *testing.T) {
	for _, euid := range []int{501, 0} {
		t.Run(map[int]string{501: "user", 0: "root"}[euid], func(t *testing.T) {
			fixture := newStatusFixture(t, http.StatusOK)
			if euid == 0 {
				system := fixture.deps.Sys.(cliTestSys)
				system.euid = 0
				system.env["SUDO_USER"] = "alice"
				fixture.deps.Sys = system
			}
			stdout, stderr, code := runCLIForTest([]string{"status"}, fixture.deps)

			if code != 0 || stderr != "" {
				t.Fatalf("status = (%d, %q, %q), want success", code, stdout, stderr)
			}
			for _, want := range []string{
				"OK   sing-box: sing-box 1.14.2",
				"OK   gateway: 192.0.2.10:1080 is reachable",
				"OK   tunnel: utun9 172.19.0.1 holds the default route",
				"OK   gateway CIDRs: 1 CIDRs",
				"OK   geo: geoip-ru.srs is 1 days old",
				"OK   geo: geosite-category-ru.srs is 1 days old",
			} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout = %q, want %q", stdout, want)
				}
			}
			if err := fixture.runner.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRunStatusReportsSingBoxFailuresAndSecretMismatch(t *testing.T) {
	t.Run("not running", func(t *testing.T) {
		fixture := newStatusFixture(t, http.StatusOK)
		fixture.server.Close()
		stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
		if code != 1 || !strings.Contains(stdout, "FAIL sing-box: not reachable at ") || !strings.Contains(stdout, "sudo twarp install") {
			t.Fatalf("status = (%d, %q), want sing-box failure", code, stdout)
		}
	})

	t.Run("secret mismatch", func(t *testing.T) {
		fixture := newStatusFixture(t, http.StatusUnauthorized)
		stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
		if code != 0 || !strings.Contains(stdout, "WARN sing-box: running, but clash secret mismatch") {
			t.Fatalf("status = (%d, %q), want warning without failure", code, stdout)
		}
	})
}

func TestRunStatusReportsUnavailableGateway(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	fixture.deps.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 1 || !strings.Contains(stdout, "FAIL gateway: 192.0.2.10:1080 is not reachable: connection refused") {
		t.Fatalf("status = (%d, %q), want gateway failure", code, stdout)
	}
}

func TestRunStatusReportsForeignTunnel(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	fixture.runner = &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: statusFixtureData(t, "route-utun-outline.txt")}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun7"}}, Response: sysexec.Response{Output: statusFixtureData(t, "ifconfig-utun-outline.txt")}},
	}}
	fixture.deps.Runner = fixture.runner
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 1 || !strings.Contains(stdout, "FAIL tunnel: utun7 10.8.0.2: another VPN") {
		t.Fatalf("status = (%d, %q), want foreign tunnel failure", code, stdout)
	}
	if err := fixture.runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStatusWarnsWhenTunnelIsInactive(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	fixture.runner = &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: statusFixtureData(t, "route-en0.txt")}},
	}}
	fixture.deps.Runner = fixture.runner
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "WARN tunnel: default route via en0: twarp tunnel is not active") {
		t.Fatalf("status = (%d, %q), want inactive tunnel warning", code, stdout)
	}
	if err := fixture.runner.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStatusWarnsWhenGatewayCIDRsAreEmpty(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	if err := os.Remove(filepath.Join(fixture.home, "gateway-ips.json")); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "WARN gateway CIDRs: 0 CIDRs") {
		t.Fatalf("status = (%d, %q), want empty CIDR warning", code, stdout)
	}
}

func TestRunStatusWarnsAboutStaleGeo(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	now := fixture.deps.Now()
	path := filepath.Join(fixture.out, "geo", "geoip-ru.srs")
	if err := os.Chtimes(path, now.Add(-9*24*time.Hour), now.Add(-9*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 0 || !strings.Contains(stdout, "WARN geo: geoip-ru.srs is 9 days old: sudo twarp geo update") {
		t.Fatalf("status = (%d, %q), want stale geo warning", code, stdout)
	}
}

func TestRunStatusFailsWhenGeoFileIsMissing(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusOK)
	if err := os.Remove(filepath.Join(fixture.out, "geo", "geoip-ru.srs")); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 1 || !strings.Contains(stdout, "FAIL geo: geoip-ru.srs is missing: sudo twarp geo update") {
		t.Fatalf("status = (%d, %q), want missing geo failure", code, stdout)
	}
}

func TestRunStatusNetComparesEgressWithVPNServer(t *testing.T) {
	for _, test := range []struct {
		name     string
		serverIP string
		want     string
	}{
		{name: "same", serverIP: "203.0.113.9", want: "OK   egress: egress via vpn 203.0.113.9"},
		{name: "different", serverIP: "198.51.100.7", want: "WARN egress: egress 203.0.113.9 differs from vpn server 198.51.100.7 (destination may be routed direct)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStatusFixture(t, http.StatusOK)
			fixture.deps.LookupIP = func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(test.serverIP)}, nil
			}
			stdout, _, code := runCLIForTest([]string{"status", "--net"}, fixture.deps)
			if code != 0 || !strings.Contains(stdout, test.want) {
				t.Fatalf("status --net = (%d, %q), want %q", code, stdout, test.want)
			}
		})
	}
}

func TestRunStatusMissingConfigDoesNotCreateHome(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "absent-home")
	stdout, stderr, code := runCLIForTest([]string{"status"}, cliDeps{Sys: cliTestSys{
		euid: 501,
		env:  map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(base, "out"), "TWARP_SINGBOX": "/test/sing-box"},
	}})
	if code != 1 || stderr != "" || stdout != "FAIL config: run twarp migrate\n" {
		t.Fatalf("status = (%d, %q, %q), want migrate failure", code, stdout, stderr)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status created home %q: %v", home, err)
	}
}

type statusFixture struct {
	deps   cliDeps
	runner *sysexec.Fake
	server *httptest.Server
	home   string
	out    string
}

func newStatusFixture(t *testing.T, clashStatus int) statusFixture {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	clash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			_, _ = fmt.Fprint(w, "203.0.113.9\n")
		case "/version":
		default:
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/version" {
			return
		}
		if clashStatus != http.StatusOK {
			w.WriteHeader(clashStatus)
			return
		}
		_, _ = fmt.Fprint(w, `{"version":"1.14.2"}`)
	}))
	t.Cleanup(clash.Close)
	target, err := url.Parse(clash.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: statusRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "ifconfig.me" {
			request = request.Clone(request.Context())
			copyURL := *request.URL
			copyURL.Scheme = target.Scheme
			copyURL.Host = target.Host
			request.URL = &copyURL
		}
		return transport.RoundTrip(request)
	})}

	base := t.TempDir()
	home := filepath.Join(base, "home")
	out := filepath.Join(base, "out")
	geoDir := filepath.Join(out, "geo")
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := fmt.Sprintf("gateway:\n  socks: 192.0.2.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\nclash_api: %s\n", clash.Listener.Addr())
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	vpnURI, _, _ := syntheticVPNURI(t)
	if err := config.SaveSecrets(filepath.Join(home, "secrets.yaml"), config.Secrets{VPNURI: vpnURI, ClashSecret: "test-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "gateway-ips.json"), []byte(`{"version":1,"cidrs":[{"cidr":"100.64.10.0/24","comment":"test","added_by":"cli","added_at":"2026-10-03T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, source := range geo.DefaultSources {
		path := filepath.Join(geoDir, source.Name)
		if err := os.WriteFile(path, []byte("SRS"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(-24*time.Hour), now.Add(-24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{
		{Call: sysexec.Call{Name: "route", Args: []string{"-n", "get", "1.1.1.1"}}, Response: sysexec.Response{Output: statusFixtureData(t, "route-utun-own.txt")}},
		{Call: sysexec.Call{Name: "ifconfig", Args: []string{"utun9"}}, Response: sysexec.Response{Output: statusFixtureData(t, "ifconfig-utun-own.txt")}},
	}}
	return statusFixture{
		deps: cliDeps{
			Sys:        cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": out, "TWARP_SINGBOX": "/test/sing-box"}},
			Runner:     runner,
			HTTPClient: client,
			Now:        func() time.Time { return now },
			Dial: func(context.Context, string, string) (net.Conn, error) {
				server, client := net.Pipe()
				_ = server.Close()
				return client, nil
			},
		},
		runner: runner,
		server: clash,
		home:   home,
		out:    out,
	}
}

type statusRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip statusRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func statusFixtureData(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "launchd", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// status is the command people run when setup is incomplete, so a missing
// secrets.yaml must be reported without hiding the remaining checks.
func TestRunStatusMissingSecretsKeepsOtherChecks(t *testing.T) {
	fixture := newStatusFixture(t, http.StatusUnauthorized)
	if err := os.Remove(filepath.Join(fixture.home, "secrets.yaml")); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runCLIForTest([]string{"status"}, fixture.deps)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1 for missing secrets", code)
	}
	for _, want := range []string{
		"FAIL secrets: run twarp import < key.txt",
		"WARN sing-box: running, but clash secret mismatch",
		"OK   gateway: 192.0.2.10:1080 is reachable",
		"OK   tunnel: utun9 172.19.0.1 holds the default route",
		"OK   geo: geoip-ru.srs is 1 days old",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	}
}
