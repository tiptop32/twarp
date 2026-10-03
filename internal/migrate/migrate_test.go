package migrate_test

import (
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/migrate"
	"github.com/tiptop32/twarp/internal/state"
)

func TestRunRejectsMissingOrAmbiguousSOCKS5(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		source    string
		wantError string
	}{
		{
			name:      "no socks5 protocol",
			source:    "protocols:\n  - ssh:\n      host: legacy.example\n",
			wantError: "no socks5 protocol",
		},
		{
			name: "multiple socks5 protocols",
			source: `protocols:
  - socks5:
      host: 192.0.2.1:1080
  - socks5:
      host: 192.0.2.2:1080
`,
			wantError: "multiple socks5 protocols; choose one",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			source := filepath.Join(dir, "warp.yaml")
			if err := os.WriteFile(source, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := migrate.Run(migrate.Options{
				From:  source,
				Paths: config.Paths{Home: filepath.Join(dir, "twarp")},
				Sys:   fakeSys{euid: 501},
			})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Run() error = %v, want it to contain %q", err, test.wantError)
			}
		})
	}
}

func TestRunDoesNotOverwriteExistingConfigWithoutForce(t *testing.T) {
	t.Parallel()

	for _, destination := range []string{"config", "state"} {
		t.Run(destination, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			paths := config.Paths{Home: filepath.Join(dir, "twarp")}
			if err := os.MkdirAll(paths.Home, 0o700); err != nil {
				t.Fatal(err)
			}
			path := paths.ConfigFile()
			if destination == "state" {
				path = paths.GatewayIPsFile()
			}
			original := []byte("existing destination\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := migrate.Run(migrate.Options{
				From:  filepath.Join("testdata", "warp.yaml"),
				Paths: paths,
				Sys:   fakeSys{euid: 501},
			})
			if err == nil || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("Run() error = %v, want existing destination and --force", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !reflect.DeepEqual(got, original) {
				t.Fatalf("existing destination changed to %q", got)
			}
		})
	}
}

func TestRunSelectsAllowedRangesAndWarnsAboutIgnoredProtocols(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	source := filepath.Join(dir, "warp.yaml")
	legacy := `protocols:
  - ssh:
      host: ignored.example
  - socks5:
      host: 192.0.2.10:1080
      domains: [gateway.example]
      dns: [100.64.0.53]
      ips: [100.64.11.1/32, 10.1.2.3/32, 172.16.2.3/32, 192.168.2.3/32, 203.0.113.9/32]
`
	if err := os.WriteFile(source, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{Home: filepath.Join(dir, "twarp")}
	report, err := migrate.Run(migrate.Options{From: source, Paths: paths, Sys: fakeSys{euid: 501}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got, err := config.Load(paths.ConfigFile())
	if err != nil {
		t.Fatalf("Load(migrated config) error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("203.0.113.9/32"),
	}
	if !reflect.DeepEqual(got.Gateway.AllowedRanges, want) {
		t.Fatalf("allowed ranges = %#v, want %#v", got.Gateway.AllowedRanges, want)
	}
	for _, warning := range []string{
		"ignored warp protocol ssh",
		"public range 203.0.113.9/32 added to gateway.allowed_ranges",
	} {
		if !contains(report.Warnings, warning) {
			t.Errorf("Run() warnings = %q, want %q", report.Warnings, warning)
		}
	}
}

func TestRunRejectsRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := config.Paths{Home: filepath.Join(dir, "twarp")}
	_, err := migrate.Run(migrate.Options{
		From:  filepath.Join("testdata", "warp.yaml"),
		Paths: paths,
		Sys:   fakeSys{euid: 0},
	})
	if err == nil || !strings.Contains(err.Error(), "do not run migrate with sudo") {
		t.Fatalf("Run() error = %v, want sudo refusal", err)
	}
	if _, statErr := os.Stat(paths.Home); !os.IsNotExist(statErr) {
		t.Fatalf("migration created home as root: %v", statErr)
	}
}

func TestRunMigratesWarpConfig(t *testing.T) {
	t.Parallel()

	home := filepath.Join(t.TempDir(), "twarp")
	paths := config.Paths{Home: home}
	report, err := migrate.Run(migrate.Options{
		From:  filepath.Join("testdata", "warp.yaml"),
		Paths: paths,
		Sys:   fakeSys{euid: 501},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.ConfigWritten != paths.ConfigFile() || report.StateWritten != paths.GatewayIPsFile() || report.CIDRs != 8 {
		t.Fatalf("Run() report = %#v", report)
	}
	info, err := os.Stat(paths.Home)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o700 {
		t.Errorf("twarp home permissions = %04o, want 0700", permissions)
	}

	gotConfig, err := config.Load(paths.ConfigFile())
	if err != nil {
		t.Fatalf("Load(migrated config) error = %v", err)
	}
	wantDomains := []string{"intra.example", "chat.example", "meet.example", "video.example", "shop.example", "docs.example"}
	wantRanges := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	if gotConfig.Gateway.Socks != "192.168.1.10:1080" || gotConfig.Gateway.DNS != "100.64.0.53" {
		t.Errorf("migrated gateway endpoints = socks %q, DNS %q", gotConfig.Gateway.Socks, gotConfig.Gateway.DNS)
	}
	if !reflect.DeepEqual(gotConfig.Gateway.Domains, wantDomains) {
		t.Errorf("migrated domains = %#v, want %#v", gotConfig.Gateway.Domains, wantDomains)
	}
	if !reflect.DeepEqual(gotConfig.Gateway.AllowedRanges, wantRanges) {
		t.Errorf("migrated allowed ranges = %#v, want %#v", gotConfig.Gateway.AllowedRanges, wantRanges)
	}
	if !reflect.DeepEqual(gotConfig.Direct.LocalDomains, []string{"home.arpa"}) {
		t.Errorf("migrated local domains = %#v, want [home.arpa]", gotConfig.Direct.LocalDomains)
	}

	configText, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configText), "# fallback gateway DNS (manual): 192.168.100.53") {
		t.Errorf("migrated config lacks fallback DNS comment:\n%s", configText)
	}

	store := state.New(state.Options{
		File:          paths.GatewayIPsFile(),
		LockFile:      paths.LockFile(),
		AuditFile:     paths.AuditFile(),
		AllowedRanges: wantRanges,
		GatewaySocks:  netip.MustParseAddr("192.168.1.10"),
	})
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List(migrated state) error = %v", err)
	}
	wantCIDRs := map[string]bool{
		"100.64.10.182/32": true,
		"100.64.10.242/32": true,
		"100.64.10.108/32": true,
		"100.127.1.1/32":   true,
		"100.64.12.12/32":  true,
		"100.64.12.13/32":  true,
		"100.64.11.0/24":   true,
		"100.64.12.0/24":   true,
	}
	if len(entries) != len(wantCIDRs) {
		t.Fatalf("migrated CIDRs = %d, want %d", len(entries), len(wantCIDRs))
	}
	for _, entry := range entries {
		if !wantCIDRs[entry.CIDR.String()] {
			t.Errorf("unexpected migrated CIDR %s", entry.CIDR)
		}
		if entry.AddedBy != "migrate" || entry.Comment != "migrated from warp" {
			t.Errorf("migrated entry = %#v", entry)
		}
	}

	wantWarnings := []string{
		"host bits masked: 100.64.11.149/24 → 100.64.11.0/24",
		"host bits masked: 100.64.12.160/24 → 100.64.12.0/24",
		"mail.example.ru is already routed direct by the .ru rule",
	}
	for _, warning := range wantWarnings {
		if !contains(report.Warnings, warning) {
			t.Errorf("Run() warnings = %q, want %q", report.Warnings, warning)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type fakeSys struct {
	euid int
}

func (system fakeSys) Geteuid() int                   { return system.euid }
func (fakeSys) Getenv(string) string                  { return "" }
func (fakeSys) LookupUser(string) (*user.User, error) { return nil, os.ErrNotExist }
func (fakeSys) Stat(string) (os.FileInfo, error)      { return nil, os.ErrNotExist }

// A CIDR rejected by the hard safety rules must not leave a half-migrated
// state behind, even with --force over existing files.
func TestRunForceFailureKeepsExistingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := config.Paths{Home: filepath.Join(dir, "twarp")}
	if err := os.MkdirAll(paths.Home, 0o700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("existing config\n")
	originalState := []byte(`{"version":1,"cidrs":[]}` + "\n")
	if err := os.WriteFile(paths.ConfigFile(), originalConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.GatewayIPsFile(), originalState, 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "warp.yaml")
	legacy := "protocols:\n  - socks5:\n      host: 192.168.1.10:1080\n      domains: [intra.example]\n      dns: [100.64.0.53]\n" +
		"      ips: [100.64.10.182/32, 100.64.10.0/8]\n"
	if err := os.WriteFile(source, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := migrate.Run(migrate.Options{From: source, Paths: paths, Force: true, Sys: fakeSys{euid: 501}}); err == nil {
		t.Fatal("Run() error = nil, want rejected /8 CIDR")
	}

	for path, want := range map[string][]byte{paths.ConfigFile(): originalConfig, paths.GatewayIPsFile(): originalState} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s changed to %q after failed migration", filepath.Base(path), got)
		}
	}
	entries, err := os.ReadDir(paths.Home)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "tmp") {
			t.Errorf("temporary file %s left behind", entry.Name())
		}
	}
}
