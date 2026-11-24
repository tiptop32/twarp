package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestXrayRollbackRestartsOldJobAfterCancellation(t *testing.T) {
	dir := t.TempDir()
	job := xrayJob{
		domain: "gui/501", target: "gui/501/dev.twarp.xray-vpn2",
		config: filepath.Join(dir, "client.json"), plist: filepath.Join(dir, "agent.plist"),
	}
	fs := launchd.OSFS{}
	if err := fs.WriteFile(job.config, []byte("old config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile(job.plist, []byte("old plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runner := &cancelXrayBootstrap{cancel: cancel}
	service := New(Deps{Runner: runner, FS: fs}, ActorCLI)
	err := service.activateXray(ctx, job, true, []byte("candidate"), []byte("candidate plist"), 19080)
	if !errors.Is(err, context.Canceled) || !runner.restarted {
		t.Fatalf("rollback = %v, old job restarted = %v", err, runner.restarted)
	}
	for path, want := range map[string]string{job.config: "old config", job.plist: "old plist"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v", path, got, err)
		}
	}
}

type cancelXrayBootstrap struct {
	cancel    context.CancelFunc
	attempted bool
	restarted bool
}

func (runner *cancelXrayBootstrap) Run(ctx context.Context, _ string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch args[0] {
	case "bootout":
		return nil, nil
	case "print":
		return nil, errors.New("Could not find service")
	case "bootstrap":
		if !runner.attempted {
			runner.attempted = true
			runner.cancel()
			return nil, ctx.Err()
		}
		runner.restarted = true
		return nil, nil
	default:
		return nil, errors.New("unexpected launchctl operation")
	}
}

func TestSyncResolversInstallsAndRemovesNamedVPNDomains(t *testing.T) {
	dir := t.TempDir()
	flush := sysexec.ExpectedCall{Call: sysexec.Call{Name: "killall", Args: []string{"-HUP", "mDNSResponder"}}}
	runner := &sysexec.Fake{Expect: []sysexec.ExpectedCall{flush, flush}}
	service := New(Deps{ResolverDir: dir, Runner: runner}, ActorCLI)
	cfg := config.Config{
		Gateway: config.GatewayConfig{Domains: []string{"gateway.example"}},
		VPN:     config.VPNConfig{Tunnels: []config.Tunnel{{Domains: []string{"vpn.example"}}}},
	}
	if _, err := service.SyncResolvers(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gateway.example", "vpn.example"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != "# Managed by twarp; do not edit. Removed by: sudo twarp stop / uninstall\nnameserver 172.19.0.2\n" {
			t.Fatalf("%s did not select TUN DNS: %q, %v", name, data, err)
		}
	}
	cfg.VPN.Tunnels = nil
	if _, err := service.SyncResolvers(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vpn.example")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale resolver file was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "gateway.example")); err != nil {
		t.Fatal(err)
	}
}
