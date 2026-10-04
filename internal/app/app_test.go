package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

type testSys struct {
	euid int
	env  map[string]string
}

func (system testSys) Geteuid() int                   { return system.euid }
func (system testSys) Getenv(name string) string      { return system.env[name] }
func (testSys) LookupUser(string) (*user.User, error) { return nil, errors.New("no users") }
func (testSys) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

func newTestService(t *testing.T, euid int) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 100.64.0.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\ndirect:\n  local_domains: [local.example]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	system := testSys{euid: euid, env: map[string]string{
		"TWARP_HOME": home, "TWARP_OUT": filepath.Join(base, "out"), "TWARP_LOG_DIR": filepath.Join(base, "log"),
		"SUDO_USER": "alice",
	}}
	return New(Deps{Sys: system}, ActorTUI), base
}

func TestRoutesFollowRenderedRuleOrder(t *testing.T) {
	service, _ := newTestService(t, 501)
	gateway, err := service.Gateway()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.AddGatewayCIDR(context.Background(), AddGatewayRequest{CIDR: "100.64.10.0/24"}); err != nil {
		t.Fatal(err)
	}
	routes, err := service.Routes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if routes.GatewayCIDRs != 1 || strings.Join(routes.DirectSuffixes, " ") != ".ru .su .рф" || routes.VPNProtocol != "" {
		t.Fatalf("routes = %+v", routes)
	}
	var order []string
	for _, rule := range routes.Rules {
		order = append(order, fmt.Sprintf("%s:%s", rule.Outbound, rule.Match))
	}
	got := strings.Join(order, "\n")
	want := strings.Join([]string{
		":detect protocol and domain",
		":DNS queries",
		"direct:gateway SOCKS 100.64.0.10/32",
		"gateway:domains intra.example",
		"gateway:gateway-ip rule-set (1 CIDRs)",
		"direct:private IP ranges",
		"direct:domains local.example",
		"direct:domains ru, su, рф",
		"direct:rule-sets geoip-ru, geosite-category-ru",
		"vpn:everything else",
	}, "\n")
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
}

func TestGatewayRefusesRootAndRootActionsRequireIt(t *testing.T) {
	root, _ := newTestService(t, 0)
	if _, err := root.Gateway(); !errors.Is(err, ErrRootForbidden) {
		t.Fatalf("root Gateway() error = %v, want ErrRootForbidden", err)
	}
	user, _ := newTestService(t, 501)
	ctx := context.Background()
	for name, action := range map[string]func() error{
		"start": func() error { _, err := user.Start(ctx); return err },
		"stop":  func() error { _, err := user.Stop(ctx); return err },
		"apply": func() error { _, err := user.Apply(ctx); return err },
		"geo":   func() error { _, err := user.GeoUpdate(ctx); return err },
	} {
		if err := action(); !errors.Is(err, ErrRootRequired) {
			t.Errorf("%s as user error = %v, want ErrRootRequired", name, err)
		}
	}
}

func TestLogsReturnsTail(t *testing.T) {
	service, base := newTestService(t, 501)
	if _, err := service.Logs(10); err == nil {
		t.Fatal("Logs without a log file succeeded")
	}
	if err := os.MkdirAll(filepath.Join(base, "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	for index := 1; index <= 5; index++ {
		fmt.Fprintf(&log, "line %d\n", index)
	}
	if err := os.WriteFile(filepath.Join(base, "log", "sing-box.log"), []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := service.Logs(2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "line 4,line 5" {
		t.Fatalf("lines = %v", lines)
	}
}
