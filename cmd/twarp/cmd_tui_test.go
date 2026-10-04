package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/state"
)

type fakeTUIBackend struct {
	status      app.Status
	netStatus   app.Status
	routes      app.Routes
	entries     []app.GatewayEntry
	connections []singbox.Connection
	connErr     error
	logs        []string
	installed   bool
	sudoErr     error
	added       []string
	removed     []string
	sudo        [][]string
}

func (backend *fakeTUIBackend) Status(_ context.Context, options app.StatusOptions) app.Status {
	if options.Network {
		return backend.netStatus
	}
	return backend.status
}

func (backend *fakeTUIBackend) Routes(context.Context) (app.Routes, error) {
	return backend.routes, nil
}

func (backend *fakeTUIBackend) Connections(context.Context) ([]singbox.Connection, error) {
	return backend.connections, backend.connErr
}

func (backend *fakeTUIBackend) Logs(int) ([]string, error) { return backend.logs, nil }

func (backend *fakeTUIBackend) ListGatewayCIDRs(context.Context) ([]app.GatewayEntry, error) {
	return backend.entries, nil
}

func (backend *fakeTUIBackend) AddGatewayCIDR(_ context.Context, request app.AddGatewayRequest) (app.AddResult, error) {
	prefix, err := netip.ParsePrefix(request.CIDR)
	if err != nil {
		return app.AddResult{}, errors.New("invalid CIDR")
	}
	backend.added = append(backend.added, request.CIDR+"|"+request.Comment)
	backend.entries = append(backend.entries, app.GatewayEntry{CIDR: prefix, Comment: request.Comment, AddedBy: app.ActorTUI})
	return app.AddResult{Status: state.AddStatusAdded, CIDR: prefix}, nil
}

func (backend *fakeTUIBackend) RemoveGatewayCIDR(_ context.Context, cidr string) (app.RemoveResult, error) {
	backend.removed = append(backend.removed, cidr)
	prefix := netip.MustParsePrefix(cidr)
	kept := backend.entries[:0]
	for _, entry := range backend.entries {
		if entry.CIDR != prefix {
			kept = append(kept, entry)
		}
	}
	backend.entries = kept
	return app.RemoveResult{Status: state.RemoveStatusRemoved, CIDR: prefix}, nil
}

func (backend *fakeTUIBackend) Installed() bool { return backend.installed }

func (backend *fakeTUIBackend) SudoCommand(args ...string) (*exec.Cmd, error) {
	backend.sudo = append(backend.sudo, args)
	if backend.sudoErr != nil {
		return nil, backend.sudoErr
	}
	return exec.Command("true"), nil
}

// newTestTUIModel turns polling and cursor blinking off, so every command the
// model returns finishes at once and tests can run them synchronously.
func newTestTUIModel(backend tuiBackend) tuiModel {
	model := newTUIModel(backend)
	model.fastEvery, model.statusEvery = 0, 0
	styles := model.input.Styles()
	styles.Cursor.Blink = false
	model.input.SetStyles(styles)
	return model
}

// send applies msg and feeds the results of the returned commands back.
func send(t *testing.T, model tuiModel, msg tea.Msg) tuiModel {
	t.Helper()
	next, cmd := model.Update(msg)
	model = next.(tuiModel)
	if cmd == nil {
		return model
	}
	return sendResult(t, model, cmd())
}

func sendResult(t *testing.T, model tuiModel, msg tea.Msg) tuiModel {
	t.Helper()
	switch msg := msg.(type) {
	case nil, tea.QuitMsg:
		return model
	case tea.BatchMsg:
		for _, cmd := range msg {
			if cmd != nil {
				model = sendResult(t, model, cmd())
			}
		}
		return model
	}
	return send(t, model, msg)
}

func key(text string) tea.KeyPressMsg {
	switch text {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	}
	return tea.KeyPressMsg{Code: []rune(text)[0], Text: text}
}

func typeText(t *testing.T, model tuiModel, text string) tuiModel {
	t.Helper()
	for _, r := range text {
		model = send(t, model, key(string(r)))
	}
	return model
}

func plainView(model tuiModel) string {
	return ansi.Strip(model.View().Content)
}

func dashboardBackend() *fakeTUIBackend {
	return &fakeTUIBackend{
		status: app.Status{
			Checks: []app.Check{
				{Level: app.LevelOK, Name: "sing-box", Detail: "sing-box 1.14.2"},
				{Level: app.LevelWarn, Name: "geo", Detail: "geoip-ru.srs is 9 days old: sudo twarp geo update"},
			},
			SingBoxRunning: true, SingBoxVersion: "1.14.2",
			TunnelActive: true, TunnelInterface: "utun8",
			GatewaySocks: "100.64.0.10:1080", GatewayReachable: true,
			GeoUpdated: time.Now().Add(-2 * time.Hour),
		},
		routes: app.Routes{
			GatewayDomains: []string{"intra.example", "dev.example"}, GatewayCIDRs: 8,
			DirectSuffixes: []string{".ru", ".su", ".рф"}, GeoRuleSets: []string{"geoip-ru", "geosite-category-ru"},
			VPNProtocol: "VLESS Reality",
			Rules: []app.RouteRule{
				{Action: "sniff", Match: "detect protocol and domain"},
				{Action: "route", Outbound: "gateway", Match: "domains intra.example, dev.example"},
				{Action: "route", Outbound: "vpn", Match: "everything else"},
			},
		},
		connections: []singbox.Connection{
			{Chains: []string{"vpn"}, Host: "www.example", DestinationIP: "198.51.100.7", DestinationPort: "443"},
			{Chains: []string{"gateway"}, Host: "intra.example", DestinationIP: "100.64.10.5", DestinationPort: "22"},
			{Chains: []string{"vpn"}, Host: "api.example", DestinationIP: "198.51.100.8", DestinationPort: "443"},
		},
	}
}

func initModel(t *testing.T, backend tuiBackend) tuiModel {
	t.Helper()
	model := newTestTUIModel(backend)
	return sendResult(t, model, model.Init()())
}

func TestTUIDashboardShowsStatusRoutesAndTraffic(t *testing.T) {
	model := newTestTUIModel(dashboardBackend())
	if !strings.Contains(plainView(model), "checking…") {
		t.Fatalf("initial view = %q, want checking", plainView(model))
	}
	model = initModel(t, dashboardBackend())
	view := plainView(model)
	for _, want := range []string{
		"Status:   ● Running", "TUN:      utun8",
		"Gateway:  ● OK", "VPN:      ● VLESS Reality",
		"Geo:      ● updated 2h ago", "sing-box: 1.14.2",
		"GATEWAY   2 domains", "8 CIDRs",
		"DIRECT    .ru .su .рф", "geoip-ru, geosite-category-ru",
		"VPN       VLESS Reality",
		"gateway   100.64.0.10:1080", "1 conn",
		"vpn       egress not checked [n]", "2 conns",
		"! geo: geoip-ru.srs is 9 days old",
		"[g] Gateway", "[s] Start/Stop", "[a] Apply", "[u] Geo update", "[?] Help",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("dashboard missing %q:\n%s", want, view)
		}
	}
}

func TestTUINetCheckShowsEgress(t *testing.T) {
	backend := dashboardBackend()
	backend.netStatus = backend.status
	backend.netStatus.Checks = append(backend.netStatus.Checks, app.Check{Level: app.LevelOK, Name: "egress", Detail: "egress via vpn 203.0.113.9"})
	backend.netStatus.EgressIP, backend.netStatus.EgressViaVPN = "203.0.113.9", true
	model := initModel(t, backend)
	model = send(t, model, key("n"))
	if view := plainView(model); !strings.Contains(view, "egress 203.0.113.9   OK") || strings.Contains(view, "checking egress") {
		t.Fatalf("view = %q, want egress result without the progress message", view)
	}
	// The periodic refresh skips the network probe: it keeps refreshing the
	// tunnel state and keeps the egress result.
	backend.status.TunnelActive = false
	model = send(t, model, statusTickMsg{})
	view := plainView(model)
	if !strings.Contains(view, "egress 203.0.113.9") || !strings.Contains(view, "● Up, not routing") {
		t.Fatalf("view after tick = %q, want fresh status and kept egress", view)
	}
	model = send(t, model, key("R"))
	if view := plainView(model); !strings.Contains(view, "egress not checked [n]") {
		t.Fatalf("view after refresh = %q, want egress cleared", view)
	}
}

func TestTUIRootActionsUseSudoWithSameBinary(t *testing.T) {
	backend := dashboardBackend()
	model := initModel(t, backend)

	model = send(t, model, key("s"))
	if view := plainView(model); !strings.Contains(view, "stop the tunnel and disable autostart? sudo twarp stop [y/N]") {
		t.Fatalf("view = %q, want stop confirmation", view)
	}
	model = send(t, model, key("n"))
	if len(backend.sudo) != 0 {
		t.Fatalf("sudo after cancel = %v", backend.sudo)
	}
	model = send(t, model, key("s"))
	model = send(t, model, key("y"))
	model = send(t, model, key("a"))
	model = send(t, model, key("u"))
	got := make([]string, len(backend.sudo))
	for index, args := range backend.sudo {
		got[index] = strings.Join(args, " ")
	}
	if strings.Join(got, ",") != "stop,apply,geo update" {
		t.Fatalf("sudo commands = %v", got)
	}

	model = send(t, model, actionDoneMsg{action: "stop", output: "stopped; start again: sudo twarp start"})
	if view := plainView(model); !strings.Contains(view, "stopped; start again: sudo twarp start") {
		t.Fatalf("view = %q, want action output", view)
	}
	model = send(t, model, actionDoneMsg{action: "apply", output: "twarp apply: sing-box check failed", err: errors.New("exit status 1")})
	if view := plainView(model); !strings.Contains(view, "twarp apply: sing-box check failed") {
		t.Fatalf("view = %q, want action error", view)
	}

	backend.status.TunnelActive = false
	model = send(t, model, key("R"))
	model = send(t, model, key("s"))
	if view := plainView(model); !strings.Contains(view, "start the tunnel? sudo twarp start [y/N]") {
		t.Fatalf("view = %q, want start confirmation", view)
	}
	// A refresh while the prompt is open must not flip the confirmed action.
	backend.status.TunnelActive = true
	model = send(t, model, statusTickMsg{})
	send(t, model, key("y"))
	if last := backend.sudo[len(backend.sudo)-1]; strings.Join(last, " ") != "start" {
		t.Fatalf("sudo after refresh = %v, want start", last)
	}
}

func TestTUIGatewayAddAndRemove(t *testing.T) {
	backend := &fakeTUIBackend{
		entries: []app.GatewayEntry{{CIDR: netip.MustParsePrefix("100.64.10.0/24"), AddedBy: "cli", AddedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Comment: "dev network"}},
	}
	model := send(t, newTestTUIModel(backend), key("g"))
	view := plainView(model)
	for _, want := range []string{"twarp › Gateway CIDRs", "CIDR", "100.64.10.0/24", "cli", "2026-10-03", "dev network", "[+] Add"} {
		if !strings.Contains(view, want) {
			t.Fatalf("gateway view = %q, want %q", view, want)
		}
	}

	model = send(t, model, key("+"))
	model = typeText(t, model, "100.64.20.0/24")
	model = send(t, model, key("enter"))
	if !strings.Contains(plainView(model), "comment for 100.64.20.0/24") {
		t.Fatalf("view = %q, want comment prompt", plainView(model))
	}
	model = typeText(t, model, "lab")
	model = send(t, model, key("enter"))
	if strings.Join(backend.added, ",") != "100.64.20.0/24|lab" {
		t.Fatalf("added = %v", backend.added)
	}
	view = plainView(model)
	if !strings.Contains(view, "added 100.64.20.0/24") || !strings.Contains(view, "warning: twarp is not installed yet") || !strings.Contains(view, "lab") {
		t.Fatalf("view = %q, want added message, warning and refreshed list", view)
	}

	model = send(t, model, key("down"))
	model = send(t, model, key("d"))
	if !strings.Contains(plainView(model), "remove 100.64.20.0/24? [y/N]") {
		t.Fatalf("view = %q, want confirmation", plainView(model))
	}
	model = send(t, model, key("n"))
	if len(backend.removed) != 0 {
		t.Fatalf("removed after cancel = %v", backend.removed)
	}
	model = send(t, model, key("d"))
	model = send(t, model, key("y"))
	if strings.Join(backend.removed, ",") != "100.64.20.0/24" {
		t.Fatalf("removed = %v", backend.removed)
	}
	if view := plainView(model); !strings.Contains(view, "removed 100.64.20.0/24") || strings.Contains(view, "lab") {
		t.Fatalf("view = %q, want removed message and refreshed list", view)
	}
	if model.cursor != 0 {
		t.Fatalf("cursor = %d, want clamped to 0", model.cursor)
	}
}

func TestTUIGatewayAddErrorAndEscape(t *testing.T) {
	backend := &fakeTUIBackend{installed: true}
	model := send(t, newTestTUIModel(backend), key("g"))
	if !strings.Contains(plainView(model), "no gateway CIDRs") {
		t.Fatalf("view = %q, want empty hint", plainView(model))
	}

	model = send(t, model, key("+"))
	model = typeText(t, model, "q")
	model = send(t, model, key("esc"))
	if model.mode != modeBrowse || model.screen != screenGateway || len(backend.added) != 0 {
		t.Fatalf("mode = %v, screen = %v, added = %v after esc", model.mode, model.screen, backend.added)
	}

	model = send(t, model, key("+"))
	model = typeText(t, model, "bogus")
	model = send(t, model, key("enter"))
	model = send(t, model, key("enter"))
	if view := plainView(model); !strings.Contains(view, "invalid CIDR") {
		t.Fatalf("view = %q, want error", view)
	}
	model = send(t, model, key("esc"))
	if model.screen != screenDashboard {
		t.Fatalf("screen = %v after esc, want dashboard", model.screen)
	}
}

func TestTUIRoutesLogsConnectionsAndHelpScreens(t *testing.T) {
	backend := dashboardBackend()
	backend.logs = []string{"INFO router: started", "WARN dns: timeout"}
	model := initModel(t, backend)

	model = send(t, model, key("r"))
	view := plainView(model)
	for _, want := range []string{"twarp › Routes", "1.   sniff", "2.   gateway   domains intra.example, dev.example", "3.   vpn       everything else"} {
		if !strings.Contains(view, want) {
			t.Fatalf("routes view = %q, want %q", view, want)
		}
	}

	model = send(t, model, key("l"))
	if view := plainView(model); !strings.Contains(view, "WARN dns: timeout") {
		t.Fatalf("logs view = %q", view)
	}

	model = send(t, model, key("c"))
	view = plainView(model)
	for _, want := range []string{"3 connections · gateway 1 · vpn 2", "OUTBOUND", "intra.example", "100.64.10.5:22"} {
		if !strings.Contains(view, want) {
			t.Fatalf("connections view = %q, want %q", view, want)
		}
	}
	if strings.Index(view, "intra.example") > strings.Index(view, "api.example") {
		t.Fatalf("view = %q, want rows sorted by outbound", view)
	}
	backend.connErr = errors.New("connection refused")
	model = send(t, model, fastTickMsg{})
	if !strings.Contains(plainView(model), "sing-box is not reachable: connection refused") {
		t.Fatalf("view = %q, want error", plainView(model))
	}

	model = send(t, model, key("?"))
	if view := plainView(model); !strings.Contains(view, "run the same twarp binary under sudo") {
		t.Fatalf("help view = %q", view)
	}
}

func TestTUIFitsWindowWidth(t *testing.T) {
	model := initModel(t, dashboardBackend())
	model = send(t, model, tea.WindowSizeMsg{Width: 40, Height: 30})
	for _, line := range strings.Split(plainView(model), "\n") {
		if ansi.StringWidth(line) > 40 {
			t.Fatalf("line %q is wider than 40 columns", line)
		}
	}
}

func TestRunTUIRejectsRootAndArguments(t *testing.T) {
	stdout, stderr, code := runCLIForTest([]string{"tui"}, cliDeps{Sys: cliTestSys{euid: 0}})
	if code != 1 || stdout != "" || !strings.Contains(stderr, "do not run tui with sudo") {
		t.Fatalf("root tui = (%d, %q, %q), want refusal", code, stdout, stderr)
	}
	stdout, stderr, code = runCLIForTest([]string{"tui", "extra"}, cliDeps{Sys: cliTestSys{euid: 501}})
	if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: twarp tui") {
		t.Fatalf("tui extra = (%d, %q, %q), want usage", code, stdout, stderr)
	}
}

func TestLiveTUIBackendSharesAppLayer(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 192.0.2.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := newLiveTUIBackend(cliDeps{
		Sys:        cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(base, "out")}},
		Executable: func() (string, error) { return "/usr/local/bin/twarp", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := backend.AddGatewayCIDR(ctx, app.AddGatewayRequest{CIDR: "192.0.2.0/24"}); err == nil {
		t.Fatal("add outside allowed_ranges succeeded, want refusal")
	}
	if _, err := backend.AddGatewayCIDR(ctx, app.AddGatewayRequest{CIDR: "100.64.30.0/24", Comment: "lab"}); err != nil {
		t.Fatal(err)
	}
	entries, err := backend.ListGatewayCIDRs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].AddedBy != app.ActorTUI || entries[0].Comment != "lab" {
		t.Fatalf("entries = %+v, want one tui entry", entries)
	}
	routes, err := backend.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if routes.GatewayCIDRs != 1 || strings.Join(routes.GatewayDomains, ",") != "intra.example" {
		t.Fatalf("routes = %+v", routes)
	}
	backend.executable = filepath.Join(base, "missing")
	if _, err := backend.SudoCommand("apply"); err == nil {
		t.Fatal("sudo command for a missing binary succeeded")
	}
}

func TestSudoCommandRefusesReplaceableBinary(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "twarp")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "twarp-link")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	backend := liveTUIBackend{executable: link, ownerUID: os.Getuid()}
	command, err := backend.SudoCommand("geo", "update")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(command.Args, " "); got != "sudo -- "+resolved+" geo update" {
		t.Fatalf("sudo command = %q, want resolved binary", got)
	}

	if err := os.Chmod(binary, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.SudoCommand("apply"); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("world-writable binary error = %v", err)
	}
	if err := os.Chmod(binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.SudoCommand("apply"); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("world-writable directory error = %v", err)
	}
	if os.Getuid() != 0 {
		backend.ownerUID = 0
		if _, err := backend.SudoCommand("apply"); err == nil || !strings.Contains(err.Error(), "not root") {
			t.Fatalf("user-owned binary error = %v, want refusal", err)
		}
	}
}

func TestTUIRootActionReportsRefusedBinary(t *testing.T) {
	backend := dashboardBackend()
	backend.sudoErr = errors.New("refusing to run it under sudo: /home/alice/go/bin/twarp is owned by uid 501, not root")
	model := send(t, initModel(t, backend), key("a"))
	if view := plainView(model); !strings.Contains(view, "apply: refusing to run it under sudo") {
		t.Fatalf("view = %q, want refusal message", view)
	}
}
