package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/singbox"
)

const (
	tuiFastRefresh    = 2 * time.Second
	tuiStatusInterval = 5 * time.Second
	tuiProbeTimeout   = 3 * time.Second
	tuiActionTimeout  = 5 * time.Second
	tuiNetTimeout     = 10 * time.Second
	tuiMaxWidth       = 84
)

// tuiBackend is what the TUI reads and changes. It is the application layer:
// *app.Service and *app.Gateway, plus the sudo command for root actions.
// Tests replace it with a fake.
type tuiBackend interface {
	Status(ctx context.Context, options app.StatusOptions) app.Status
	Routes(ctx context.Context) (app.Routes, error)
	Connections(ctx context.Context) ([]singbox.Connection, error)
	Logs(lines int) ([]string, error)
	ListGatewayCIDRs(ctx context.Context) ([]app.GatewayEntry, error)
	AddGatewayCIDR(ctx context.Context, request app.AddGatewayRequest) (app.AddResult, error)
	RemoveGatewayCIDR(ctx context.Context, cidr string) (app.RemoveResult, error)
	Installed() bool
	// SudoCommand runs this twarp binary under sudo with args. Root actions are
	// the only place the TUI starts a process: privileges cannot be raised in
	// process, and the sudo'd binary runs the same app.Service.
	SudoCommand(args ...string) *exec.Cmd
}

type liveTUIBackend struct {
	*app.Service
	*app.Gateway
	executable string
}

func (backend liveTUIBackend) SudoCommand(args ...string) *exec.Cmd {
	return exec.Command("sudo", append([]string{"--", backend.executable}, args...)...)
}

func runTUI(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.Sys.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "twarp tui: do not run tui with sudo; it asks for sudo only for start, stop, apply and geo update")
		return 1
	}
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp tui: usage: twarp tui")
		return 2
	}
	backend, err := newLiveTUIBackend(deps)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp tui: %v\n", err)
		return 1
	}
	program := tea.NewProgram(newTUIModel(backend), tea.WithInput(deps.Stdin), tea.WithOutput(stdout))
	if _, err := program.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp tui: %v\n", err)
		return 1
	}
	return 0
}

func newLiveTUIBackend(deps cliDeps) (liveTUIBackend, error) {
	service := deps.app(app.ActorTUI)
	gateway, err := service.Gateway()
	if err != nil {
		return liveTUIBackend{}, err
	}
	executable := "twarp"
	if deps.Executable != nil {
		if path, err := deps.Executable(); err == nil {
			executable = path
		}
	}
	return liveTUIBackend{Service: service, Gateway: gateway, executable: executable}, nil
}

type tuiScreen int

const (
	screenDashboard tuiScreen = iota
	screenGateway
	screenRoutes
	screenLogs
	screenConnections
	screenHelp
)

type tuiMode int

const (
	modeBrowse tuiMode = iota
	modeAddCIDR
	modeAddComment
	modeConfirmRemove
	modeConfirmToggle
)

type (
	statusMsg struct {
		status  app.Status
		network bool
	}
	routesMsg struct {
		routes app.Routes
		err    error
	}
	connectionsMsg struct {
		connections []singbox.Connection
		err         error
	}
	logsMsg struct {
		lines []string
		err   error
	}
	entriesMsg struct {
		entries []app.GatewayEntry
		err     error
	}
	gatewayDoneMsg struct {
		text     string
		warnings []string
		err      error
	}
	actionDoneMsg struct {
		action string
		output string
		err    error
	}
	fastTickMsg   struct{}
	statusTickMsg struct{}
)

type tuiModel struct {
	backend tuiBackend
	screen  tuiScreen
	mode    tuiMode
	width   int
	height  int

	status        app.Status
	statusLoaded  bool
	statusLoading bool
	netChecked    bool

	routes    app.Routes
	routesErr error

	connections    []singbox.Connection
	connectionsErr error

	logs    []string
	logsErr error

	entries    []app.GatewayEntry
	entriesErr error
	cursor     int

	input       textinput.Model
	pendingCIDR string
	message     string
	messageErr  bool
}

func newTUIModel(backend tuiBackend) tuiModel {
	input := textinput.New()
	input.CharLimit = 128
	return tuiModel{backend: backend, input: input, statusLoading: true}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(m.loadStatus(false), m.loadRoutes(), m.loadConnections(), m.loadEntries(),
		fastTick(), statusTick())
}

func fastTick() tea.Cmd {
	return tea.Tick(tuiFastRefresh, func(time.Time) tea.Msg { return fastTickMsg{} })
}

func statusTick() tea.Cmd {
	return tea.Tick(tuiStatusInterval, func(time.Time) tea.Msg { return statusTickMsg{} })
}

func (m tuiModel) loadStatus(network bool) tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		timeout := tuiProbeTimeout
		if network {
			timeout = tuiNetTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return statusMsg{status: backend.Status(ctx, app.StatusOptions{Network: network}), network: network}
	}
}

func (m tuiModel) loadRoutes() tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		routes, err := backend.Routes(context.Background())
		return routesMsg{routes: routes, err: err}
	}
}

func (m tuiModel) loadConnections() tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), tuiProbeTimeout)
		defer cancel()
		connections, err := backend.Connections(ctx)
		return connectionsMsg{connections: connections, err: err}
	}
}

func (m tuiModel) loadLogs() tea.Cmd {
	backend, lines := m.backend, max(m.bodyHeight(), 20)
	return func() tea.Msg {
		logs, err := backend.Logs(lines)
		return logsMsg{lines: logs, err: err}
	}
}

func (m tuiModel) loadEntries() tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		entries, err := backend.ListGatewayCIDRs(context.Background())
		return entriesMsg{entries: entries, err: err}
	}
}

func (m tuiModel) addEntry(cidr, comment string) tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), tuiActionTimeout)
		defer cancel()
		result, err := backend.AddGatewayCIDR(ctx, app.AddGatewayRequest{CIDR: cidr, Comment: comment})
		if err != nil {
			return gatewayDoneMsg{err: err}
		}
		return gatewayDoneMsg{text: app.AddResultText(result), warnings: installWarnings(backend, result.Warnings)}
	}
}

func (m tuiModel) removeEntry(cidr string) tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), tuiActionTimeout)
		defer cancel()
		result, err := backend.RemoveGatewayCIDR(ctx, cidr)
		if err != nil {
			return gatewayDoneMsg{err: err}
		}
		return gatewayDoneMsg{text: app.RemoveResultText(result), warnings: installWarnings(backend, result.Warnings)}
	}
}

func installWarnings(backend tuiBackend, warnings []string) []string {
	if backend.Installed() {
		return warnings
	}
	return append(warnings, app.NotInstalledWarning)
}

// runRoot suspends the TUI and runs a root action through sudo, so the password
// prompt reaches the terminal. Output is captured and shown afterwards.
func (m tuiModel) runRoot(action string, args ...string) tea.Cmd {
	command := m.backend.SudoCommand(args...)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	return tea.ExecProcess(command, func(err error) tea.Msg {
		return actionDoneMsg{action: action, output: strings.TrimSpace(output.String()), err: err}
	})
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case statusMsg:
		m.status, m.statusLoaded, m.statusLoading = msg.status, true, false
		m.netChecked = msg.network
		if msg.network {
			m.message = "" // the egress row now shows the result
		}
		return m, nil
	case routesMsg:
		m.routes, m.routesErr = msg.routes, msg.err
		return m, nil
	case connectionsMsg:
		m.connections, m.connectionsErr = msg.connections, msg.err
		return m, nil
	case logsMsg:
		m.logs, m.logsErr = msg.lines, msg.err
		return m, nil
	case entriesMsg:
		m.entries, m.entriesErr = msg.entries, msg.err
		m.cursor = min(m.cursor, max(len(m.entries)-1, 0))
		return m, nil
	case gatewayDoneMsg:
		if msg.err != nil {
			m.setMessage(msg.err.Error(), true)
		} else {
			m.setMessage(strings.Join(append([]string{msg.text}, prefixAll("warning: ", msg.warnings)...), "; "), false)
		}
		return m, tea.Batch(m.loadEntries(), m.loadRoutes())
	case actionDoneMsg:
		text := msg.output
		if text == "" {
			text = msg.action + " finished"
		}
		if msg.err != nil && msg.output == "" {
			text = fmt.Sprintf("%s: %v", msg.action, msg.err)
		}
		m.setMessage(lastLine(text), msg.err != nil)
		m.statusLoading = true
		return m, tea.Batch(m.loadStatus(false), m.loadRoutes(), m.loadConnections())
	case fastTickMsg:
		// Poll only what is on screen: connections and logs change all the time,
		// and the gateway list picks up changes made through the CLI or MCP.
		cmds := []tea.Cmd{fastTick()}
		switch m.screen {
		case screenDashboard, screenConnections:
			cmds = append(cmds, m.loadConnections())
		case screenLogs:
			cmds = append(cmds, m.loadLogs())
		case screenGateway:
			cmds = append(cmds, m.loadEntries())
		}
		return m, tea.Batch(cmds...)
	case statusTickMsg:
		// The network check is manual (n): it reaches an outside service.
		if m.screen == screenDashboard && !m.statusLoading && !m.netChecked {
			m.statusLoading = true
			return m, tea.Batch(m.loadStatus(false), statusTick())
		}
		return m, statusTick()
	case tea.KeyPressMsg:
		if m.mode != modeBrowse {
			return m.updateDialog(msg)
		}
		return m.updateBrowse(msg)
	}
	return m, nil
}

func (m *tuiModel) setMessage(text string, isErr bool) {
	m.message, m.messageErr = text, isErr
}

func (m tuiModel) updateBrowse(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc", "backspace":
		m.screen = screenDashboard
		return m, nil
	case "?":
		m.screen = screenHelp
		return m, nil
	case "g":
		m.screen = screenGateway
		return m, m.loadEntries()
	case "r":
		m.screen = screenRoutes
		return m, m.loadRoutes()
	case "l":
		m.screen = screenLogs
		return m, m.loadLogs()
	case "c":
		m.screen = screenConnections
		return m, m.loadConnections()
	case "n":
		if m.statusLoading {
			return m, nil
		}
		m.statusLoading = true
		m.setMessage("checking egress…", false)
		return m, m.loadStatus(true)
	case "R", "ctrl+r":
		m.statusLoading, m.netChecked = true, false
		return m, tea.Batch(m.loadStatus(false), m.loadRoutes(), m.loadConnections(), m.loadEntries())
	case "s":
		// Start or stop depends on the tunnel state, so wait for the first status.
		if !m.statusLoaded {
			m.setMessage("status is still loading", true)
			return m, nil
		}
		m.mode = modeConfirmToggle
		return m, nil
	case "a":
		return m, m.runRoot("apply", "apply")
	case "u":
		return m, m.runRoot("geo update", "geo", "update")
	}
	if m.screen != screenGateway {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		m.cursor = max(m.cursor-1, 0)
	case "down", "j":
		m.cursor = min(m.cursor+1, max(len(m.entries)-1, 0))
	case "+", "insert":
		m.mode = modeAddCIDR
		m.message = ""
		m.input.Reset()
		m.input.Placeholder = "100.64.10.0/24"
		return m, m.input.Focus()
	case "d", "x", "delete":
		if len(m.entries) > 0 {
			m.mode = modeConfirmRemove
			m.pendingCIDR = m.entries[m.cursor].CIDR.String()
			m.message = ""
		}
	}
	return m, nil
}

func (m tuiModel) updateDialog(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.mode {
	case modeConfirmRemove, modeConfirmToggle:
		switch msg.String() {
		case "y", "Y":
			mode := m.mode
			m.mode = modeBrowse
			if mode == modeConfirmRemove {
				return m, m.removeEntry(m.pendingCIDR)
			}
			if m.status.TunnelActive {
				return m, m.runRoot("stop", "stop")
			}
			return m, m.runRoot("start", "start")
		case "n", "N", "esc", "q", "enter":
			m.mode = modeBrowse
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.mode = modeBrowse
		m.input.Blur()
		return m, nil
	case "enter":
		value := strings.TrimSpace(m.input.Value())
		if m.mode == modeAddCIDR {
			if value == "" {
				return m, nil
			}
			m.pendingCIDR = value
			m.mode = modeAddComment
			m.input.Reset()
			m.input.Placeholder = "comment (optional)"
			return m, nil
		}
		m.mode = modeBrowse
		m.input.Blur()
		return m, m.addEntry(m.pendingCIDR, value)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

var (
	styleTitle    = lipgloss.NewStyle().Bold(true)
	styleSection  = lipgloss.NewStyle().Bold(true)
	styleHeader   = lipgloss.NewStyle().Bold(true).Underline(true)
	styleDim      = lipgloss.NewStyle().Faint(true)
	styleKey      = lipgloss.NewStyle().Bold(true)
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styleFail     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleSelected = lipgloss.NewStyle().Reverse(true)
	styleBox      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

func (m tuiModel) View() tea.View {
	inner := m.innerWidth()
	var title string
	var sections []string
	switch m.screen {
	case screenGateway:
		title, sections = "Gateway CIDRs", []string{m.viewGateway()}
	case screenRoutes:
		title, sections = "Routes", []string{m.viewRouteRules()}
	case screenLogs:
		title, sections = "sing-box log", []string{m.viewLogs()}
	case screenConnections:
		title, sections = "Connections", []string{m.viewConnections()}
	case screenHelp:
		title, sections = "Help", []string{viewHelp()}
	default:
		title = ""
		sections = []string{m.viewStatusGrid(), m.viewRoutesSummary(), m.viewTraffic()}
	}
	header := styleTitle.Render("twarp")
	if title != "" {
		header += styleDim.Render(" › ") + styleSection.Render(title)
	}
	parts := []string{lipgloss.PlaceHorizontal(inner, lipgloss.Center, header)}
	rule := styleDim.Render(strings.Repeat("─", inner))
	for _, section := range sections {
		parts = append(parts, rule, section)
	}
	if footer := m.viewFooter(); footer != "" {
		parts = append(parts, rule, footer)
	}
	parts = append(parts, rule, m.viewKeys())

	lines := strings.Split(strings.Join(parts, "\n"), "\n")
	for index, line := range lines {
		lines[index] = ansi.Truncate(line, inner, "…")
	}
	view := tea.NewView(styleBox.Width(inner + 4).Render(strings.Join(lines, "\n")))
	view.AltScreen = true
	view.WindowTitle = "twarp"
	return view
}

// innerWidth is the content width inside the border and padding.
func (m tuiModel) innerWidth() int {
	width := tuiMaxWidth
	if m.width > 0 {
		width = min(m.width, tuiMaxWidth)
	}
	return max(width-4, 20)
}

func dot(level app.Level) string {
	return levelStyle(level).Render("●")
}

func levelStyle(level app.Level) lipgloss.Style {
	switch level {
	case app.LevelOK:
		return styleOK
	case app.LevelWarn:
		return styleWarn
	default:
		return styleFail
	}
}

func (m tuiModel) checkLevel(name string) (app.Level, bool) {
	level, found := app.LevelOK, false
	for _, check := range m.status.Checks {
		if check.Name != name {
			continue
		}
		found = true
		if check.Level == app.LevelFail || (check.Level == app.LevelWarn && level == app.LevelOK) {
			level = check.Level
		}
	}
	return level, found
}

func (m tuiModel) viewStatusGrid() string {
	if !m.statusLoaded {
		return styleDim.Render("checking…")
	}
	status := m.status
	running := dot(app.LevelFail) + " Stopped"
	switch {
	case status.TunnelActive:
		running = dot(app.LevelOK) + " Running"
	case status.SingBoxRunning:
		running = dot(app.LevelWarn) + " Up, not routing"
	}
	tun := "—"
	if status.TunnelInterface != "" {
		tun = status.TunnelInterface
		if !status.TunnelActive {
			tun += styleDim.Render(" (not twarp)")
		}
	}
	gateway := dot(app.LevelFail) + " unreachable"
	if status.GatewayReachable {
		gateway = dot(app.LevelOK) + " OK"
	}
	vpn := dot(app.LevelFail) + " not imported"
	if m.routes.VPNProtocol != "" {
		vpn = dot(app.LevelOK) + " " + m.routes.VPNProtocol
		if level, found := m.checkLevel("egress"); found {
			vpn = dot(level) + " " + m.routes.VPNProtocol
		}
	}
	geo := dot(app.LevelFail) + " missing"
	if level, _ := m.checkLevel("geo"); !status.GeoUpdated.IsZero() {
		geo = dot(level) + " updated " + ago(time.Since(status.GeoUpdated))
	}
	version := "—"
	if status.SingBoxVersion != "" {
		version = status.SingBoxVersion
	} else if status.SingBoxRunning {
		version = "running"
	}
	rows := [][2]string{
		{"Status:   " + running, "TUN:      " + tun},
		{"Gateway:  " + gateway, "VPN:      " + vpn},
		{"Geo:      " + geo, "sing-box: " + version},
	}
	column := m.innerWidth() / 2
	lines := make([]string, 0, len(rows)+1)
	for _, row := range rows {
		lines = append(lines, padRight(row[0], column)+row[1])
	}
	if m.statusLoading {
		lines[0] += styleDim.Render("  ↻")
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) viewRoutesSummary() string {
	lines := []string{styleSection.Render("Routes"), ""}
	if m.routesErr != nil {
		return strings.Join(append(lines, styleFail.Render(m.routesErr.Error())), "\n")
	}
	routes := m.routes
	direct := strings.Join(routes.DirectSuffixes, " ")
	if len(routes.LocalDomains) > 0 {
		direct += fmt.Sprintf(" +%d local", len(routes.LocalDomains))
	}
	vpn := routes.VPNProtocol
	if vpn == "" {
		vpn = "not imported"
	}
	rows := [][]string{
		{"GATEWAY", plural(len(routes.GatewayDomains), "domain"), plural(routes.GatewayCIDRs, "CIDR")},
		{"DIRECT", direct, strings.Join(routes.GeoRuleSets, ", ")},
		{"VPN", vpn, "default"},
	}
	return strings.Join(append(lines, formatTable(nil, rows)...), "\n")
}

func (m tuiModel) viewTraffic() string {
	lines := []string{styleSection.Render("Traffic / checks")}
	counts := map[string]int{}
	for _, connection := range m.connections {
		counts[connection.Outbound()]++
	}
	conns := func(outbound string) string {
		if m.connectionsErr != nil {
			return styleDim.Render("—")
		}
		return plural(counts[outbound], "conn")
	}
	gatewayState := styleFail.Render("FAIL")
	if m.status.GatewayReachable {
		gatewayState = styleOK.Render("OK")
	}
	vpnTarget, vpnState := styleDim.Render("egress not checked [n]"), ""
	if m.status.EgressIP != "" {
		vpnTarget = "egress " + m.status.EgressIP
		vpnState = styleWarn.Render("WARN")
		if m.status.EgressViaVPN {
			vpnState = styleOK.Render("OK")
		}
	} else if level, found := m.checkLevel("egress"); found {
		vpnTarget, vpnState = "egress check failed", levelStyle(level).Render(string(level))
	}
	rows := [][]string{
		{app.OutboundGateway, m.status.GatewaySocks, gatewayState, conns(app.OutboundGateway)},
		{app.OutboundDirect, "ISP", "", conns(app.OutboundDirect)},
		{app.OutboundVPN, vpnTarget, vpnState, conns(app.OutboundVPN)},
	}
	lines = append(lines, formatTable(nil, rows)...)
	for _, check := range m.status.Checks {
		if check.Level != app.LevelOK {
			lines = append(lines, levelStyle(check.Level).Render("! "+check.Name+": "+check.Detail))
		}
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) viewRouteRules() string {
	if m.routesErr != nil {
		return styleFail.Render(m.routesErr.Error())
	}
	rows := make([][]string, 0, len(m.routes.Rules))
	for index, rule := range m.routes.Rules {
		target := rule.Outbound
		if target == "" {
			target = rule.Action
		}
		rows = append(rows, []string{fmt.Sprintf("%d.", index+1), target, rule.Match})
	}
	lines := formatTable([]string{"#", "TO", "MATCH"}, rows)
	lines[0] = styleHeader.Render(lines[0])
	lines = append(lines, "", styleDim.Render("gateway rules precede private ranges, so RFC1918 gateway hosts never go direct"))
	if len(m.routes.GatewayDomains) > 0 {
		lines = append(lines, styleDim.Render("gateway domains: "+strings.Join(m.routes.GatewayDomains, ", ")))
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) viewLogs() string {
	if m.logsErr != nil {
		return styleFail.Render(m.logsErr.Error())
	}
	if len(m.logs) == 0 {
		return styleDim.Render("log is empty")
	}
	lines := m.logs
	if limit := m.bodyHeight(); len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) viewGateway() string {
	if m.entriesErr != nil {
		return styleFail.Render(m.entriesErr.Error())
	}
	if len(m.entries) == 0 {
		return styleDim.Render("no gateway CIDRs: press + to add one")
	}
	rows := make([][]string, len(m.entries))
	for index, entry := range m.entries {
		rows[index] = []string{entry.CIDR.String(), entry.AddedBy, entry.AddedAt.UTC().Format(time.DateOnly), entry.Comment}
	}
	lines := formatTable([]string{"CIDR", "ADDED_BY", "ADDED_AT", "COMMENT"}, rows)
	start, end := visibleWindow(len(rows), m.cursor, m.bodyHeight()-1)
	out := []string{styleHeader.Render(lines[0])}
	for index := start; index < end; index++ {
		line := lines[index+1]
		if index == m.cursor {
			line = styleSelected.Render(padRight(line, m.innerWidth()))
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func (m tuiModel) viewConnections() string {
	if m.connectionsErr != nil {
		return styleFail.Render("sing-box is not reachable: " + m.connectionsErr.Error())
	}
	counts := map[string]int{}
	rows := make([][]string, len(m.connections))
	for index, connection := range m.connections {
		outbound := connection.Outbound()
		counts[outbound]++
		destination := connection.DestinationIP
		if connection.DestinationPort != "" {
			destination += ":" + connection.DestinationPort
		}
		rows[index] = []string{outbound, connection.Host, destination}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0] < rows[j][0]
		}
		return rows[i][1] < rows[j][1]
	})
	outbounds := make([]string, 0, len(counts))
	for outbound := range counts {
		outbounds = append(outbounds, outbound)
	}
	sort.Strings(outbounds)
	summary := []string{plural(len(m.connections), "connection")}
	for _, outbound := range outbounds {
		summary = append(summary, fmt.Sprintf("%s %d", outbound, counts[outbound]))
	}
	out := []string{strings.Join(summary, " · ")}
	if len(rows) == 0 {
		return out[0]
	}
	lines := formatTable([]string{"OUTBOUND", "HOST", "DESTINATION"}, rows)
	limit := max(m.bodyHeight()-3, 1)
	out = append(out, "", styleHeader.Render(lines[0]))
	for index, line := range lines[1:] {
		if index == limit {
			out = append(out, styleDim.Render(fmt.Sprintf("… %d more", len(rows)-limit)))
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func viewHelp() string {
	rows := [][]string{
		{"g", "gateway CIDRs: + add, d remove, ↑/↓ select"},
		{"r", "route rules in sing-box order"},
		{"l", "sing-box log, follows new lines"},
		{"c", "active connections by outbound"},
		{"n", "check egress through the vpn (contacts ifconfig.me)"},
		{"R", "refresh everything"},
		{"s", "start or stop the tunnel (sudo)"},
		{"a", "apply twarp.yaml and secrets.yaml (sudo)"},
		{"u", "update geo rule-sets (sudo)"},
		{"esc", "back to the dashboard"},
		{"q", "quit"},
	}
	lines := formatTable(nil, rows)
	return strings.Join(append(lines, "",
		styleDim.Render("Root actions suspend the TUI and run the same twarp binary under sudo."),
		styleDim.Render("Gateway changes apply without restarting sing-box.")), "\n")
}

func (m tuiModel) viewFooter() string {
	switch m.mode {
	case modeAddCIDR:
		return "add CIDR: " + m.input.View()
	case modeAddComment:
		return fmt.Sprintf("comment for %s: %s", m.pendingCIDR, m.input.View())
	case modeConfirmRemove:
		return styleWarn.Render(fmt.Sprintf("remove %s? [y/N]", m.pendingCIDR))
	case modeConfirmToggle:
		if m.status.TunnelActive {
			return styleWarn.Render("stop the tunnel and disable autostart? sudo twarp stop [y/N]")
		}
		return styleWarn.Render("start the tunnel? sudo twarp start [y/N]")
	}
	if m.message == "" {
		return ""
	}
	if m.messageErr {
		return styleFail.Render(m.message)
	}
	return styleOK.Render(m.message)
}

func (m tuiModel) viewKeys() string {
	switch m.mode {
	case modeAddCIDR, modeAddComment:
		return keys([2]string{"enter", "confirm"}, [2]string{"esc", "cancel"})
	case modeConfirmRemove, modeConfirmToggle:
		return keys([2]string{"y", "yes"}, [2]string{"n", "no"})
	}
	if m.screen == screenGateway {
		return keys([2]string{"+", "Add"}, [2]string{"d", "Remove"}, [2]string{"↑↓", "Select"}, [2]string{"esc", "Back"}, [2]string{"q", "Quit"})
	}
	if m.screen != screenDashboard {
		return keys([2]string{"esc", "Back"}, [2]string{"?", "Help"}, [2]string{"q", "Quit"})
	}
	return keys([2]string{"g", "Gateway"}, [2]string{"r", "Routes"}, [2]string{"l", "Logs"}, [2]string{"c", "Conns"}, [2]string{"s", "Start/Stop"}) + "\n" +
		keys([2]string{"a", "Apply"}, [2]string{"u", "Geo update"}, [2]string{"n", "Net check"}, [2]string{"?", "Help"}, [2]string{"q", "Quit"})
}

func keys(pairs ...[2]string) string {
	parts := make([]string, len(pairs))
	for index, pair := range pairs {
		parts[index] = styleKey.Render("["+pair[0]+"]") + " " + pair[1]
	}
	return strings.Join(parts, "  ")
}

// bodyHeight is the number of lines left for a screen body: the border,
// header, rules, footer and keys take ten.
func (m tuiModel) bodyHeight() int {
	if m.height <= 0 {
		return 1 << 20
	}
	return max(m.height-10, 2)
}

// visibleWindow returns the [start, end) range of rows that fits in height and
// keeps cursor visible.
func visibleWindow(total, cursor, height int) (start, end int) {
	height = max(height, 1)
	if total <= height {
		return 0, total
	}
	start = min(max(cursor-height+1, 0), total-height)
	return start, start + height
}

// formatTable aligns rows into lines; header comes first when given.
func formatTable(header []string, rows [][]string) []string {
	all := rows
	if header != nil {
		all = append([][]string{header}, rows...)
	}
	widths := map[int]int{}
	for _, row := range all {
		for column, cell := range row {
			widths[column] = max(widths[column], lipgloss.Width(cell))
		}
	}
	lines := make([]string, 0, len(all))
	for _, row := range all {
		cells := make([]string, len(row))
		for column, cell := range row {
			if column == len(row)-1 {
				cells[column] = cell
			} else {
				cells[column] = padRight(cell, widths[column])
			}
		}
		lines = append(lines, strings.TrimRight(strings.Join(cells, "   "), " "))
	}
	return lines
}

func padRight(text string, width int) string {
	return text + strings.Repeat(" ", max(width-lipgloss.Width(text), 0))
}

func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", count, noun)
}

func ago(age time.Duration) string {
	switch {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		return fmt.Sprintf("%dm ago", int(age/time.Minute))
	case age < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(age/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(age/(24*time.Hour)))
	}
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}

func prefixAll(prefix string, values []string) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = prefix + value
	}
	return out
}
