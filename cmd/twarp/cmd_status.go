package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/sysexec"
	"github.com/tiptop32/twarp/internal/uri"
)

const (
	statusProbeTimeout = 2 * time.Second
	egressProbeTimeout = 5 * time.Second
	geoWarningAge      = 7 * 24 * time.Hour
)

type statusReporter struct {
	w      io.Writer
	failed bool
}

func (reporter *statusReporter) line(level, check, detail string) {
	_, _ = fmt.Fprintf(reporter.w, "%-4s %s: %s\n", level, check, detail)
	if level == "FAIL" {
		reporter.failed = true
	}
}

func runStatus(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	flags := flag.NewFlagSet("twarp status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	checkNetwork := flags.Bool("net", false, "check the public egress address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "twarp status: unexpected arguments: %v\n", flags.Args())
		return 2
	}

	reporter := &statusReporter{w: stdout}
	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		reporter.line("FAIL", "config", err.Error())
		return 1
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			reporter.line("FAIL", "config", "run twarp migrate")
		} else {
			reporter.line("FAIL", "config", err.Error())
		}
		return 1
	}
	// Missing or unreadable secrets are reported, but the remaining checks still
	// run: status is what people use while the setup is incomplete.
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	switch {
	case errors.Is(err, os.ErrNotExist):
		reporter.line("FAIL", "secrets", "run twarp import < key.txt")
	case err != nil:
		reporter.line("FAIL", "secrets", err.Error())
	}

	checkSingBox(reporter, cfg, secrets, deps.HTTPClient)
	checkGateway(reporter, cfg.Gateway.Socks, deps.Dial)
	checkTunnel(reporter, deps.Runner)
	checkGatewayCIDRs(reporter, paths)
	checkGeo(reporter, paths.GeoDir(), deps.Now)
	if *checkNetwork {
		if secrets.VPNURI == "" {
			reporter.line("FAIL", "egress", "no vpn URI: run twarp import < key.txt")
		} else {
			checkEgress(reporter, secrets.VPNURI, deps.HTTPClient, deps.LookupIP)
		}
	}
	if reporter.failed {
		return 1
	}
	return 0
}

func checkSingBox(reporter *statusReporter, cfg config.Config, secrets config.Secrets, client *http.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), statusProbeTimeout)
	defer cancel()
	version, err := (singbox.Clash{Addr: cfg.ClashAPI, Secret: secrets.ClashSecret, Client: client}).Version(ctx)
	switch {
	case err == nil:
		reporter.line("OK", "sing-box", "sing-box "+version)
	case errors.Is(err, singbox.ErrUnauthorized):
		reporter.line("WARN", "sing-box", "running, but clash secret mismatch")
	default:
		reporter.line("FAIL", "sing-box", fmt.Sprintf("not reachable at %s (is the service installed? sudo twarp install)", cfg.ClashAPI))
	}
}

func checkGateway(reporter *statusReporter, address string, dial func(context.Context, string, string) (net.Conn, error)) {
	if dial == nil {
		reporter.line("FAIL", "gateway", "TCP dialer is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), statusProbeTimeout)
	defer cancel()
	connection, err := dial(ctx, "tcp", address)
	if err != nil {
		reporter.line("FAIL", "gateway", fmt.Sprintf("%s is not reachable: %v", address, err))
		return
	}
	_ = connection.Close()
	reporter.line("OK", "gateway", address+" is reachable")
}

type recordingRunner struct {
	sysexec.Runner
	routeOutput string
}

func (runner *recordingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := runner.Runner.Run(ctx, name, args...)
	if name == "route" && err == nil {
		runner.routeOutput = string(output)
	}
	return output, err
}

func checkTunnel(reporter *statusReporter, runner sysexec.Runner) {
	if runner == nil {
		reporter.line("FAIL", "tunnel", "system command runner is unavailable")
		return
	}
	recording := &recordingRunner{Runner: runner}
	conflict, err := launchd.DetectConflict(context.Background(), recording)
	if err != nil {
		reporter.line("FAIL", "tunnel", err.Error())
		return
	}
	switch {
	case conflict.OwnTUN:
		reporter.line("OK", "tunnel", fmt.Sprintf("%s %s holds the default route", conflict.Interface, conflict.Addr))
	case conflict.Hint != "":
		reporter.line("FAIL", "tunnel", fmt.Sprintf("%s %s: %s", conflict.Interface, conflict.Addr, conflict.Hint))
	default:
		reporter.line("WARN", "tunnel", fmt.Sprintf("default route via %s: twarp tunnel is not active", routeInterface(recording.routeOutput)))
	}
}

func routeInterface(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "interface:" {
			return fields[1]
		}
	}
	return "unknown interface"
}

func checkGatewayCIDRs(reporter *statusReporter, paths config.Paths) {
	prefixes, err := state.ReadPrefixes(paths.GatewayIPsFile(), paths.LockFile())
	if err != nil {
		reporter.line("FAIL", "gateway CIDRs", err.Error())
		return
	}
	if len(prefixes) == 0 {
		reporter.line("WARN", "gateway CIDRs", "0 CIDRs")
		return
	}
	reporter.line("OK", "gateway CIDRs", fmt.Sprintf("%d CIDRs", len(prefixes)))
}

func checkGeo(reporter *statusReporter, directory string, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	for _, source := range geo.DefaultSources {
		info, err := os.Stat(filepath.Join(directory, source.Name))
		if err != nil {
			reporter.line("FAIL", "geo", fmt.Sprintf("%s is missing: sudo twarp geo update", source.Name))
			continue
		}
		age := now().Sub(info.ModTime())
		if age < 0 {
			age = 0
		}
		days := int(age / (24 * time.Hour))
		detail := fmt.Sprintf("%s is %d days old", source.Name, days)
		if age > geoWarningAge {
			reporter.line("WARN", "geo", detail+": sudo twarp geo update")
		} else {
			reporter.line("OK", "geo", detail)
		}
	}
}

func checkEgress(reporter *statusReporter, vpnURI string, client *http.Client, lookupIP func(context.Context, string, string) ([]net.IP, error)) {
	if client == nil || lookupIP == nil {
		reporter.line("FAIL", "egress", "network dependencies are unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), egressProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.me/ip", nil)
	if err != nil {
		reporter.line("FAIL", "egress", err.Error())
		return
	}
	response, err := client.Do(request)
	if err != nil {
		reporter.line("FAIL", "egress", fmt.Sprintf("get external IP: %v", err))
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		reporter.line("FAIL", "egress", fmt.Sprintf("get external IP: unexpected status %s", response.Status))
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		reporter.line("FAIL", "egress", fmt.Sprintf("read external IP: %v", err))
		return
	}
	externalIP, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		reporter.line("FAIL", "egress", fmt.Sprintf("invalid external IP: %v", err))
		return
	}
	outbound, err := uri.Parse(vpnURI)
	if err != nil {
		reporter.line("FAIL", "egress", err.Error())
		return
	}
	serverIPs, err := lookupIP(ctx, "ip", outbound.Server)
	if err != nil || len(serverIPs) == 0 {
		if err == nil {
			err = errors.New("no addresses returned")
		}
		reporter.line("FAIL", "egress", fmt.Sprintf("resolve vpn server %s: %v", outbound.Server, err))
		return
	}
	for _, serverIP := range serverIPs {
		if serverIP.Equal(net.IP(externalIP.AsSlice())) {
			reporter.line("OK", "egress", "egress via vpn "+externalIP.String())
			return
		}
	}
	reporter.line("WARN", "egress", fmt.Sprintf("egress %s differs from vpn server %s (destination may be routed direct)", externalIP, serverIPs[0]))
}
