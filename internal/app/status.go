package app

import (
	"context"
	"errors"
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

// Level is the outcome of one status check.
type Level string

// Check levels.
const (
	LevelOK   Level = "OK"
	LevelWarn Level = "WARN"
	LevelFail Level = "FAIL"
)

// Check is one status check result.
type Check struct {
	Level  Level
	Name   string
	Detail string
}

// StatusOptions selects optional, slower checks.
type StatusOptions struct {
	// Network also compares the public egress address with the vpn server.
	Network bool
}

// Status is the result of every status check, plus the facts behind them for
// front ends that render a dashboard instead of a list.
type Status struct {
	Checks []Check

	SingBoxVersion string
	SingBoxRunning bool

	TunnelActive    bool
	TunnelInterface string
	TunnelAddr      string

	GatewaySocks     string
	GatewayReachable bool
	GatewayCIDRs     int

	// GeoUpdated is the oldest geo rule-set mtime; zero when one is missing.
	GeoUpdated time.Time

	// EgressIP is set when StatusOptions.Network ran and found the address.
	EgressIP     string
	EgressViaVPN bool
}

// Failed reports whether any check failed.
func (status Status) Failed() bool {
	for _, check := range status.Checks {
		if check.Level == LevelFail {
			return true
		}
	}
	return false
}

func (status *Status) add(level Level, name, detail string) {
	status.Checks = append(status.Checks, Check{Level: level, Name: name, Detail: detail})
}

// Status runs every status check. Only a missing or invalid config stops it
// early: status is what people use while the setup is incomplete.
func (s *Service) Status(ctx context.Context, options StatusOptions) Status {
	var status Status
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		status.add(LevelFail, "config", err.Error())
		return status
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			status.add(LevelFail, "config", "create ~/.config/twarp/twarp.yaml (see README)")
		} else {
			status.add(LevelFail, "config", err.Error())
		}
		return status
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	switch {
	case errors.Is(err, os.ErrNotExist):
		status.add(LevelFail, "secrets", "run twarp import < key.txt")
	case err != nil:
		status.add(LevelFail, "secrets", err.Error())
	}

	s.checkSingBox(ctx, &status, cfg, secrets)
	s.checkGateway(ctx, &status, cfg.Gateway.Socks)
	s.checkTunnel(ctx, &status)
	checkGatewayCIDRs(&status, paths)
	checkGeo(&status, paths.GeoDir(), s.now())
	if options.Network {
		if secrets.VPNURI == "" {
			status.add(LevelFail, "egress", "no vpn URI: run twarp import < key.txt")
		} else {
			s.checkEgress(ctx, &status, secrets.VPNURI)
		}
	}
	return status
}

func (s *Service) checkSingBox(ctx context.Context, status *Status, cfg config.Config, secrets config.Secrets) {
	ctx, cancel := context.WithTimeout(ctx, statusProbeTimeout)
	defer cancel()
	version, err := (singbox.Clash{Addr: cfg.ClashAPI, Secret: secrets.ClashSecret, Client: s.deps.HTTPClient}).Version(ctx)
	switch {
	case err == nil:
		status.SingBoxRunning, status.SingBoxVersion = true, version
		status.add(LevelOK, "sing-box", "sing-box "+version)
	case errors.Is(err, singbox.ErrUnauthorized):
		status.SingBoxRunning = true
		status.add(LevelWarn, "sing-box", "running, but clash secret mismatch")
	default:
		status.add(LevelFail, "sing-box", fmt.Sprintf("not reachable at %s (is the service installed? sudo twarp install)", cfg.ClashAPI))
	}
}

func (s *Service) checkGateway(ctx context.Context, status *Status, address string) {
	status.GatewaySocks = address
	if s.deps.Dial == nil {
		status.add(LevelFail, "gateway", "TCP dialer is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, statusProbeTimeout)
	defer cancel()
	connection, err := s.deps.Dial(ctx, "tcp", address)
	if err != nil {
		status.add(LevelFail, "gateway", fmt.Sprintf("%s is not reachable: %v", address, err))
		return
	}
	_ = connection.Close()
	status.GatewayReachable = true
	status.add(LevelOK, "gateway", address+" is reachable")
}

func (s *Service) checkTunnel(ctx context.Context, status *Status) {
	if s.deps.Runner == nil {
		status.add(LevelFail, "tunnel", "system command runner is unavailable")
		return
	}
	conflict, err := launchd.DetectConflict(ctx, s.deps.Runner)
	if err != nil {
		status.add(LevelFail, "tunnel", err.Error())
		return
	}
	status.TunnelInterface, status.TunnelAddr = conflict.Interface, conflict.Addr
	switch {
	case conflict.OwnTUN:
		// A stale own utun can outlive the service after `twarp stop`
		// (launchd bootout removes the service, not the route), so the
		// route alone does not prove the tunnel is active.
		state, err := singBoxServiceState(ctx, s.deps.Runner)
		if err != nil {
			status.add(LevelFail, "tunnel", err.Error())
			return
		}
		if state != sysexec.ServiceRunning {
			status.add(LevelFail, "tunnel", fmt.Sprintf("stale route: %s %s holds the default route, but the sing-box service is not running; run: sudo twarp start", conflict.Interface, conflict.Addr))
			return
		}
		status.TunnelActive = true
		status.add(LevelOK, "tunnel", fmt.Sprintf("%s %s holds the default route", conflict.Interface, conflict.Addr))
	case conflict.Hint != "":
		status.add(LevelFail, "tunnel", fmt.Sprintf("%s %s: %s", conflict.Interface, conflict.Addr, conflict.Hint))
	default:
		status.add(LevelWarn, "tunnel", fmt.Sprintf("default route via %s: twarp tunnel is not active", conflict.Interface))
	}
}

// singBoxServiceState classifies the launchd sing-box service state. An
// unrecognized print failure surfaces as an error: the inspection failed, so
// the tunnel state cannot be judged.
func singBoxServiceState(ctx context.Context, runner sysexec.Runner) (sysexec.ServiceState, error) {
	output, err := runner.Run(ctx, "launchctl", "print", sysexec.SystemTarget())
	state := sysexec.PrintState(output, err)
	if state == sysexec.ServiceUnknown {
		return state, fmt.Errorf("inspect sing-box service: %w", err)
	}
	return state, nil
}

func checkGatewayCIDRs(status *Status, paths config.Paths) {
	prefixes, err := state.ReadPrefixes(paths.GatewayIPsFile(), paths.LockFile())
	if err != nil {
		status.add(LevelFail, "gateway CIDRs", err.Error())
		return
	}
	status.GatewayCIDRs = len(prefixes)
	if len(prefixes) == 0 {
		status.add(LevelWarn, "gateway CIDRs", "0 CIDRs")
		return
	}
	status.add(LevelOK, "gateway CIDRs", fmt.Sprintf("%d CIDRs", len(prefixes)))
}

func checkGeo(status *Status, directory string, now time.Time) {
	var oldest time.Time
	missing := false
	for _, source := range geo.DefaultSources {
		info, err := os.Stat(filepath.Join(directory, source.Name))
		if err != nil {
			missing = true
			status.add(LevelFail, "geo", fmt.Sprintf("%s is missing: sudo twarp geo update", source.Name))
			continue
		}
		if oldest.IsZero() || info.ModTime().Before(oldest) {
			oldest = info.ModTime()
		}
		age := max(now.Sub(info.ModTime()), 0)
		days := int(age / (24 * time.Hour))
		detail := fmt.Sprintf("%s is %d days old", source.Name, days)
		if age > geoWarningAge {
			status.add(LevelWarn, "geo", detail+": sudo twarp geo update")
		} else {
			status.add(LevelOK, "geo", detail)
		}
	}
	if !missing {
		status.GeoUpdated = oldest
	}
}

func (s *Service) checkEgress(ctx context.Context, status *Status, vpnURI string) {
	client, lookupIP := s.deps.HTTPClient, s.deps.LookupIP
	if client == nil || lookupIP == nil {
		status.add(LevelFail, "egress", "network dependencies are unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, egressProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.me/ip", nil)
	if err != nil {
		status.add(LevelFail, "egress", err.Error())
		return
	}
	response, err := client.Do(request)
	if err != nil {
		status.add(LevelFail, "egress", fmt.Sprintf("get external IP: %v", err))
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		status.add(LevelFail, "egress", fmt.Sprintf("get external IP: unexpected status %s", response.Status))
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		status.add(LevelFail, "egress", fmt.Sprintf("read external IP: %v", err))
		return
	}
	externalIP, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		status.add(LevelFail, "egress", fmt.Sprintf("invalid external IP: %v", err))
		return
	}
	status.EgressIP = externalIP.String()
	outbound, err := uri.Parse(vpnURI)
	if err != nil {
		status.add(LevelFail, "egress", err.Error())
		return
	}
	serverIPs, err := lookupIP(ctx, "ip", outbound.Server)
	if err != nil || len(serverIPs) == 0 {
		if err == nil {
			err = errors.New("no addresses returned")
		}
		status.add(LevelFail, "egress", fmt.Sprintf("resolve vpn server %s: %v", outbound.Server, err))
		return
	}
	for _, serverIP := range serverIPs {
		if serverIP.Equal(net.IP(externalIP.AsSlice())) {
			status.EgressViaVPN = true
			status.add(LevelOK, "egress", "egress via vpn "+externalIP.String())
			return
		}
	}
	status.add(LevelWarn, "egress", fmt.Sprintf("egress %s differs from vpn server %s (destination may be routed direct)", externalIP, serverIPs[0]))
}
