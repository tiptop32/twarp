package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

// GatewayEntry is one gateway CIDR with its provenance.
type GatewayEntry = state.Entry

// AddResult reports the outcome of AddGatewayCIDR.
type AddResult = state.AddResult

// RemoveResult reports the outcome of RemoveGatewayCIDR.
type RemoveResult = state.RemoveResult

// AddGatewayRequest is one gateway CIDR addition.
type AddGatewayRequest struct {
	CIDR    string
	Comment string
	// Force skips the allowed_ranges check. Only the CLI offers it.
	Force bool
}

// NotInstalledWarning explains why a successful change did not reach sing-box yet.
const NotInstalledWarning = "twarp is not installed yet: saved to gateway-ips.json; sudo twarp install will write the rule-set"

// Gateway manages the user-owned gateway CIDR list for one actor.
type Gateway struct {
	store         *state.Store
	actor         string
	allowedRanges []netip.Prefix
	rulesDir      string
}

// NewGateway wraps an existing store. Service.Gateway builds one from config.
func NewGateway(store *state.Store, actor string, allowedRanges []netip.Prefix, rulesDir string) *Gateway {
	return &Gateway{store: store, actor: actor, allowedRanges: append([]netip.Prefix(nil), allowedRanges...), rulesDir: rulesDir}
}

// Gateway loads config and returns the gateway list manager. It refuses root:
// the state, lock and audit files must stay owned by the user.
func (s *Service) Gateway() (*Gateway, error) {
	if s.isRoot() {
		return nil, ErrRootForbidden
	}
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.Gateway.Socks)
	if err != nil {
		return nil, fmt.Errorf("parse gateway.socks: %w", err)
	}
	gatewaySocks, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("gateway.socks host must be an IP address: %w", err)
	}

	var running func() bool
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err == nil {
		if s.deps.Clash != nil {
			running = s.deps.Clash(cfg, secrets)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	store := state.New(state.Options{
		File:          paths.GatewayIPsFile(),
		LockFile:      paths.LockFile(),
		AuditFile:     paths.AuditFile(),
		AllowedRanges: cfg.Gateway.AllowedRanges,
		GatewaySocks:  gatewaySocks,
		OnChange:      render.OnChangeWriter(paths.RulesDir()),
		Running:       running,
	})
	return NewGateway(store, s.actor, cfg.Gateway.AllowedRanges, paths.RulesDir()), nil
}

// ListGatewayCIDRs returns the gateway CIDRs sorted by address.
func (g *Gateway) ListGatewayCIDRs(context.Context) ([]GatewayEntry, error) {
	return g.store.List()
}

// AddGatewayCIDR validates and adds a CIDR. Before install the change is
// only saved; check Installed to tell the user.
func (g *Gateway) AddGatewayCIDR(ctx context.Context, request AddGatewayRequest) (AddResult, error) {
	return g.store.Add(ctx, g.actor, request.CIDR, request.Comment, request.Force)
}

// RemoveGatewayCIDR removes the exact normalized CIDR if present.
func (g *Gateway) RemoveGatewayCIDR(ctx context.Context, cidr string) (RemoveResult, error) {
	return g.store.Remove(ctx, g.actor, cidr)
}

// AllowedRanges returns gateway.allowed_ranges from twarp.yaml.
func (g *Gateway) AllowedRanges() []netip.Prefix {
	return append([]netip.Prefix(nil), g.allowedRanges...)
}

// Installed reports whether install created the rule-set that sing-box reads.
func (g *Gateway) Installed() bool {
	return render.Installed(g.rulesDir)
}

// AddResultText is the one-line summary of an add shared by front ends.
func AddResultText(result AddResult) string {
	switch result.Status {
	case state.AddStatusAlreadyPresent:
		return fmt.Sprintf("already present: %s", result.CIDR)
	case state.AddStatusCoveredBy:
		return fmt.Sprintf("covered by %s: %s", result.CoveredBy, result.CIDR)
	default:
		return fmt.Sprintf("added %s", result.CIDR)
	}
}

// RemoveResultText is the one-line summary of a remove shared by front ends.
func RemoveResultText(result RemoveResult) string {
	if result.Status == state.RemoveStatusRemoved {
		return fmt.Sprintf("removed %s", result.CIDR)
	}
	return fmt.Sprintf("not found: %s", result.CIDR)
}
