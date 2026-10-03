package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

type gatewayStore struct {
	Store         *state.Store
	AllowedRanges []netip.Prefix
	RulesDir      string
}

func newGatewayStore(deps cliDeps) (gatewayStore, error) {
	paths, err := config.Resolve(deps.Sys)
	if err != nil {
		return gatewayStore{}, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return gatewayStore{}, err
	}
	host, _, err := net.SplitHostPort(cfg.Gateway.Socks)
	if err != nil {
		return gatewayStore{}, fmt.Errorf("parse gateway.socks: %w", err)
	}
	gatewaySocks, err := netip.ParseAddr(host)
	if err != nil {
		return gatewayStore{}, fmt.Errorf("gateway.socks host must be an IP address: %w", err)
	}

	var running func() bool
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err == nil {
		if deps.Clash != nil {
			running = deps.Clash(cfg, secrets)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return gatewayStore{}, err
	}
	return gatewayStore{
		Store: state.New(state.Options{
			File:          paths.GatewayIPsFile(),
			LockFile:      paths.LockFile(),
			AuditFile:     paths.AuditFile(),
			AllowedRanges: cfg.Gateway.AllowedRanges,
			GatewaySocks:  gatewaySocks,
			OnChange:      render.OnChangeWriter(paths.RulesDir()),
			Running:       running,
		}),
		AllowedRanges: append([]netip.Prefix(nil), cfg.Gateway.AllowedRanges...),
		RulesDir:      paths.RulesDir(),
	}, nil
}
