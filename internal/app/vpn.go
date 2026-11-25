package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/uri"
)

// ImportVPN replaces one VPN URI without changing other stored credentials.
// An empty name selects the primary VPN.
func (s *Service) ImportVPN(name, raw string, random io.Reader) (string, error) {
	if s.isRoot() {
		return "", ErrRootForbidden
	}
	if name != "" && !config.ValidTunnelName(name) {
		return "", errors.New("invalid VPN tunnel name")
	}
	outbound, err := uri.Parse(raw)
	if err != nil {
		return "", err
	}
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return "", err
	}
	if outbound.Network == "xhttp" {
		if name == "" {
			return "", errors.New("XHTTP requires a named VPN tunnel with xray configured")
		}
		cfg, err := config.Load(paths.ConfigFile())
		if err != nil {
			return "", errors.New("XHTTP requires a named VPN tunnel with xray configured in a valid twarp.yaml")
		}
		xrayEnabled := false
		for _, tunnel := range cfg.VPN.Tunnels {
			if tunnel.Name == name && tunnel.Xray != nil {
				xrayEnabled = true
				break
			}
		}
		if !xrayEnabled {
			return "", errors.New("XHTTP requires a named VPN tunnel with xray configured")
		}
	}
	if err := config.UpdateSecrets(paths.SecretsFile(), func(secrets *config.Secrets) error {
		if secrets.ClashSecret == "" {
			var secret [32]byte
			if _, err := io.ReadFull(random, secret[:]); err != nil {
				return fmt.Errorf("generate clash secret: %w", err)
			}
			secrets.ClashSecret = hex.EncodeToString(secret[:])
		}
		if name == "" {
			secrets.VPNURI = raw
		} else {
			if secrets.VPNURIs == nil {
				secrets.VPNURIs = make(map[string]string)
			}
			secrets.VPNURIs[name] = raw
		}
		return nil
	}); err != nil {
		return "", err
	}
	return vpnProtocol(outbound), nil
}
