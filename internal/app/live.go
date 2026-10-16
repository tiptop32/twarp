package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/tiptop32/twarp/internal/config"
)

// LiveConfig describes the config.json sing-box runs on.
type LiveConfig struct {
	// Gateway is the gateway outbound endpoint in the running config.
	Gateway netip.AddrPort
	// AppliedAt is the config.json mtime.
	AppliedAt time.Time
}

// ReadLiveConfig reads the gateway endpoint from the installed config.json.
// The file is root-only (0600): users get the mtime from AppliedAt instead.
func ReadLiveConfig(path string) (LiveConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return LiveConfig{}, fmt.Errorf("stat running config: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return LiveConfig{}, fmt.Errorf("read running config: %w", err)
	}
	var document struct {
		Outbounds []struct {
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort uint16 `json:"server_port"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return LiveConfig{}, fmt.Errorf("decode running config: %w", err)
	}
	for _, outbound := range document.Outbounds {
		if outbound.Tag != OutboundGateway {
			continue
		}
		addr, err := netip.ParseAddr(outbound.Server)
		if err != nil {
			return LiveConfig{}, fmt.Errorf("running config: gateway server %q is not an IP address", outbound.Server)
		}
		return LiveConfig{Gateway: netip.AddrPortFrom(addr, outbound.ServerPort), AppliedAt: info.ModTime()}, nil
	}
	return LiveConfig{}, errors.New("running config has no gateway outbound")
}

// AppliedAt returns the config.json mtime; stat needs no read permission.
func AppliedAt(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// ConfigStale reports whether twarp.yaml or secrets.yaml changed after the
// running config was applied.
func ConfigStale(paths config.Paths, appliedAt time.Time) (bool, error) {
	for _, path := range []string{paths.ConfigFile(), paths.SecretsFile()} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if info.ModTime().After(appliedAt) {
			return true, nil
		}
	}
	return false, nil
}
