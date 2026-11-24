package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/resolver"
)

// SyncResolvers sends system DNS for gateway and named VPN domains to sing-box.
// Files owned by another tool are left in place and listed in the summary.
func (s *Service) SyncResolvers(ctx context.Context, cfg config.Config) (string, error) {
	if s.deps.ResolverDir == "" {
		return "", nil
	}
	domains := cfg.Gateway.Domains
	if len(cfg.VPN.Tunnels) != 0 {
		domains = slices.Clone(domains)
		for _, tunnel := range cfg.VPN.Tunnels {
			domains = append(domains, tunnel.Domains...)
		}
	}
	result, err := resolver.Sync(s.deps.ResolverDir, domains, render.TUNDNS)
	if result.Changed {
		s.flushDNSCache(ctx)
	}
	if err != nil {
		return "", fmt.Errorf("update %s: %w", s.deps.ResolverDir, err)
	}
	if len(result.Foreign) == 0 {
		return "", nil
	}
	return fmt.Sprintf("\nnot managed by twarp, left as is in %s: %s", s.deps.ResolverDir, strings.Join(result.Foreign, ", ")), nil
}

// RemoveResolvers removes twarp's resolver files so their domains use system
// DNS when the tunnel is down.
func (s *Service) RemoveResolvers(ctx context.Context) error {
	if s.deps.ResolverDir == "" {
		return nil
	}
	removed, err := resolver.RemoveAll(s.deps.ResolverDir)
	if removed {
		s.flushDNSCache(ctx)
	}
	if err != nil {
		return fmt.Errorf("clean %s: %w", s.deps.ResolverDir, err)
	}
	return nil
}

// flushDNSCache drops answers cached before the resolver change, such as the
// NXDOMAIN a gateway name got from the network DNS. mDNSResponder rereads the
// resolver directory on its own, so a failed flush only delays the change.
func (s *Service) flushDNSCache(ctx context.Context) {
	_, _ = s.deps.Runner.Run(ctx, "killall", "-HUP", "mDNSResponder")
}
