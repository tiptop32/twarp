package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/resolver"
)

// SyncResolvers sends system DNS for the gateway domains to sing-box. It
// returns a note for the summary when some domains keep a resolver file that
// twarp does not own.
func (s *Service) SyncResolvers(ctx context.Context, domains []string) (string, error) {
	if s.deps.ResolverDir == "" {
		return "", nil
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

// RemoveResolvers removes the resolver files written by twarp, so gateway
// domains resolve through the network again while the tunnel is down.
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
