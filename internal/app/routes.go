package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/net/idna"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/state"
	"github.com/tiptop32/twarp/internal/uri"
)

// Outbound tags.
const (
	OutboundGateway = "gateway"
	OutboundDirect  = "direct"
	OutboundVPN     = "vpn"
)

// RouteRule is one rendered route rule in a readable form.
type RouteRule struct {
	Match    string
	Outbound string
	// Action is set for rules without an outbound, such as sniff.
	Action string
}

// Routes summarizes how traffic is split, from the same config the renderer uses.
type Routes struct {
	GatewaySocks   string
	GatewayDomains []string
	GatewayCIDRs   int
	DirectSuffixes []string
	LocalDomains   []string
	GeoRuleSets    []string
	// VPNProtocol is empty when no VPN URI is imported or it does not parse.
	VPNProtocol string
	// Rules are the route rules in sing-box order; unmatched traffic goes to vpn.
	Rules []RouteRule
}

// Routes loads config and gateway state and describes the routing.
func (s *Service) Routes(context.Context) (Routes, error) {
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return Routes{}, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return Routes{}, err
	}
	prefixes, err := state.ReadPrefixes(paths.GatewayIPsFile(), paths.LockFile())
	if err != nil {
		return Routes{}, err
	}
	rules, err := render.RouteRules(cfg)
	if err != nil {
		return Routes{}, err
	}
	routes := Routes{
		GatewaySocks:   cfg.Gateway.Socks,
		GatewayDomains: append([]string(nil), cfg.Gateway.Domains...),
		GatewayCIDRs:   len(prefixes),
		LocalDomains:   append([]string(nil), cfg.Direct.LocalDomains...),
	}
	for _, suffix := range render.DirectSuffixes() {
		routes.DirectSuffixes = append(routes.DirectSuffixes, "."+displayDomain(suffix))
	}
	for _, source := range geo.DefaultSources {
		routes.GeoRuleSets = append(routes.GeoRuleSets, strings.TrimSuffix(source.Name, ".srs"))
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Routes{}, err
	}
	if secrets.VPNURI != "" {
		if outbound, err := uri.Parse(secrets.VPNURI); err == nil {
			routes.VPNProtocol = vpnProtocol(outbound)
		}
	}
	for _, rule := range rules {
		routes.Rules = append(routes.Rules, describeRule(rule, len(prefixes)))
	}
	routes.Rules = append(routes.Rules, RouteRule{Match: "everything else", Outbound: OutboundVPN})
	return routes, nil
}

func vpnProtocol(outbound singbox.Outbound) string {
	protocol := strings.ToUpper(outbound.Type)
	if outbound.TLS != nil && outbound.TLS.Reality != nil {
		protocol += " Reality"
	}
	return protocol
}

func describeRule(rule singbox.RouteRule, gatewayCIDRs int) RouteRule {
	described := RouteRule{Outbound: rule.Outbound}
	switch {
	case rule.Action == "sniff":
		described.Action, described.Match = "sniff", "detect protocol and domain"
	case rule.Action == "hijack-dns":
		described.Action, described.Match = "hijack-dns", "DNS queries"
	case len(rule.IPCIDR) > 0:
		described.Match = "gateway SOCKS " + strings.Join(rule.IPCIDR, ", ")
	case len(rule.DomainSuffix) > 0:
		names := make([]string, len(rule.DomainSuffix))
		for index, suffix := range rule.DomainSuffix {
			names[index] = displayDomain(suffix)
		}
		described.Match = "domains " + strings.Join(names, ", ")
	case len(rule.RuleSet) == 1 && rule.RuleSet[0] == "gateway-ip":
		described.Match = fmt.Sprintf("gateway-ip rule-set (%d CIDRs)", gatewayCIDRs)
	case len(rule.RuleSet) > 0:
		described.Match = "rule-sets " + strings.Join(rule.RuleSet, ", ")
	case rule.IPIsPrivate:
		described.Match = "private IP ranges"
	default:
		described.Match = "rule"
	}
	if described.Action == "" {
		described.Action = "route"
	}
	return described
}

// displayDomain turns punycode labels such as xn--p1ai into Unicode.
func displayDomain(domain string) string {
	if unicode, err := idna.ToUnicode(domain); err == nil {
		return unicode
	}
	return domain
}

// Connections returns the active sing-box connections from the Clash API.
func (s *Service) Connections(ctx context.Context) ([]singbox.Connection, error) {
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return nil, err
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return singbox.Clash{Addr: cfg.ClashAPI, Secret: secrets.ClashSecret, Client: s.deps.HTTPClient}.Connections(ctx)
}

// logTailBytes bounds how much of the log Logs reads: the file grows until
// newsyslog rotates it.
const logTailBytes = 256 << 10

// Logs returns up to the last lines of the sing-box log.
func (s *Service) Logs(lines int) ([]string, error) {
	path := SingBoxLogFile(s.deps.Sys)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sing-box log: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat sing-box log: %w", err)
	}
	offset := max(info.Size()-logTailBytes, 0)
	data, err := io.ReadAll(io.NewSectionReader(file, offset, info.Size()-offset))
	if err != nil {
		return nil, fmt.Errorf("read sing-box log: %w", err)
	}
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return nil, nil
	}
	all := strings.Split(text, "\n")
	if offset > 0 && len(all) > 1 {
		all = all[1:] // the first line was cut by the offset
	}
	if lines > 0 && len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all, nil
}
