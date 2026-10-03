// Package migrate converts legacy warp configuration into twarp configuration and state.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/state"
	"go.yaml.in/yaml/v3"
)

// Options configures a legacy warp migration.
type Options struct {
	From  string
	Paths config.Paths
	Force bool
	Sys   config.Sys
}

// Report describes files written and migration decisions requiring attention.
type Report struct {
	ConfigWritten string
	StateWritten  string
	CIDRs         int
	Warnings      []string
}

type legacyConfig struct {
	Protocols      []map[string]yaml.Node `yaml:"protocols"`
	ExcludeDomains []string               `yaml:"exclude_domains"`
}

type legacySOCKS struct {
	Host    string   `yaml:"host"`
	Domains []string `yaml:"domains"`
	DNS     []string `yaml:"dns"`
	IPs     []string `yaml:"ips"`
}

var standardRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// Run migrates one legacy warp file into twarp.yaml and gateway-ips.json.
func Run(opts Options) (Report, error) {
	system := opts.Sys
	if system == nil {
		system = config.OSSys{}
	}
	if system.Geteuid() == 0 {
		return Report{}, errors.New("do not run migrate with sudo")
	}

	source, err := os.ReadFile(opts.From)
	if err != nil {
		return Report{}, fmt.Errorf("read legacy warp config %q: %w", opts.From, err)
	}

	var legacy legacyConfig
	if err := yaml.Unmarshal(source, &legacy); err != nil {
		return Report{}, fmt.Errorf("decode legacy warp config %q: %w", opts.From, err)
	}
	socks, protocolWarnings, err := selectSOCKS(legacy.Protocols)
	if err != nil {
		return Report{}, err
	}
	if len(socks.DNS) == 0 {
		return Report{}, errors.New("socks5 protocol has no DNS servers")
	}

	gatewaySocks, err := socksAddress(socks.Host)
	if err != nil {
		return Report{}, err
	}
	prefixes := make([]netip.Prefix, 0, len(socks.IPs))
	for _, input := range socks.IPs {
		prefix, _, err := state.Normalize(input)
		if err != nil {
			return Report{}, fmt.Errorf("normalize warp CIDR %q: %w", input, err)
		}
		prefixes = append(prefixes, prefix)
	}
	allowedRanges, rangeWarnings := minimalAllowedRanges(prefixes)
	localDomains, domainWarnings := localDomains(legacy.ExcludeDomains)

	configPath := opts.Paths.ConfigFile()
	statePath := opts.Paths.GatewayIPsFile()
	if !opts.Force {
		for _, path := range []string{configPath, statePath} {
			if _, err := os.Stat(path); err == nil {
				return Report{}, fmt.Errorf("destination %q already exists; use --force to overwrite", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return Report{}, fmt.Errorf("stat destination %q: %w", path, err)
			}
		}
	}
	if err := os.MkdirAll(opts.Paths.Home, 0o700); err != nil {
		return Report{}, fmt.Errorf("create twarp home %q: %w", opts.Paths.Home, err)
	}
	if err := os.Chmod(opts.Paths.Home, 0o700); err != nil {
		return Report{}, fmt.Errorf("set twarp home permissions %q: %w", opts.Paths.Home, err)
	}

	// Build both files next to their destinations and rename them only after
	// every CIDR passed validation, so a failure never leaves a half migration.
	stateTemp := statePath + ".migrate-tmp"
	configTemp := configPath + ".migrate-tmp"
	defer func() {
		_ = os.Remove(stateTemp)
		_ = os.Remove(configTemp)
	}()
	if err := os.Remove(stateTemp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Report{}, fmt.Errorf("remove stale temporary state %q: %w", stateTemp, err)
	}

	report := Report{
		ConfigWritten: configPath,
		StateWritten:  statePath,
		Warnings:      append(append(protocolWarnings, rangeWarnings...), domainWarnings...),
	}
	store := state.New(state.Options{
		File:          stateTemp,
		LockFile:      opts.Paths.LockFile(),
		AuditFile:     opts.Paths.AuditFile(),
		AllowedRanges: allowedRanges,
		GatewaySocks:  gatewaySocks,
	})
	for _, input := range socks.IPs {
		result, err := store.Add(context.Background(), "migrate", input, "migrated from warp", false)
		if err != nil {
			return Report{}, fmt.Errorf("migrate CIDR %q: %w", input, err)
		}
		report.Warnings = append(report.Warnings, result.Warnings...)
		if result.Status == state.AddStatusAdded {
			report.CIDRs++
		}
	}

	configText := renderConfig(socks, allowedRanges, localDomains)
	if err := os.WriteFile(configTemp, []byte(configText), 0o600); err != nil {
		return Report{}, fmt.Errorf("write migrated config %q: %w", configTemp, err)
	}
	if _, err := config.Load(configTemp); err != nil {
		return Report{}, fmt.Errorf("migrated config does not validate: %w", err)
	}
	if err := os.Rename(stateTemp, statePath); err != nil {
		return Report{}, fmt.Errorf("install migrated state %q: %w", statePath, err)
	}
	if err := os.Rename(configTemp, configPath); err != nil {
		return Report{}, fmt.Errorf("install migrated config %q: %w", configPath, err)
	}
	return report, nil
}

func selectSOCKS(protocols []map[string]yaml.Node) (legacySOCKS, []string, error) {
	var selected []legacySOCKS
	var warnings []string
	for _, protocol := range protocols {
		for name, node := range protocol {
			if name != "socks5" {
				warnings = append(warnings, fmt.Sprintf("ignored warp protocol %s", name))
				continue
			}
			var socks legacySOCKS
			if err := node.Decode(&socks); err != nil {
				return legacySOCKS{}, nil, fmt.Errorf("decode socks5 protocol: %w", err)
			}
			selected = append(selected, socks)
		}
	}
	if len(selected) == 0 {
		return legacySOCKS{}, nil, errors.New("legacy warp config has no socks5 protocol")
	}
	if len(selected) > 1 {
		return legacySOCKS{}, nil, errors.New("legacy warp config has multiple socks5 protocols; choose one before migrating")
	}
	return selected[0], warnings, nil
}

func socksAddress(hostPort string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse socks5 host %q: %w", hostPort, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse socks5 address %q: %w", host, err)
	}
	return addr.Unmap(), nil
}

func minimalAllowedRanges(prefixes []netip.Prefix) ([]netip.Prefix, []string) {
	var ranges []netip.Prefix
	var warnings []string
	for _, prefix := range prefixes {
		covered := false
		for _, standard := range standardRanges {
			if containsPrefix(standard, prefix) {
				if !containsPrefixIn(ranges, standard) {
					ranges = append(ranges, standard)
				}
				covered = true
				break
			}
		}
		if !covered && !containsPrefixIn(ranges, prefix) {
			ranges = append(ranges, prefix)
			warnings = append(warnings, fmt.Sprintf("public range %s added to gateway.allowed_ranges", prefix))
		}
	}
	return ranges, warnings
}

func containsPrefix(container, prefix netip.Prefix) bool {
	return container.Addr().BitLen() == prefix.Addr().BitLen() &&
		prefix.Bits() >= container.Bits() && container.Contains(prefix.Addr())
}

func containsPrefixIn(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == want {
			return true
		}
	}
	return false
}

func localDomains(domains []string) ([]string, []string) {
	var local []string
	var warnings []string
	for _, domain := range domains {
		normalized := strings.TrimLeft(strings.ToLower(strings.TrimSpace(domain)), ".")
		for _, suffix := range []string{"ru", "su", "xn--p1ai"} {
			if normalized == suffix || strings.HasSuffix(normalized, "."+suffix) {
				warnings = append(warnings, fmt.Sprintf("%s is already routed direct by the .%s rule", normalized, suffix))
				normalized = ""
				break
			}
		}
		if normalized != "" {
			local = append(local, normalized)
		}
	}
	return local, warnings
}

func renderConfig(socks legacySOCKS, allowedRanges []netip.Prefix, localDomains []string) string {
	var output strings.Builder
	output.WriteString("gateway:\n  socks: ")
	output.WriteString(strconv.Quote(socks.Host))
	output.WriteString("\n  domains:\n")
	for _, domain := range socks.Domains {
		output.WriteString("    - ")
		output.WriteString(strconv.Quote(domain))
		output.WriteByte('\n')
	}
	output.WriteString("  dns: ")
	output.WriteString(strconv.Quote(socks.DNS[0]))
	output.WriteByte('\n')
	for _, fallback := range socks.DNS[1:] {
		output.WriteString("  # fallback gateway DNS (manual): ")
		output.WriteString(fallback)
		output.WriteByte('\n')
	}
	output.WriteString("  allowed_ranges:\n")
	for _, prefix := range allowedRanges {
		output.WriteString("    - ")
		output.WriteString(strconv.Quote(prefix.String()))
		output.WriteByte('\n')
	}
	if len(localDomains) > 0 {
		output.WriteString("direct:\n  local_domains:\n")
		for _, domain := range localDomains {
			output.WriteString("    - ")
			output.WriteString(strconv.Quote(domain))
			output.WriteByte('\n')
		}
	}
	return output.String()
}
