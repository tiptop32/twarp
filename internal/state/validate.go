package state

import (
	"fmt"
	"net/netip"
	"strings"
)

const mappedIPv4PrefixBits = 96

// Normalize parses an IP address or prefix and returns its canonical prefix.
// Bare IPv4 and IPv6 addresses become /32 and /128 prefixes, respectively.
func Normalize(input string) (netip.Prefix, []string, error) {
	if prefix, err := netip.ParsePrefix(input); err == nil {
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < mappedIPv4PrefixBits {
				return netip.Prefix{}, nil, fmt.Errorf(
					"mapped IPv6 prefix /%d is shorter than /%d",
					prefix.Bits(), mappedIPv4PrefixBits,
				)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-mappedIPv4PrefixBits)
		}

		masked := prefix.Masked()
		if prefix != masked {
			return masked, []string{fmt.Sprintf("host bits masked: %s → %s", input, masked)}, nil
		}
		return prefix, nil, nil
	}

	addr, err := netip.ParseAddr(input)
	if err != nil {
		return netip.Prefix{}, nil, fmt.Errorf("parse IP or CIDR %q: %w", input, err)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil, nil
}

// validatePrefix applies the hard network-safety rules and the configurable
// allowed-range policy. Force bypasses only the allowed-range policy.
func validatePrefix(prefix netip.Prefix, allowedRanges []netip.Prefix, corpSocks netip.Addr, force bool) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix")
	}

	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4() {
		if prefix.Bits() < 16 {
			return fmt.Errorf("IPv4 prefix must be /16 or longer: %s", prefix)
		}
	} else if prefix.Bits() < 48 {
		return fmt.Errorf("IPv6 prefix must be /48 or longer: %s", prefix)
	}

	switch {
	case addr.IsLoopback():
		return fmt.Errorf("loopback prefix is not allowed: %s", prefix)
	case addr.IsUnspecified():
		return fmt.Errorf("unspecified prefix is not allowed: %s", prefix)
	case addr.IsLinkLocalUnicast():
		return fmt.Errorf("link-local unicast prefix is not allowed: %s", prefix)
	case addr.IsLinkLocalMulticast():
		return fmt.Errorf("link-local multicast prefix is not allowed: %s", prefix)
	case addr.IsMulticast():
		return fmt.Errorf("multicast prefix is not allowed: %s", prefix)
	}

	limitedBroadcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	if prefix.Contains(limitedBroadcast) {
		return fmt.Errorf("limited broadcast address is not allowed: %s", prefix)
	}

	if !corpSocks.IsValid() {
		return fmt.Errorf("corporate SOCKS address is not configured")
	}
	corpSocks = corpSocks.Unmap()
	if prefix.Contains(corpSocks) {
		return fmt.Errorf("prefix %s contains corporate SOCKS address %s", prefix, corpSocks)
	}

	if force {
		return nil
	}
	for _, allowed := range allowedRanges {
		if containsPrefix(allowed, prefix) {
			return nil
		}
	}

	values := make([]string, 0, len(allowedRanges))
	for _, allowed := range allowedRanges {
		values = append(values, allowed.Masked().String())
	}
	return fmt.Errorf("prefix %s is outside allowed ranges: %s", prefix, strings.Join(values, ", "))
}

func containsPrefix(container, prefix netip.Prefix) bool {
	if !container.IsValid() || !prefix.IsValid() {
		return false
	}
	container = container.Masked()
	prefix = prefix.Masked()
	return container.Addr().BitLen() == prefix.Addr().BitLen() &&
		prefix.Bits() >= container.Bits() &&
		container.Contains(prefix.Addr())
}
