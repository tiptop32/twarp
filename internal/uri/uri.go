// Package uri converts supported VPN share URIs into sing-box outbounds.
package uri

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tiptop32/twarp/internal/singbox"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// defaultFingerprint is used when the URI has no fp: sing-box refuses to start
// a REALITY client without uTLS ("uTLS is required by reality client").
const defaultFingerprint = "chrome"

// Parse converts a VLESS REALITY URI into a VPN outbound.
func Parse(raw string) (singbox.Outbound, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return singbox.Outbound{}, errors.New("invalid VPN URI")
	}
	if parsed.Scheme != "vless" {
		return singbox.Outbound{}, errors.New("unsupported scheme")
	}
	host := parsed.Hostname()
	if !validServerHost(host) {
		return singbox.Outbound{}, errors.New("invalid host")
	}

	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return singbox.Outbound{}, errors.New("invalid port")
	}

	query := parsed.Query()
	uuid := ""
	if parsed.User != nil {
		uuid = parsed.User.Username()
	}
	if !uuidPattern.MatchString(uuid) {
		return singbox.Outbound{}, errors.New("invalid UUID")
	}
	if query.Get("security") != "reality" {
		return singbox.Outbound{}, errors.New("security must be reality")
	}
	if transport := query.Get("type"); transport != "" && transport != "tcp" {
		return singbox.Outbound{}, errors.New("transport type must be tcp")
	}
	if encryption := query.Get("encryption"); encryption != "" && encryption != "none" {
		return singbox.Outbound{}, errors.New("encryption must be none")
	}
	flow := query.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return singbox.Outbound{}, errors.New("flow must be xtls-rprx-vision or empty")
	}
	publicKey := query.Get("pbk")
	if publicKey == "" {
		return singbox.Outbound{}, errors.New("public key is required")
	}
	decodedPublicKey, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(decodedPublicKey) != 32 {
		return singbox.Outbound{}, errors.New("invalid public key")
	}
	shortID := query.Get("sid")
	if _, err := hex.DecodeString(shortID); err != nil {
		return singbox.Outbound{}, errors.New("invalid short ID")
	}

	// The REALITY server checks SNI against its target during the handshake.
	serverName := query.Get("sni")
	if serverName == "" {
		return singbox.Outbound{}, errors.New("sni is required")
	}
	fingerprint := query.Get("fp")
	if fingerprint == "" {
		fingerprint = defaultFingerprint
	}

	tls := &singbox.OutboundTLS{
		Enabled:    true,
		ServerName: serverName,
		UTLS:       &singbox.UTLS{Enabled: true, Fingerprint: fingerprint},
		Reality: &singbox.Reality{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   shortID,
		},
	}

	return singbox.Outbound{
		Type:           "vless",
		Tag:            "vpn",
		Server:         host,
		ServerPort:     uint16(port),
		UUID:           uuid,
		Flow:           flow,
		TLS:            tls,
		DomainResolver: "direct",
	}, nil
}

func validServerHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.Contains(host, ":") {
		return false
	}

	domain := strings.TrimSuffix(host, ".")
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
