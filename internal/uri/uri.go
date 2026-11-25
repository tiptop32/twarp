// Package uri converts supported VPN share URIs into sing-box outbounds.
package uri

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// Parse converts a VLESS REALITY or TLS URI into a VPN outbound.
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

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return singbox.Outbound{}, errors.New("invalid VPN query parameters")
	}
	for _, values := range query {
		if len(values) != 1 {
			return singbox.Outbound{}, errors.New("duplicate VPN query parameter")
		}
	}
	uuid := ""
	if parsed.User != nil {
		uuid = parsed.User.Username()
	}
	if !uuidPattern.MatchString(uuid) {
		return singbox.Outbound{}, errors.New("invalid UUID")
	}
	security := query.Get("security")
	transport := query.Get("type")
	if security != "reality" && (security != "tls" || transport != "xhttp") {
		return singbox.Outbound{}, errors.New("security must be reality or tls/xhttp")
	}
	if transport != "" && transport != "tcp" && transport != "xhttp" {
		return singbox.Outbound{}, errors.New("transport type must be tcp or xhttp")
	}
	if security == "reality" && transport == "xhttp" {
		return singbox.Outbound{}, errors.New("REALITY requires tcp transport")
	}
	if encryption := query.Get("encryption"); encryption != "" && encryption != "none" {
		return singbox.Outbound{}, errors.New("encryption must be none")
	}
	flow := query.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return singbox.Outbound{}, errors.New("flow must be xtls-rprx-vision or empty")
	}
	if transport == "xhttp" && flow != "" {
		return singbox.Outbound{}, errors.New("xhttp requires empty flow")
	}
	publicKey := query.Get("pbk")
	shortID := query.Get("sid")
	if security == "reality" {
		if publicKey == "" {
			return singbox.Outbound{}, errors.New("public key is required")
		}
		decodedPublicKey, err := base64.RawURLEncoding.DecodeString(publicKey)
		if err != nil || len(decodedPublicKey) != 32 {
			return singbox.Outbound{}, errors.New("invalid public key")
		}
		if _, err := hex.DecodeString(shortID); err != nil {
			return singbox.Outbound{}, errors.New("invalid short ID")
		}
	}
	if security == "tls" && (publicKey != "" || shortID != "") {
		return singbox.Outbound{}, errors.New("REALITY parameters are not supported with TLS")
	}

	// Keep the remote SNI even when Xray dials the loopback bridge.
	serverName := query.Get("sni")
	if serverName == "" {
		return singbox.Outbound{}, errors.New("sni is required")
	}
	fingerprint := query.Get("fp")
	if fingerprint == "" {
		fingerprint = defaultFingerprint
	}

	tls := &singbox.OutboundTLS{Enabled: true, ServerName: serverName,
		UTLS: &singbox.UTLS{Enabled: true, Fingerprint: fingerprint}}
	if security == "reality" {
		tls.Reality = &singbox.Reality{Enabled: true, PublicKey: publicKey, ShortID: shortID}
	}

	outbound := singbox.Outbound{Type: "vless", Tag: "vpn", Server: host, ServerPort: uint16(port), UUID: uuid, Flow: flow, TLS: tls, DomainResolver: "direct"}
	if transport == "xhttp" {
		outbound.Network = transport
		outbound.XHTTP = &singbox.XHTTP{Host: query.Get("host"), Path: query.Get("path"), Mode: query.Get("mode")}
		if extra := query.Get("extra"); query.Has("extra") {
			outbound.XHTTP.Extra = json.RawMessage(extra)
			if extra == "" {
				return singbox.Outbound{}, errors.New("xhttp extra must be a JSON object")
			}
		}
		if err := outbound.XHTTP.Validate(); err != nil {
			return singbox.Outbound{}, err
		}
		tls.ALPN = []string{"h2"}
		if query.Has("alpn") {
			tls.ALPN = strings.Split(query.Get("alpn"), ",")
			for _, protocol := range tls.ALPN {
				if protocol != "h2" && protocol != "http/1.1" {
					return singbox.Outbound{}, errors.New("xhttp ALPN must be h2 or http/1.1 for the TCP bridge")
				}
			}
		}
	} else if query.Has("extra") || query.Has("mode") || query.Has("host") || query.Has("path") {
		return singbox.Outbound{}, errors.New("xhttp parameters require xhttp transport")
	}
	return outbound, nil
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
