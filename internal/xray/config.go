// Package xray renders the local Xray client for VLESS tunnels.
package xray

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
)

const method = "2022-blake3-aes-256-gcm"

// BridgeTag identifies the fixed-destination TCP listener in sing-box.
func BridgeTag(tunnel config.Tunnel) string { return "xray-bridge-" + tunnel.Name }

// LocalOutbound authenticates the Xray hop for both TCP and UDP. A listener
// taking over the port cannot decode or forward selected traffic without the key.
func LocalOutbound(tunnel config.Tunnel, clashSecret string) singbox.Outbound {
	mac := hmac.New(sha256.New, []byte(clashSecret))
	_, _ = mac.Write([]byte("twarp/xray/local/v1/" + tunnel.Name))
	return singbox.Outbound{
		Type: "shadowsocks", Tag: tunnel.Tag(), Server: singbox.VPNProxyListen,
		ServerPort: tunnel.Xray.Listen, Method: method, Password: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}
}

// ClientConfig renders Xray's single VLESS outbound, using the supplied
// transport metadata while retaining the local authenticated listener.
func ClientConfig(tunnel config.Tunnel, clashSecret string, vless singbox.Outbound) ([]byte, error) {
	if tunnel.Xray == nil || tunnel.Xray.Listen == 0 || tunnel.Xray.Bridge == 0 || tunnel.Xray.Listen == tunnel.Xray.Bridge {
		return nil, errors.New("xray requires distinct local listener and bridge ports")
	}
	if vless.Type != "vless" || vless.TLS == nil || !vless.TLS.Enabled || vless.TLS.UTLS == nil || !vless.TLS.UTLS.Enabled {
		return nil, errors.New("xray requires a VLESS TLS profile with a fingerprint")
	}
	local := LocalOutbound(tunnel, clashSecret)
	// The bridge's fixed destination is the original remote server. Dial it
	// locally while keeping remote TLS and HTTP identities in streamSettings.
	settings := map[string]any{"address": singbox.VPNProxyListen, "port": tunnel.Xray.Bridge, "id": vless.UUID, "encryption": "none"}
	stream := map[string]any{"network": "raw", "security": "reality"}
	if vless.Network == "xhttp" {
		if vless.XHTTP == nil || vless.TLS.Reality != nil || vless.Flow != "" {
			return nil, errors.New("XHTTP requires TLS, transport settings, and empty flow")
		}
		if err := vless.XHTTP.Validate(); err != nil {
			return nil, err
		}
		alpn := vless.TLS.ALPN
		if len(alpn) == 0 {
			alpn = []string{"h2"}
		}
		for _, protocol := range alpn {
			if protocol != "h2" && protocol != "http/1.1" {
				return nil, errors.New("XHTTP requires TCP-compatible ALPN")
			}
		}
		stream["network"] = "xhttp"
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"serverName": vless.TLS.ServerName, "alpn": alpn, "fingerprint": vless.TLS.UTLS.Fingerprint}
		stream["xhttpSettings"] = vless.XHTTP
	} else {
		if (vless.Network != "" && vless.Network != "tcp") || vless.XHTTP != nil || vless.TLS.Reality == nil || !vless.TLS.Reality.Enabled {
			return nil, errors.New("xray requires REALITY for raw TCP transport")
		}
		flow := vless.Flow
		if flow == "xtls-rprx-vision" {
			flow += "-udp443"
		}
		settings["flow"] = flow
		stream["realitySettings"] = map[string]string{"serverName": vless.TLS.ServerName, "fingerprint": vless.TLS.UTLS.Fingerprint, "password": vless.TLS.Reality.PublicKey, "shortId": vless.TLS.Reality.ShortID}
	}
	return json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "error", "access": "none"},
		"inbounds":  []any{map[string]any{"protocol": local.Type, "listen": local.Server, "port": local.ServerPort, "settings": map[string]string{"method": local.Method, "password": local.Password, "network": "tcp,udp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": settings, "streamSettings": stream}},
	})
}
