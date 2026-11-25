// Package xray renders the local Xray client for a VLESS REALITY tunnel.
package xray

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

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
	local := LocalOutbound(tunnel, clashSecret)
	// Xray's bare Vision option rejects UDP/443 locally. With the suffix it
	// allows QUIC but still sends the original Vision flow to the server.
	flow := vless.Flow
	if flow == "xtls-rprx-vision" {
		flow += "-udp443"
	}
	return json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "error", "access": "none"},
		"inbounds": []any{map[string]any{
			"protocol": local.Type, "listen": local.Server, "port": local.ServerPort,
			"settings": map[string]string{"method": local.Method, "password": local.Password, "network": "tcp,udp"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"address": local.Server, "port": tunnel.Xray.Bridge,
				"id": vless.UUID, "encryption": "none", "flow": flow,
			},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]string{
					"serverName": vless.TLS.ServerName, "fingerprint": vless.TLS.UTLS.Fingerprint,
					"password": vless.TLS.Reality.PublicKey, "shortId": vless.TLS.Reality.ShortID,
				},
			},
		}},
	})
}
