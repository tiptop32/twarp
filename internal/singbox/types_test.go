package singbox_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tiptop32/twarp/internal/singbox"
)

func TestOutboundJSON(t *testing.T) {
	t.Parallel()

	uuid := randomUUID(t)
	publicKey := randomX25519PublicKey(t)
	outbound := singbox.Outbound{
		Type:       "vless",
		Tag:        "vpn",
		Server:     "vpn.example.com",
		ServerPort: 443,
		UUID:       uuid,
		Flow:       "xtls-rprx-vision",
		TLS: &singbox.OutboundTLS{
			Enabled:    true,
			ServerName: "example.com",
			UTLS: &singbox.UTLS{
				Enabled:     true,
				Fingerprint: "edge",
			},
			Reality: &singbox.Reality{
				Enabled:   true,
				PublicKey: publicKey,
				ShortID:   "0123abcd",
			},
		},
		DomainResolver: "direct",
	}

	got, err := json.Marshal(outbound)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	want := fmt.Sprintf(`{"type":"vless","tag":"vpn","server":"vpn.example.com","server_port":443,"uuid":%q,"flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"edge"},"reality":{"enabled":true,"public_key":%q,"short_id":"0123abcd"}},"domain_resolver":"direct"}`, uuid, publicKey)
	if string(got) != want {
		t.Fatalf("json.Marshal() = %s, want %s", got, want)
	}
}

func randomUUID(t *testing.T) string {
	t.Helper()

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("generate UUID: %v", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(id)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:])
}

func randomX25519PublicKey(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}
