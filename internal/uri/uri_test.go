package uri_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/singbox"
	uri "github.com/tiptop32/twarp/internal/uri"
)

func TestParseVLESSReality(t *testing.T) {
	t.Parallel()

	uuid := randomUUID(t)
	publicKey := randomX25519PublicKey(t)
	raw := makeVLESSURI(uuid, publicKey, url.Values{
		"security":   {"reality"},
		"encryption": {"none"},
		"headerType": {"none"},
		"fp":         {"edge"},
		"type":       {"tcp"},
		"flow":       {"xtls-rprx-vision"},
		"sni":        {"example.com"},
		"sid":        {"0123abcd"},
	})

	got, err := uri.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := singbox.Outbound{
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(Parse()) error = %v", err)
	}
	wantJSON := fmt.Sprintf(`{"type":"vless","tag":"vpn","server":"vpn.example.com","server_port":443,"uuid":%q,"flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"edge"},"reality":{"enabled":true,"public_key":%q,"short_id":"0123abcd"}},"domain_resolver":"direct"}`, uuid, publicKey)
	if string(gotJSON) != wantJSON {
		t.Fatalf("json.Marshal(Parse()) = %s, want %s", gotJSON, wantJSON)
	}
}

func TestParseRejectsInvalidURIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		uuid      string
		publicKey string
		query     url.Values
		edit      func(string) string
		wantError string
	}{
		{
			name:      "Shadowsocks scheme",
			edit:      func(string) string { return "ss://synthetic" },
			wantError: "unsupported scheme",
		},
		{
			name:      "VMess scheme",
			edit:      func(string) string { return "vmess://synthetic" },
			wantError: "unsupported scheme",
		},
		{
			name:      "non-REALITY security",
			query:     url.Values{"security": {"tls"}, "flow": {"xtls-rprx-vision"}},
			wantError: "security must be reality",
		},
		{
			name:      "WebSocket transport",
			query:     url.Values{"security": {"reality"}, "type": {"ws"}, "flow": {"xtls-rprx-vision"}},
			wantError: "transport type must be tcp",
		},
		{
			name:      "missing public key",
			publicKey: "-",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			wantError: "public key is required",
		},
		{
			name:      "invalid port",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			edit:      func(raw string) string { return strings.Replace(raw, ":443?", ":70000?", 1) },
			wantError: "invalid port",
		},
		{
			name:      "zero port",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			edit:      func(raw string) string { return strings.Replace(raw, ":443?", ":0?", 1) },
			wantError: "invalid port",
		},
		{
			name:      "empty UUID",
			uuid:      "-",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			wantError: "invalid UUID",
		},
		{
			name:      "malformed UUID",
			uuid:      "not-a-uuid",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			wantError: "invalid UUID",
		},
		{
			name:      "unsupported flow",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-direct"}},
			wantError: "flow must be xtls-rprx-vision or empty",
		},
		{
			name:      "unsupported encryption",
			query:     url.Values{"security": {"reality"}, "encryption": {"auto"}, "flow": {"xtls-rprx-vision"}},
			wantError: "encryption must be none",
		},
		{
			name:      "malformed public key",
			publicKey: "not-a-public-key",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			wantError: "invalid public key",
		},
		{
			name:      "non-hex short ID",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}, "sid": {"not-hex"}},
			wantError: "invalid short ID",
		},
		{
			name:      "missing SNI",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			wantError: "sni is required",
		},
		{
			name:      "missing host",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			edit:      func(raw string) string { return strings.Replace(raw, "vpn.example.com", "", 1) },
			wantError: "invalid host",
		},
		{
			name:      "malformed domain",
			query:     url.Values{"security": {"reality"}, "flow": {"xtls-rprx-vision"}},
			edit:      func(raw string) string { return strings.Replace(raw, "vpn.example.com", "-bad..host", 1) },
			wantError: "invalid host",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			uuid := test.uuid
			switch uuid {
			case "":
				uuid = randomUUID(t)
			case "-":
				uuid = ""
			}
			publicKey := test.publicKey
			switch publicKey {
			case "":
				publicKey = randomX25519PublicKey(t)
			case "-":
				publicKey = ""
			}
			query := test.query.Clone()
			if query == nil {
				query = make(url.Values)
			}
			if !query.Has("sid") {
				query.Set("sid", "0123abcd")
			}
			raw := makeVLESSURI(uuid, publicKey, query)
			if test.edit != nil {
				raw = test.edit(raw)
			}

			_, err := uri.Parse(raw)
			if err == nil {
				t.Fatalf("Parse() error = nil, want %q", test.wantError)
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Parse() error = %q, want it to contain %q", err, test.wantError)
			}
		})
	}
}

func TestParseAllowsEmptyOptionalParameters(t *testing.T) {
	t.Parallel()

	uuid := randomUUID(t)
	publicKey := randomX25519PublicKey(t)
	raw := makeVLESSURI(uuid, publicKey, url.Values{
		"security": {"reality"},
		"sni":      {"example.com"},
	})

	got, err := uri.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	// sing-box rejects a REALITY client without uTLS, so an empty fp falls back to chrome.
	if got.TLS.UTLS == nil || !got.TLS.UTLS.Enabled || got.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("Parse() TLS.UTLS = %#v, want enabled chrome for an empty fp", got.TLS.UTLS)
	}
	if got.TLS.Reality.ShortID != "" {
		t.Fatalf("Parse() TLS.Reality.ShortID = %q, want empty", got.TLS.Reality.ShortID)
	}
	if got.Flow != "" {
		t.Fatalf("Parse() Flow = %q, want empty", got.Flow)
	}
}

func TestParseIPv6Host(t *testing.T) {
	t.Parallel()

	uuid := randomUUID(t)
	publicKey := randomX25519PublicKey(t)
	raw := makeVLESSURI(uuid, publicKey, url.Values{
		"security": {"reality"},
		"flow":     {"xtls-rprx-vision"},
		"sni":      {"example.com"},
	})
	raw = strings.Replace(raw, "vpn.example.com", "[2001:db8::1]", 1)

	got, err := uri.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Server != "2001:db8::1" {
		t.Fatalf("Parse() Server = %q, want %q", got.Server, "2001:db8::1")
	}
}

func TestParseErrorDoesNotExposeCredentials(t *testing.T) {
	t.Parallel()

	uuid := randomUUID(t)
	publicKey := randomX25519PublicKey(t)
	sid := "0123abcd"
	raw := makeVLESSURI(uuid, publicKey, url.Values{
		"security": {"tls"},
		"flow":     {"xtls-rprx-vision"},
		"sid":      {sid},
	})

	_, err := uri.Parse(raw)
	if err == nil {
		t.Fatal("Parse() error = nil, want an error")
	}
	for _, secret := range []string{uuid, publicKey, sid} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Parse() error exposes a credential: %q", err)
		}
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

func makeVLESSURI(uuid, publicKey string, query url.Values) string {
	if publicKey != "" {
		query.Set("pbk", publicKey)
	}
	return fmt.Sprintf("vless://%s@vpn.example.com:443?%s#ignored-name", uuid, query.Encode())
}
