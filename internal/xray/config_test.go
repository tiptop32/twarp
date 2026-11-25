package xray_test

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/uri"
	"github.com/tiptop32/twarp/internal/xray"
)

func TestClientConfigPreservesXHTTPTransportThroughBridge(t *testing.T) {
	const extra = `{"headers":{"X-Test":"a+b"},"xPaddingBytes":"100-200","noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32"},"futureOption":{"count":9007199254740993,"flags":[true,null,"x"]}}`
	for _, test := range []struct {
		name string
		alpn string
		want []string
	}{
		{"default HTTP2", "", []string{"h2"}},
		{"explicit protocols", "http/1.1,h2", []string{"http/1.1", "h2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := url.Values{
				"security": {"tls"}, "type": {"xhttp"}, "encryption": {"none"},
				"sni": {"tls.example.com"}, "fp": {"firefox"},
				"host": {"http.example.com"}, "path": {"/vpn/route?ed=2048&token=a+b"},
				"mode": {"stream-up"}, "extra": {extra},
			}
			if test.alpn != "" {
				query.Set("alpn", test.alpn)
			}
			profile, err := uri.Parse("vless://" + "11111111-1111-4111-8111-111111111111" + "@upstream.example.com:8443?" + query.Encode())
			if err != nil {
				t.Fatal(err)
			}
			tunnel := config.Tunnel{Name: "vpn2", Xray: &config.XrayPorts{Listen: 19080, Bridge: 19081}}
			data, err := xray.ClientConfig(tunnel, "synthetic-local-secret", profile)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Inbounds []struct {
					Protocol string
					Listen   string
					Port     uint16
					Settings struct {
						Method   string
						Password string
						Network  string
					}
				}
				Outbounds []struct {
					Settings struct {
						Address string
						Port    uint16
						ID      string
						Flow    string
					}
					StreamSettings struct {
						Network     string
						Security    string
						TLSSettings struct {
							ServerName  string
							Fingerprint string
							ALPN        []string
						}
						XHTTPSettings singbox.XHTTP
					}
				}
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Inbounds) != 1 || len(got.Outbounds) != 1 {
				t.Fatal("expected one authenticated local listener and one VLESS outbound")
			}
			inbound := got.Inbounds[0]
			if inbound.Protocol != "shadowsocks" || inbound.Listen != "127.0.0.1" || inbound.Port != 19080 || inbound.Settings.Method != "2022-blake3-aes-256-gcm" || inbound.Settings.Network != "tcp,udp" || inbound.Settings.Password == "" {
				t.Fatal("XHTTP client lost its authenticated local TCP/UDP listener")
			}
			outbound := got.Outbounds[0]
			if outbound.Settings.Address != "127.0.0.1" || outbound.Settings.Port != 19081 {
				t.Fatal("XHTTP client bypasses the fixed-destination local bridge")
			}
			if outbound.Settings.ID != "11111111-1111-4111-8111-111111111111" || outbound.Settings.Flow != "" {
				t.Fatal("XHTTP VLESS identity or flow changed")
			}
			stream := outbound.StreamSettings
			if stream.Network != "xhttp" || stream.Security != "tls" || stream.TLSSettings.ServerName != "tls.example.com" || stream.TLSSettings.Fingerprint != "firefox" || !reflect.DeepEqual(stream.TLSSettings.ALPN, test.want) {
				t.Fatal("remote TLS settings were not preserved")
			}
			if stream.XHTTPSettings.Host != "http.example.com" || stream.XHTTPSettings.Path != "/vpn/route?ed=2048&token=a+b" || stream.XHTTPSettings.Mode != "stream-up" || string(stream.XHTTPSettings.Extra) != extra {
				t.Fatal("XHTTP host, path, mode, or arbitrary extra JSON changed")
			}
		})
	}
}

func TestClientConfigKeepsRealityIdentityThroughBridge(t *testing.T) {
	query := url.Values{
		"security": {"reality"}, "type": {"tcp"}, "flow": {"xtls-rprx-vision"},
		"sni": {"reality.example.com"}, "fp": {"edge"},
		"pbk": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "sid": {"0123abcd"},
	}
	profile, err := uri.Parse("vless://" + "11111111-1111-4111-8111-111111111111" + "@upstream.example.com:443?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	data, err := xray.ClientConfig(config.Tunnel{Name: "vpn2", Xray: &config.XrayPorts{Listen: 19080, Bridge: 19081}}, "synthetic-local-secret", profile)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Outbounds []struct {
			Settings struct {
				Address string
				Port    uint16
				Flow    string
			}
			StreamSettings struct {
				Network         string
				Security        string
				RealitySettings map[string]string
			}
		}
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Outbounds) != 1 {
		t.Fatal("expected one VLESS outbound")
	}
	outbound := got.Outbounds[0]
	if outbound.Settings.Address != "127.0.0.1" || outbound.Settings.Port != 19081 || outbound.Settings.Flow != "xtls-rprx-vision-udp443" {
		t.Fatal("REALITY did not use its local bridge and UDP/443-compatible Vision flow")
	}
	if outbound.StreamSettings.Network != "raw" || outbound.StreamSettings.Security != "reality" || !reflect.DeepEqual(outbound.StreamSettings.RealitySettings, map[string]string{
		"serverName": "reality.example.com", "fingerprint": "edge", "password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "shortId": "0123abcd",
	}) {
		t.Fatal("REALITY handshake settings changed")
	}
}

func TestClientConfigRejectsIncompleteProfiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		tunnel config.Tunnel
		vless  singbox.Outbound
	}{
		{name: "missing ports"},
		{name: "missing TLS", tunnel: config.Tunnel{Xray: &config.XrayPorts{Listen: 19080, Bridge: 19081}}, vless: singbox.Outbound{Type: "vless"}},
		{name: "missing XHTTP settings", tunnel: config.Tunnel{Xray: &config.XrayPorts{Listen: 19080, Bridge: 19081}}, vless: singbox.Outbound{Type: "vless", Network: "xhttp", TLS: &singbox.OutboundTLS{Enabled: true, UTLS: &singbox.UTLS{Enabled: true}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := xray.ClientConfig(test.tunnel, "synthetic-local-secret", test.vless); err == nil {
				t.Fatal("invalid Xray profile was accepted")
			}
		})
	}
}
