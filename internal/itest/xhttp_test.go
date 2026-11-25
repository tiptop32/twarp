//go:build integration && darwin

package itest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/uri"
	"github.com/tiptop32/twarp/internal/xray"
)

func TestXrayXHTTPTraffic(t *testing.T) {
	binary, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray executable not installed")
	}
	const payload = "synthetic HTTP response through TLS/XHTTP"
	release := make(chan struct{})
	defer close(release)
	var received atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || host != "web.xhttp.example" || r.URL.Path != "/through-xhttp" {
			http.Error(w, "unexpected upstream request", http.StatusBadRequest)
			return
		}
		received.Add(1)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// Keep both hops visible to the Clash API until routing is observed.
		<-release
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(origin.Close)

	serverPort, listenPort, bridgePort := freePort(t), freePort(t), freePort(t)
	raw, server, certificate := xhttpFixture(t, serverPort)
	startXrayProcess(t, binary, serverPort, server)
	name := fmt.Sprintf("xhttp-%d", listenPort)
	f := newRenderedFixtureWithProfiles(t, 0, "", fmt.Sprintf("  tunnels:\n    - name: %s\n      domains: [xhttp.example]\n      xray: {listen_port: %d, bridge_port: %d}\n", name, listenPort, bridgePort), map[string]string{name: raw})
	box := f.start(t)
	cfg, err := config.Load(filepath.Join(f.home, "twarp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := uri.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := xray.ClientConfig(cfg.VPN.Tunnels[0], f.clashSecret, profile)
	if err != nil {
		t.Fatal(err)
	}
	// Trust only this synthetic server certificate, without disabling TLS
	// verification or changing the rendered transport or ingress credentials.
	clientConfig = trustXrayCertificate(t, clientConfig, certificate)
	startXrayProcess(t, binary, listenPort, clientConfig)

	dial, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", box.mixedPort), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dial.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	target := "web.xhttp.example:" + strconv.Itoa(origin.Listener.Addr().(*net.TCPAddr).Port)
	response, err := client.Get("http://" + target + "/through-xhttp")
	if err != nil {
		t.Fatalf("HTTP through XHTTP: %v\nsing-box: %s", err, box.Log())
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || received.Load() != 1 {
		t.Fatalf("XHTTP upstream returned %s after %d requests", response.Status, received.Load())
	}
	box.waitForOutbound(t, target, "vpn-"+name, time.Second)
	box.waitForOutbound(t, fmt.Sprintf("127.0.0.1:%d", serverPort), "direct", time.Second)
	release <- struct{}{}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != payload {
		t.Fatalf("XHTTP response body = %q, error = %v; want %q", body, err, payload)
	}
	if f.vpn.ConnectCount(target) != 0 || f.gateway.ConnectCount(target) != 0 {
		t.Fatal("XHTTP request reached another tunnel")
	}
}

func xhttpFixture(t *testing.T, port int) (string, []byte, []string) {
	t.Helper()
	const serverName, httpHost, path = "tls.xhttp.test", "edge.xhttp.test", "/synthetic-xhttp/"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), "\n")
	privateKey := strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))), "\n")
	seed := syntheticSecrets(t, "")
	address, err := url.Parse(seed.VPNURI)
	if err != nil {
		t.Fatal(err)
	}
	address.Host = fmt.Sprintf("127.0.0.1:%d", port)
	address.RawQuery = url.Values{
		"security": {"tls"}, "encryption": {"none"}, "type": {"xhttp"},
		"sni": {serverName}, "fp": {"chrome"}, "alpn": {"h2"},
		"host": {httpHost}, "path": {path}, "mode": {"stream-up"},
		"extra": {`{"xPaddingBytes":"23-23"}`},
	}.Encode()
	document := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": []any{map[string]string{"id": address.User.Username()}}},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "tls",
				"tlsSettings": map[string]any{
					"alpn": []string{"h2"}, "rejectUnknownSni": true,
					"certificates": []any{map[string]any{"certificate": certificate, "key": privateKey}},
				},
				"xhttpSettings": map[string]any{"host": httpHost, "path": path, "mode": "stream-up", "xPaddingBytes": "23-23"},
			},
		}},
		// Only the remote Xray can resolve the HTTP upstream's synthetic name.
		"dns":       map[string]any{"hosts": map[string]string{"web.xhttp.example": "127.0.0.1"}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]string{"targetStrategy": "ForceIPv4"}}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return address.String(), data, certificate
}

func trustXrayCertificate(t *testing.T, data []byte, certificate []string) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	outbounds, ok := document["outbounds"].([]any)
	if !ok || len(outbounds) != 1 {
		t.Fatal("expected one rendered Xray outbound")
	}
	outbound, ok := outbounds[0].(map[string]any)
	if !ok {
		t.Fatal("expected an Xray outbound object")
	}
	stream, ok := outbound["streamSettings"].(map[string]any)
	if !ok {
		t.Fatal("expected Xray stream settings")
	}
	tls, ok := stream["tlsSettings"].(map[string]any)
	if !ok {
		t.Fatal("expected Xray TLS settings")
	}
	tls["disableSystemRoot"] = true
	tls["certificates"] = []any{map[string]any{"usage": "verify", "certificate": certificate}}
	patched, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return patched
}
