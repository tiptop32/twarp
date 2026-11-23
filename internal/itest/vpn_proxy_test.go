//go:build integration && darwin

package itest

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVPNProxyIgnoresSplitRoutingAndStopsWithSingBox(t *testing.T) {
	proxyPort := freePort(t)
	fixture := newRenderedFixtureWithVPNProxy(t, proxyPort, "")
	box := fixture.start(t)
	const gatewayTarget = "host.intra.example:80"
	assertOutbound(t, box, gatewayTarget, "gateway")
	proxyInbound := singBoxProcess{mixedPort: proxyPort}
	conn := proxyInbound.openCONNECT(t, gatewayTarget)
	fixture.vpn.waitForConnectCount(t, gatewayTarget, 1, time.Second)
	_ = conn.Close()
	fixture.vpn.EnableRelay()

	const body = "response through vpn"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	proxy := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	if got, err := proxyOnlyCurl(t, proxyPort, "", server.URL); curlExitCode(err) != 7 {
		t.Fatalf("direct socket was not denied: %q, %v", got, err)
	}
	if got, err := proxyOnlyCurl(t, proxyPort, proxy, server.URL); err != nil || string(got) != body {
		t.Fatalf("through VPN proxy: %q, %v", got, err)
	}
	fixture.vpn.waitForConnectCount(t, strings.TrimPrefix(server.URL, "http://"), 1, time.Second)

	box.stop()
	if got, err := proxyOnlyCurl(t, proxyPort, proxy, server.URL); curlExitCode(err) != 7 {
		t.Fatalf("VPN proxy did not fail closed: %q, %v", got, err)
	}
	if got, err := proxyOnlyCurl(t, proxyPort, "", server.URL); curlExitCode(err) != 7 {
		t.Fatalf("direct socket became available after proxy stopped: %q, %v", got, err)
	}
}

func TestVPNProxyTLSRequiresTrustedPeer(t *testing.T) {
	cert, key := proxyTestCertificate(t)
	proxyPort := freePort(t)
	tlsYAML := fmt.Sprintf("vpn_proxy_tls_cert: %q\nvpn_proxy_tls_key: %q\n", cert, key)
	fixture := newRenderedFixtureWithVPNProxy(t, proxyPort, tlsYAML)
	fixture.vpn.EnableRelay()
	fixture.start(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "VPN upstream")
	}))
	t.Cleanup(upstream.Close)
	proxy := fmt.Sprintf("https://127.0.0.1:%d", proxyPort)
	cmd := func(args ...string) ([]byte, error) {
		return proxyOnlyCurl(t, proxyPort, proxy, upstream.URL, args...)
	}
	if got, err := cmd(); curlExitCode(err) != 60 {
		t.Fatalf("untrusted proxy: got %q, %v; want certificate verification failure", got, err)
	}
	if got, err := cmd("--proxy-cacert", cert); err != nil || string(got) != "VPN upstream" {
		t.Fatalf("trusted proxy: got %q, %v", got, err)
	}
}

func proxyTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	pair := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func proxyOnlyCurl(t *testing.T, port int, proxy, target string, options ...string) ([]byte, error) {
	t.Helper()
	args := []string{"-D", fmt.Sprintf("PROXY_PORT=%d", port), "-f", filepath.Join("..", "..", "scripts", "proxy-only.sb"),
		"/usr/bin/curl", "--disable", "--noproxy", "", "--proxy", proxy, "--max-time", "3", "-fsS"}
	return exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec", append(append(args, options...), target)...).CombinedOutput()
}

func curlExitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 0
}
