//go:build integration && darwin

package itest

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVPNProxyIgnoresSplitRoutingAndStopsWithSingBox(t *testing.T) {
	proxyPort := freePort(t)
	fixture := newRenderedFixtureWithVPNProxy(t, proxyPort)
	fixture.vpn.EnableRelay()
	box := fixture.start(t)
	assertOutbound(t, box, "host.intra.example:80", "gateway")

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
}

func proxyOnlyCurl(t *testing.T, port int, proxy, target string) ([]byte, error) {
	t.Helper()
	return exec.CommandContext(t.Context(), "/usr/bin/sandbox-exec",
		"-D", fmt.Sprintf("PROXY_PORT=%d", port), "-f", filepath.Join("..", "..", "scripts", "proxy-only.sb"),
		"/usr/bin/curl", "--disable", "--noproxy", "", "--proxy", proxy, "--max-time", "3", "-fsS", target,
	).CombinedOutput()
}

func curlExitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 0
}
