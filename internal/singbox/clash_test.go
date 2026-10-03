package singbox_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tiptop32/twarp/internal/singbox"
)

func TestClashVersion(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/version" {
			t.Errorf("request = %s %s, want GET /version", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer top-secret" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer top-secret")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"version":"sing-box 1.14.2","meta":true}`))
	}))
	defer server.Close()

	client := singbox.Clash{Addr: server.Listener.Addr().String(), Secret: "top-secret"}
	got, err := client.Version(context.Background())
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if got != "sing-box 1.14.2" {
		t.Fatalf("Version() = %q, want %q", got, "sing-box 1.14.2")
	}
}

func TestClashConnections(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/connections" {
			t.Errorf("request = %s %s, want GET /connections", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want no header for an empty secret", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
  "connections": [{
    "chains": ["gateway", "mixed-in"],
    "metadata": {
      "destinationIP": "100.64.10.10",
      "destinationPort": "443",
      "host": "service.gateway.example"
    }
  }]
}`))
	}))
	defer server.Close()

	client := singbox.Clash{Addr: server.Listener.Addr().String()}
	got, err := client.Connections(context.Background())
	if err != nil {
		t.Fatalf("Connections() error = %v", err)
	}
	want := []singbox.Connection{{
		Chains:          []string{"gateway", "mixed-in"},
		DestinationIP:   "100.64.10.10",
		DestinationPort: "443",
		Host:            "service.gateway.example",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Connections() = %#v, want %#v", got, want)
	}
	if got[0].Outbound() != "gateway" {
		t.Fatalf("Outbound() = %q, want %q", got[0].Outbound(), "gateway")
	}
	if got := (singbox.Connection{}).Outbound(); got != "" {
		t.Fatalf("empty Outbound() = %q, want empty string", got)
	}
}

func TestClashUnauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := singbox.Clash{Addr: server.Listener.Addr().String(), Secret: "wrong"}
	_, err := client.Version(context.Background())
	if !errors.Is(err, singbox.ErrUnauthorized) {
		t.Fatalf("Version() error = %v, want ErrUnauthorized", err)
	}
}

func TestClashUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	addr := server.Listener.Addr().String()
	server.Close()

	client := singbox.Clash{Addr: addr}
	_, err := client.Connections(context.Background())
	if err == nil || !strings.Contains(err.Error(), "GET /connections") {
		t.Fatalf("Connections() error = %v, want wrapped network error", err)
	}
}

func TestClashRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"version":`))
	}))
	defer server.Close()

	client := singbox.Clash{Addr: server.Listener.Addr().String()}
	_, err := client.Version(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode GET /version") {
		t.Fatalf("Version() error = %v, want wrapped JSON error", err)
	}
}

func TestClashRunningAndRunningFunc(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"version":"sing-box 1.14.2"}`))
	}))
	addr := server.Listener.Addr().String()
	client := singbox.Clash{Addr: addr}

	if !client.Running(context.Background()) {
		t.Fatal("Running() = false, want true")
	}
	if !client.RunningFunc()() {
		t.Fatal("RunningFunc()() = false, want true")
	}

	server.Close()
	if client.Running(context.Background()) {
		t.Fatal("Running() = true after server closed")
	}
	if client.RunningFunc()() {
		t.Fatal("RunningFunc()() = true after server closed")
	}
}

// A 401 means sing-box answered: it is running, only the secret is wrong.
func TestClashRunningTreatsUnauthorizedAsRunning(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := singbox.Clash{Addr: server.Listener.Addr().String(), Secret: "wrong"}
	if !client.Running(context.Background()) {
		t.Fatal("Running() = false for a 401 response, want true")
	}
}
