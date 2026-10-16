package socksprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

var (
	testCreds  = &Credentials{User: "proxy", Password: "synthetic-password"}
	testTarget = netip.MustParseAddrPort("100.64.0.53:53")
)

func probeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestHandshake(t *testing.T) {
	tests := []struct {
		name   string
		server FakeServer
		creds  *Credentials
		want   error
	}{
		{"no auth", FakeServer{}, nil, nil},
		{"no-auth server accepts offered credentials", FakeServer{}, testCreds, nil},
		{"auth", FakeServer{Creds: testCreds}, testCreds, nil},
		{"wrong password", FakeServer{Creds: testCreds}, &Credentials{User: "proxy", Password: "wrong"}, ErrAuthRejected},
		{"auth required, none configured", FakeServer{Creds: testCreds}, nil, ErrNoMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.server.Dial()
			defer func() { _ = conn.Close() }()
			if err := Handshake(probeContext(t), conn, tt.creds); !errors.Is(err, tt.want) {
				t.Fatalf("Handshake() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHandshakeRejectsNonSOCKSServers(t *testing.T) {
	t.Run("closed after accept", func(t *testing.T) {
		server, client := net.Pipe()
		go func() {
			buf := make([]byte, 3)
			_, _ = server.Read(buf)
			_ = server.Close()
		}()
		if err := Handshake(probeContext(t), client, nil); !errors.Is(err, ErrNotSOCKS5) {
			t.Fatalf("Handshake() = %v, want ErrNotSOCKS5", err)
		}
	})
	t.Run("http server", func(t *testing.T) {
		server, client := net.Pipe()
		go func() {
			buf := make([]byte, 3)
			_, _ = server.Read(buf)
			_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
		}()
		if err := Handshake(probeContext(t), client, nil); !errors.Is(err, ErrNotSOCKS5) {
			t.Fatalf("Handshake() = %v, want ErrNotSOCKS5", err)
		}
	})
	t.Run("silent server times out", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		go func() {
			buf := make([]byte, 3)
			_, _ = server.Read(buf)
		}()
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if err := Handshake(ctx, client, nil); err == nil {
			t.Fatal("Handshake() = nil, want a timeout")
		}
	})
}

func TestConnect(t *testing.T) {
	tests := []struct {
		name  string
		reply byte
		want  error
	}{
		{"success", 0x00, nil},
		{"vpn down", 0x03, ErrUpstreamDown},
		{"host unreachable", 0x04, ErrConnectFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := FakeServer{Creds: testCreds, ConnectReply: tt.reply}.Dial()
			defer func() { _ = conn.Close() }()
			ctx := probeContext(t)
			if err := Handshake(ctx, conn, testCreds); err != nil {
				t.Fatal(err)
			}
			if err := Connect(ctx, conn, testTarget); !errors.Is(err, tt.want) {
				t.Fatalf("Connect() = %v, want %v", err, tt.want)
			}
		})
	}
}
