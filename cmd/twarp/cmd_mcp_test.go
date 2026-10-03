package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRunMCPRejectsRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithDeps([]string{"mcp"}, &stdout, &stderr, cliDeps{Sys: cliTestSys{euid: 0}})
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "do not run mcp with sudo") {
		t.Fatalf("root mcp = (%d, %q, %q), want refusal", code, stdout.String(), stderr.String())
	}
}

func TestRunMCPServesToolsOverPipesUntilEOF(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configText := "gateway:\n  socks: 192.0.2.10:1080\n  domains: [intra.example]\n  dns: 100.64.0.53\n  allowed_ranges: [100.64.0.0/10]\n"
	if err := os.WriteFile(filepath.Join(home, "twarp.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runWithDeps([]string{"mcp"}, serverWriter, &stderr, cliDeps{
			Sys:   cliTestSys{euid: 501, env: map[string]string{"TWARP_HOME": home, "TWARP_OUT": filepath.Join(base, "out")}},
			Stdin: serverReader,
			MCPTransport: func(stdin io.Reader, stdout io.Writer) sdk.Transport {
				return &sdk.IOTransport{Reader: stdin.(io.ReadCloser), Writer: stdout.(io.WriteCloser)}
			},
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "twarp-cli-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &sdk.IOTransport{Reader: clientReader, Writer: clientWriter}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 3 {
		t.Errorf("tools/list returned %d tools, want 3", len(tools.Tools))
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("mcp exit = %d, stderr = %q", code, stderr.String())
		}
	case <-ctx.Done():
		t.Fatal("mcp server did not exit after client EOF")
	}
}
