package main

import (
	"context"
	"fmt"
	"io"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tiptop32/twarp/internal/app"
	mcpserver "github.com/tiptop32/twarp/internal/mcp"
)

const mcpServerVersion = "dev"

type mcpTransport = sdk.Transport

type mcpTransportFactory func(io.Reader, io.Writer) mcpTransport

func stdioMCPTransport() mcpTransport {
	return &sdk.StdioTransport{}
}

func runMCP(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.Sys.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "twarp mcp: do not run mcp with sudo")
		return 1
	}
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "twarp mcp: usage: twarp mcp")
		return 2
	}
	gateway, err := deps.app(app.ActorMCP).Gateway()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp mcp: %v\n", err)
		return 1
	}
	server := mcpserver.NewServer(gateway, mcpserver.Info{
		AllowedRanges: gateway.AllowedRanges(),
		Installed:     gateway.Installed,
		Version:       mcpServerVersion,
	})
	factory := deps.MCPTransport
	if factory == nil {
		factory = func(stdin io.Reader, stdout io.Writer) mcpTransport {
			return &sdk.IOTransport{Reader: readCloser(stdin), Writer: writeCloser(stdout)}
		}
	}
	if err := server.Run(context.Background(), factory(deps.Stdin, stdout)); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp mcp: %v\n", err)
		return 1
	}
	return 0
}

func readCloser(reader io.Reader) io.ReadCloser {
	if closer, ok := reader.(io.ReadCloser); ok {
		return closer
	}
	return io.NopCloser(reader)
}

func writeCloser(writer io.Writer) io.WriteCloser {
	if closer, ok := writer.(io.WriteCloser); ok {
		return closer
	}
	return nopWriteCloser{Writer: writer}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
