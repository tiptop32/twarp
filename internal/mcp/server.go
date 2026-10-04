// Package mcp exposes gateway network state through Model Context Protocol tools.
package mcp

import (
	"context"
	"net/netip"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tiptop32/twarp/internal/app"
)

// Gateway is the part of the application layer the MCP tools use; *app.Gateway
// implements it, so MCP, CLI and TUI share one validation and audit path.
type Gateway interface {
	ListGatewayCIDRs(ctx context.Context) ([]app.GatewayEntry, error)
	AddGatewayCIDR(ctx context.Context, request app.AddGatewayRequest) (app.AddResult, error)
	RemoveGatewayCIDR(ctx context.Context, cidr string) (app.RemoveResult, error)
}

// Info supplies server metadata and read-only configuration shown to MCP clients.
type Info struct {
	AllowedRanges []netip.Prefix
	Installed     func() bool
	Version       string
}

type addInput struct {
	CIDR    string `json:"cidr" jsonschema:"required IP address or CIDR prefix; domain names are not accepted"`
	Comment string `json:"comment" jsonschema:"required short description of the host or network"`
}

type addOutput struct {
	Status         string   `json:"status"`
	CIDR           string   `json:"cidr"`
	CoveredBy      string   `json:"covered_by,omitempty"`
	Warnings       []string `json:"warnings"`
	SingBoxRunning bool     `json:"singbox_running"`
	Note           string   `json:"note"`
}

type removeInput struct {
	CIDR string `json:"cidr" jsonschema:"required IP address or CIDR prefix; domain names are not accepted"`
}

type removeOutput struct {
	Status         string `json:"status"`
	CIDR           string `json:"cidr"`
	SingBoxRunning bool   `json:"singbox_running"`
	Note           string `json:"note"`
}

type listInput struct{}

type listEntry struct {
	CIDR    string `json:"cidr"`
	Comment string `json:"comment"`
	AddedBy string `json:"added_by"`
	AddedAt string `json:"added_at"`
}

type listOutput struct {
	CIDRs         []listEntry `json:"cidrs"`
	AllowedRanges []string    `json:"allowed_ranges"`
}

// NewServer constructs the twarp MCP server and registers its gateway tools.
func NewServer(gateway Gateway, info Info) *sdk.Server {
	server := sdk.NewServer(&sdk.Implementation{Name: "twarp", Version: info.Version}, nil)
	sdk.AddTool(server, &sdk.Tool{
		Name: "gateway_ip_add",
		Description: "Add an IP address or CIDR to networks reached through the SOCKS gateway (for example, a new VM). " +
			"Domain names are not accepted. The CIDR must be inside an allowed range returned by gateway_ip_list, " +
			"and broad ranges are rejected. Changes are applied without restarting sing-box.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, input addInput) (*sdk.CallToolResult, addOutput, error) {
		result, err := gateway.AddGatewayCIDR(ctx, app.AddGatewayRequest{CIDR: input.CIDR, Comment: input.Comment})
		if err != nil {
			return nil, addOutput{}, err
		}
		return nil, addOutput{
			Status:         string(result.Status),
			CIDR:           result.CIDR.String(),
			CoveredBy:      prefixString(result.CoveredBy),
			Warnings:       nonNil(result.Warnings),
			SingBoxRunning: result.SingBoxRunning,
			Note:           mutationNote(info.Installed),
		}, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name: "gateway_ip_remove",
		Description: "Remove an IP address or CIDR from networks reached through the SOCKS gateway. " +
			"Domain names are not accepted. Use gateway_ip_list to inspect configured CIDRs and allowed ranges. " +
			"Changes are applied without restarting sing-box.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, input removeInput) (*sdk.CallToolResult, removeOutput, error) {
		result, err := gateway.RemoveGatewayCIDR(ctx, input.CIDR)
		if err != nil {
			return nil, removeOutput{}, err
		}
		return nil, removeOutput{
			Status:         string(result.Status),
			CIDR:           result.CIDR.String(),
			SingBoxRunning: result.SingBoxRunning,
			Note:           mutationNote(info.Installed),
		}, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name: "gateway_ip_list",
		Description: "List IP/CIDR networks reached through the SOCKS gateway and the allowed ranges for gateway_ip_add. " +
			"These tools accept IP addresses and CIDRs, not domain names; changes apply without restarting sing-box.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ listInput) (*sdk.CallToolResult, listOutput, error) {
		entries, err := gateway.ListGatewayCIDRs(ctx)
		if err != nil {
			return nil, listOutput{}, err
		}
		output := listOutput{
			CIDRs:         make([]listEntry, 0, len(entries)),
			AllowedRanges: make([]string, 0, len(info.AllowedRanges)),
		}
		for _, entry := range entries {
			output.CIDRs = append(output.CIDRs, listEntry{
				CIDR:    entry.CIDR.String(),
				Comment: entry.Comment,
				AddedBy: entry.AddedBy,
				AddedAt: entry.AddedAt.UTC().Format(time.RFC3339),
			})
		}
		for _, allowed := range info.AllowedRanges {
			output.AllowedRanges = append(output.AllowedRanges, allowed.String())
		}
		return nil, output, nil
	})
	return server
}

func mutationNote(installed func() bool) string {
	if installed != nil && installed() {
		return "written; sing-box reloads within ~1s"
	}
	return "saved; twarp is not installed yet, sudo twarp install will apply it"
}

func prefixString(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
