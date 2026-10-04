package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

func TestGatewayIPAddPersistsAndRenders(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	rulesDir := filepath.Join(base, "rules")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := state.New(state.Options{
		File:          filepath.Join(home, "gateway-ips.json"),
		LockFile:      filepath.Join(home, "gateway-ips.lock"),
		AuditFile:     filepath.Join(home, "audit.jsonl"),
		AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		GatewaySocks:  netip.MustParseAddr("192.0.2.10"),
		OnChange:      render.OnChangeWriter(rulesDir),
	})
	client := connectTestClient(ctx, t, NewServer(app.NewGateway(store, app.ActorMCP, nil, ""), Info{
		AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Installed:     func() bool { return true },
		Version:       "test",
	}))

	result, err := client.CallTool(ctx, &sdk.CallToolParams{
		Name: "gateway_ip_add",
		Arguments: map[string]any{
			"cidr":    "100.64.20.10",
			"comment": "new vm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("gateway_ip_add returned tool error: %#v", result.Content)
	}
	var output struct {
		Status string `json:"status"`
		CIDR   string `json:"cidr"`
		Note   string `json:"note"`
	}
	decodeStructured(t, result.StructuredContent, &output)
	if output.Status != "added" || output.CIDR != "100.64.20.10/32" {
		t.Fatalf("gateway_ip_add output = %#v, want added normalized CIDR", output)
	}
	if output.Note != "written; sing-box reloads within ~1s" {
		t.Errorf("note = %q, want hot-reload explanation", output.Note)
	}

	for path, want := range map[string][]byte{
		filepath.Join(home, "gateway-ips.json"):    []byte(`"cidr":"100.64.20.10/32"`),
		filepath.Join(rulesDir, "gateway-ip.json"): []byte("100.64.20.10/32"),
		filepath.Join(home, "audit.jsonl"):         []byte(`"actor":"mcp"`),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		if !bytes.Contains(data, want) {
			t.Errorf("%s = %s, want %s", path, data, want)
		}
	}
}

func TestGatewayIPAddExplainsAllowedRanges(t *testing.T) {
	ctx := context.Background()
	client := newTestSession(t, false)
	result, err := client.CallTool(ctx, &sdk.CallToolParams{
		Name:      "gateway_ip_add",
		Arguments: map[string]any{"cidr": "8.8.8.0/24", "comment": "public resolver"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("gateway_ip_add IsError = false, want tool error: %#v", result)
	}
	text := toolText(result)
	for _, want := range []string{"outside allowed ranges", "allowed ranges: 100.64.0.0/10"} {
		if !strings.Contains(text, want) {
			t.Errorf("tool error = %q, want %q", text, want)
		}
	}
}

func TestGatewayIPAddReportsNoOpStatusesAndNotInstalled(t *testing.T) {
	ctx := context.Background()
	client := newTestSession(t, false)
	call := func(cidr string) addOutput {
		t.Helper()
		result, err := client.CallTool(ctx, &sdk.CallToolParams{
			Name:      "gateway_ip_add",
			Arguments: map[string]any{"cidr": cidr, "comment": "test network"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatalf("gateway_ip_add(%q) returned tool error: %s", cidr, toolText(result))
		}
		var output addOutput
		decodeStructured(t, result.StructuredContent, &output)
		return output
	}

	if output := call("100.64.20.0/24"); output.Status != "added" ||
		output.Note != "saved; twarp is not installed yet, sudo twarp install will apply it" {
		t.Fatalf("first add = %#v, want added with not-installed note", output)
	}
	if output := call("100.64.20.0/24"); output.Status != "already_present" {
		t.Errorf("second add = %#v, want already_present", output)
	}
	if output := call("100.64.20.10"); output.Status != "covered_by" || output.CoveredBy != "100.64.20.0/24" {
		t.Errorf("covered add = %#v, want covered_by 100.64.20.0/24", output)
	}
}

func TestGatewayToolSchemasAndDescriptions(t *testing.T) {
	client := newTestSession(t, false)
	result, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]*sdk.Tool, len(result.Tools))
	for _, tool := range result.Tools {
		tools[tool.Name] = tool
	}
	for _, name := range []string{"gateway_ip_add", "gateway_ip_remove", "gateway_ip_list"} {
		if tools[name] == nil {
			t.Errorf("tools/list missing %q", name)
		}
	}
	add := tools["gateway_ip_add"]
	if add == nil {
		return
	}
	schema, ok := add.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("gateway_ip_add input schema type = %T, want map", add.InputSchema)
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("gateway_ip_add properties = %#v, want map", schema["properties"])
	}
	if _, exists := properties["force"]; exists {
		t.Error("gateway_ip_add schema exposes forbidden force field")
	}
	for _, property := range []string{"cidr", "comment"} {
		if _, exists := properties[property]; !exists {
			t.Errorf("gateway_ip_add schema missing %q", property)
		}
		if !containsString(schema["required"], property) {
			t.Errorf("gateway_ip_add schema does not require %q: %#v", property, schema["required"])
		}
	}
	for _, phrase := range []string{
		"networks reached through the SOCKS gateway",
		"Domain names are not accepted",
		"allowed range returned by gateway_ip_list",
		"broad ranges are rejected",
		"without restarting sing-box",
	} {
		if !strings.Contains(add.Description, phrase) {
			t.Errorf("gateway_ip_add description = %q, want %q", add.Description, phrase)
		}
	}
}

func TestGatewayIPListAndRemove(t *testing.T) {
	ctx := context.Background()
	client := newTestSession(t, true)
	added, err := client.CallTool(ctx, &sdk.CallToolParams{
		Name:      "gateway_ip_add",
		Arguments: map[string]any{"cidr": "100.64.20.10", "comment": "new vm"},
	})
	if err != nil || added.IsError {
		t.Fatalf("gateway_ip_add = (%v, %s)", err, toolText(added))
	}

	listed, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "gateway_ip_list", Arguments: map[string]any{}})
	if err != nil || listed.IsError {
		t.Fatalf("gateway_ip_list = (%v, %s)", err, toolText(listed))
	}
	var list listOutput
	decodeStructured(t, listed.StructuredContent, &list)
	if len(list.AllowedRanges) != 1 || list.AllowedRanges[0] != "100.64.0.0/10" {
		t.Errorf("allowed_ranges = %#v, want [100.64.0.0/10]", list.AllowedRanges)
	}
	if len(list.CIDRs) != 1 || list.CIDRs[0].CIDR != "100.64.20.10/32" ||
		list.CIDRs[0].Comment != "new vm" || list.CIDRs[0].AddedBy != "mcp" || list.CIDRs[0].AddedAt == "" {
		t.Errorf("cidrs = %#v, want persisted MCP entry", list.CIDRs)
	}

	removed, err := client.CallTool(ctx, &sdk.CallToolParams{
		Name:      "gateway_ip_remove",
		Arguments: map[string]any{"cidr": "100.64.20.10"},
	})
	if err != nil || removed.IsError {
		t.Fatalf("gateway_ip_remove = (%v, %s)", err, toolText(removed))
	}
	var removal removeOutput
	decodeStructured(t, removed.StructuredContent, &removal)
	if removal.Status != "removed" || removal.CIDR != "100.64.20.10/32" ||
		removal.Note != "written; sing-box reloads within ~1s" {
		t.Errorf("gateway_ip_remove output = %#v, want removed with hot-reload note", removal)
	}

	listed, err = client.CallTool(ctx, &sdk.CallToolParams{Name: "gateway_ip_list", Arguments: map[string]any{}})
	if err != nil || listed.IsError {
		t.Fatalf("gateway_ip_list after remove = (%v, %s)", err, toolText(listed))
	}
	decodeStructured(t, listed.StructuredContent, &list)
	if len(list.CIDRs) != 0 {
		t.Errorf("cidrs after remove = %#v, want empty", list.CIDRs)
	}
}

func newTestSession(t *testing.T, installed bool) *sdk.ClientSession {
	t.Helper()
	base := t.TempDir()
	store := state.New(state.Options{
		File:          filepath.Join(base, "gateway-ips.json"),
		LockFile:      filepath.Join(base, "gateway-ips.lock"),
		AuditFile:     filepath.Join(base, "audit.jsonl"),
		AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		GatewaySocks:  netip.MustParseAddr("192.0.2.10"),
	})
	return connectTestClient(context.Background(), t, NewServer(app.NewGateway(store, app.ActorMCP, nil, ""), Info{
		AllowedRanges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Installed:     func() bool { return installed },
		Version:       "test",
	}))
}

func toolText(result *sdk.CallToolResult) string {
	if result == nil {
		return ""
	}
	var texts []string
	for _, content := range result.Content {
		if text, ok := content.(*sdk.TextContent); ok {
			texts = append(texts, text.Text)
		}
	}
	return strings.Join(texts, "\n")
}

func containsString(value any, want string) bool {
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func connectTestClient(ctx context.Context, t *testing.T, server *sdk.Server) *sdk.ClientSession {
	t.Helper()
	clientTransport, serverTransport := sdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "twarp-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Wait()
	})
	return clientSession
}

func decodeStructured(t *testing.T, value any, target any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
