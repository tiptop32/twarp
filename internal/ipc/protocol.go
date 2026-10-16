// Package ipc is the local protocol between the twarp CLI or TUI and the
// twarpd root daemon: one JSON line per request and per response over a unix
// socket. Requests carry no paths or data, only a fixed operation, so the
// daemon can do no more for a caller than turn its owner's VPN on and off.
package ipc

import (
	"errors"
	"fmt"
	"time"

	"github.com/tiptop32/twarp/internal/config"
)

// Version is the protocol version every request must carry.
const Version = 1

// DefaultSocketPath is where twarpd listens. TWARP_SOCKET overrides it in tests.
const DefaultSocketPath = "/var/run/twarp/twarpd.sock"

// MaxRequestBytes bounds one request line.
const MaxRequestBytes = 4 << 10

// maxResponseBytes bounds one response line read by the client.
const maxResponseBytes = 64 << 10

// Operations the daemon accepts.
const (
	OpUp        = "up"
	OpDown      = "down"
	OpApply     = "apply"
	OpGeoUpdate = "geo_update"
	OpStatus    = "status"
)

// Actors a client may name; the daemon audits them as daemon-<actor>.
const (
	ActorCLI = "cli"
	ActorTUI = "tui"
)

// Response codes for failures.
const (
	CodeForbidden  = "forbidden"
	CodeBadRequest = "bad_request"
	CodeBusy       = "busy"
	CodeFailed     = "failed"
)

var (
	operations = map[string]bool{OpUp: true, OpDown: true, OpApply: true, OpGeoUpdate: true, OpStatus: true}
	actors     = map[string]bool{ActorCLI: true, ActorTUI: true}
)

// Request asks the daemon to run one operation.
type Request struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Actor string `json:"actor"`
}

// Validate rejects unknown versions, operations and actors.
func (request Request) Validate() error {
	switch {
	case request.V != Version:
		return fmt.Errorf("unsupported protocol version %d", request.V)
	case !operations[request.Op]:
		return fmt.Errorf("unknown operation %q", request.Op)
	case !actors[request.Actor]:
		return fmt.Errorf("unknown actor %q", request.Actor)
	}
	return nil
}

// Response is the daemon's answer to one request.
type Response struct {
	OK bool `json:"ok"`
	// Summary is the line the CLI prints under sudo for the same operation.
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
	// Live is set for status.
	Live *LiveStatus `json:"live,omitempty"`
}

// Err returns the failure as an error, or nil when OK is set.
func (response Response) Err() error {
	if response.OK {
		return nil
	}
	if response.Code == CodeForbidden {
		return fmt.Errorf("%w: %s", ErrForbidden, response.Error)
	}
	if response.Error == "" {
		return errors.New("twarpd: request failed")
	}
	return errors.New(response.Error)
}

// ErrForbidden reports a caller that is neither the owner nor root.
var ErrForbidden = errors.New("twarpd: forbidden")

// LiveStatus describes the config sing-box is running.
type LiveStatus struct {
	// GatewayConfigured is gateway.socks as written in twarp.yaml.
	GatewayConfigured string `json:"gateway_configured"`
	// GatewayLive is the gateway outbound address in the running config.json.
	GatewayLive     string    `json:"gateway_live"`
	ConfigAppliedAt time.Time `json:"config_applied_at"`
	// Stale is set when twarp.yaml or secrets.yaml is newer than config.json.
	Stale            bool   `json:"stale"`
	LastResolveError string `json:"last_resolve_error,omitempty"`
}

// SocketPath returns the daemon socket path.
func SocketPath(system config.Sys) string {
	if path := system.Getenv("TWARP_SOCKET"); path != "" {
		return path
	}
	return DefaultSocketPath
}

// Timeout is how long a client waits for op. up and apply run sing-box check,
// geo_update downloads the rule-sets.
func Timeout(op string) time.Duration {
	switch op {
	case OpStatus:
		return 5 * time.Second
	case OpDown:
		return 30 * time.Second
	case OpGeoUpdate:
		return 2 * time.Minute
	default:
		return time.Minute
	}
}
