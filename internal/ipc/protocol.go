// Package ipc is the protocol between the twarp CLI/TUI and the twarpd root
// daemon: one JSON line per request and per response over a unix socket.
// Requests carry no paths or data, only a fixed operation, so a client can
// do no more than its owner could with sudo twarp start/stop/apply.
package ipc

import (
	"errors"
	"fmt"
	"time"
)

// Version is the protocol version every request must carry.
const Version = 1

// DefaultSocket is where twarpd listens; TWARP_SOCKET overrides it.
const DefaultSocket = "/var/run/twarp/twarpd.sock"

// MaxRequestSize bounds one request line.
const MaxRequestSize = 4096

// Operations.
const (
	OpUp        = "up"
	OpDown      = "down"
	OpApply     = "apply"
	OpGeoUpdate = "geo_update"
	OpStatus    = "status"
)

// Actors a client may name; the daemon records them in the root audit log.
const (
	ActorCLI = "cli"
	ActorTUI = "tui"
)

// ErrorForbidden is the Response.Error for a peer outside the allowed uids.
const ErrorForbidden = "forbidden"

var (
	operations = map[string]struct{}{OpUp: {}, OpDown: {}, OpApply: {}, OpGeoUpdate: {}, OpStatus: {}}
	actors     = map[string]struct{}{ActorCLI: {}, ActorTUI: {}}
)

// Request is one client request.
type Request struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Actor string `json:"actor,omitempty"`
}

// Validate checks the version, operation and actor.
func (request Request) Validate() error {
	if request.V != Version {
		return fmt.Errorf("unsupported protocol version %d, want %d", request.V, Version)
	}
	if _, ok := operations[request.Op]; !ok {
		return fmt.Errorf("unknown operation %q", request.Op)
	}
	if _, ok := actors[request.Actor]; !ok && request.Actor != "" {
		return fmt.Errorf("unknown actor %q", request.Actor)
	}
	return nil
}

// Response is the daemon's answer to one request.
type Response struct {
	OK bool `json:"ok"`
	// Summary is the line the CLI prints for the same operation under sudo.
	Summary string      `json:"summary,omitempty"`
	Error   string      `json:"error,omitempty"`
	Live    *LiveStatus `json:"live,omitempty"`
}

// LiveStatus is what the daemon knows about the running config.
type LiveStatus struct {
	// GatewayConfigured is gateway.socks as written in twarp.yaml.
	GatewayConfigured string `json:"gateway_configured"`
	// GatewayLive is the gateway address in the running config.json.
	GatewayLive     string    `json:"gateway_live"`
	ConfigAppliedAt time.Time `json:"config_applied_at"`
	// Stale is true when twarp.yaml or secrets.yaml is newer than config.json.
	Stale            bool   `json:"stale"`
	LastResolveError string `json:"last_resolve_error,omitempty"`
}

// Client errors.
var (
	ErrDaemonUnavailable = errors.New("twarpd is not running")
	ErrForbidden         = errors.New("twarpd refused the request: the caller is not the twarp owner")
)
