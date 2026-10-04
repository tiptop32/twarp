// Package app is the application layer shared by the CLI, TUI and MCP server.
// Front ends parse input and render output; every read or change of config,
// gateway state, launchd or sing-box goes through Service so they cannot drift.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
)

// DefaultLogDir holds the sing-box and geo logs and the root audit log.
const DefaultLogDir = "/usr/local/var/log/twarp"

// Actors recorded in audit logs.
const (
	ActorCLI = "cli"
	ActorTUI = "tui"
	ActorMCP = "mcp"
)

// ErrRootRequired is returned by operations that change system state.
var ErrRootRequired = errors.New("run with sudo")

// ErrRootForbidden is returned by operations on user-owned files under sudo:
// they would leave root-owned files in the twarp home.
var ErrRootForbidden = errors.New("do not run with sudo")

// Deps are the system boundaries of Service. Tests replace them with fakes.
type Deps struct {
	Sys        config.Sys
	Runner     sysexec.Runner
	FS         launchd.FS
	Dial       func(context.Context, string, string) (net.Conn, error)
	HTTPClient *http.Client
	LookupIP   func(context.Context, string, string) ([]net.IP, error)
	Now        func() time.Time
	// Clash builds the sing-box liveness probe used after gateway changes.
	Clash func(config.Config, config.Secrets) func() bool
	// GeoOptions overrides download settings; Dir and AuditFile are always set
	// by GeoUpdate.
	GeoOptions geo.Options
}

// Service implements twarp operations for one front end, identified by actor
// in audit records.
type Service struct {
	deps  Deps
	actor string
}

// New returns a Service that records actor in audit logs.
func New(deps Deps, actor string) *Service {
	return &Service{deps: deps, actor: actor}
}

func (s *Service) now() time.Time {
	if s.deps.Now == nil {
		return time.Now()
	}
	return s.deps.Now()
}

func (s *Service) isRoot() bool {
	return s.deps.Sys != nil && s.deps.Sys.Geteuid() == 0
}

// LogDir returns the directory of the daemon logs and the root audit log.
func LogDir(system config.Sys) string {
	if directory := system.Getenv("TWARP_LOG_DIR"); directory != "" {
		return directory
	}
	return DefaultLogDir
}

// RootAuditFile is the audit log written by root commands; user commands write
// to the audit log in the twarp home instead.
func RootAuditFile(system config.Sys) string {
	return filepath.Join(LogDir(system), "audit.jsonl")
}

// SingBoxLogFile is where launchd sends sing-box output.
func SingBoxLogFile(system config.Sys) string {
	return filepath.Join(LogDir(system), "sing-box.log")
}

func (s *Service) appendRootAudit(operation, result string) error {
	path := RootAuditFile(s.deps.Sys)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit directory %q: %w", filepath.Dir(path), err)
	}
	record := struct {
		TS     time.Time `json:"ts"`
		Actor  string    `json:"actor"`
		Op     string    `json:"op"`
		Result string    `json:"result"`
	}{TS: s.now().UTC(), Actor: s.actor, Op: operation, Result: result}
	if err := fsutil.AppendJSONLine(path, record); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}
