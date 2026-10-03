package launchd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/geo"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
)

// FS isolates filesystem changes made by Install and Uninstall.
type FS interface {
	MkdirAll(path string, mode fs.FileMode) error
	Chown(path string, uid, gid int) error
	WriteFile(path string, data []byte, mode fs.FileMode) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
}

// OSFS applies filesystem operations to the host.
type OSFS struct{}

// MkdirAll delegates to os.MkdirAll.
func (OSFS) MkdirAll(path string, mode fs.FileMode) error { return os.MkdirAll(path, mode) }

// Chown delegates to os.Chown.
func (OSFS) Chown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

// WriteFile atomically replaces path with data and exactly mode. Unlike
// os.WriteFile it never keeps the permissions of an existing file, so a
// config.json that was once world-readable cannot stay that way.
func (OSFS) WriteFile(path string, data []byte, mode fs.FileMode) error {
	return fsutil.WriteFileAtomic(path, data, mode)
}

// Remove delegates to os.Remove.
func (OSFS) Remove(path string) error { return os.Remove(path) }

// Stat delegates to os.Stat.
func (OSFS) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }

// Deps contains all operating-system boundaries used by lifecycle operations.
type Deps struct {
	Runner     sysexec.Runner
	Sys        config.Sys
	FS         FS
	Executable func() (string, error)
}

// Options contains resolved inputs and prepared render operations for Install.
type Options struct {
	Paths        config.Paths
	Config       config.Config
	Secrets      config.Secrets
	GeoUpdate    func(context.Context) error
	RenderConfig func() ([]byte, error)
	WriteRuleSet func(dir string) error
}

// Install validates the host, prepares sing-box files, and loads both system services.
func Install(ctx context.Context, deps Deps, options Options) error {
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	uid, gid, ok := config.SudoOwner(deps.Sys)
	if !ok {
		return errors.New("run with sudo: SUDO_UID and SUDO_GID are required")
	}
	if options.Paths.SingBox == "" {
		return errors.New("sing-box executable is not configured")
	}
	if deps.Runner == nil || deps.FS == nil {
		return errors.New("install dependencies are incomplete")
	}
	if _, err := singbox.Version(ctx, deps.Runner, options.Paths.SingBox); err != nil {
		return err
	}
	conflict, err := DetectConflict(ctx, deps.Runner)
	if err != nil {
		return err
	}
	if conflict.Hint != "" {
		return errors.New(conflict.Hint)
	}
	if err := CheckBrewService(ctx, deps.Runner, uid); err != nil {
		return err
	}

	for _, directory := range []string{options.Paths.RulesDir(), options.Paths.GeoDir(), logDir, workingDir} {
		if err := deps.FS.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", directory, err)
		}
	}
	if err := deps.FS.Chown(options.Paths.RulesDir(), uid, gid); err != nil {
		return fmt.Errorf("give rule-set directory to sudo user: %w", err)
	}

	missingGeo, err := geoFilesMissing(deps.FS, options.Paths.GeoDir())
	if err != nil {
		return err
	}
	if missingGeo {
		if options.GeoUpdate == nil {
			return errors.New("geo update is unavailable")
		}
		if err := options.GeoUpdate(ctx); err != nil {
			return fmt.Errorf("update geo rule-sets: %w", err)
		}
	}

	if options.RenderConfig == nil || options.WriteRuleSet == nil {
		return errors.New("render operations are incomplete")
	}
	configJSON, err := options.RenderConfig()
	if err != nil {
		return fmt.Errorf("render sing-box config: %w", err)
	}
	if err := deps.FS.WriteFile(options.Paths.OutConfig(), configJSON, 0o600); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}
	if err := options.WriteRuleSet(options.Paths.RulesDir()); err != nil {
		return fmt.Errorf("write gateway rule-set: %w", err)
	}
	if err := deps.FS.Chown(render.RuleSetPath(options.Paths.RulesDir()), uid, gid); err != nil {
		return fmt.Errorf("give gateway rule-set to sudo user: %w", err)
	}
	if err := singbox.Check(ctx, deps.Runner, options.Paths.SingBox, options.Paths.OutConfig()); err != nil {
		return err
	}

	singBoxPlist, err := SingBoxPlist(options.Paths)
	if err != nil {
		return err
	}
	if err := deps.FS.WriteFile(SingBoxPlistPath, singBoxPlist, 0o644); err != nil {
		return fmt.Errorf("write sing-box plist: %w", err)
	}
	if err := sysexec.Bootout(ctx, deps.Runner, sysexec.SystemTarget()); err != nil {
		return fmt.Errorf("unload existing sing-box service: %w", err)
	}
	if err := sysexec.Bootstrap(ctx, deps.Runner, "system", SingBoxPlistPath); err != nil {
		return fmt.Errorf("load sing-box service: %w", err)
	}

	if deps.Executable == nil {
		return errors.New("resolve twarp executable: dependency is unavailable")
	}
	executable, err := deps.Executable()
	if err != nil {
		return fmt.Errorf("resolve twarp executable: %w", err)
	}
	geoPlist, err := GeoPlist(executable)
	if err != nil {
		return err
	}
	if err := deps.FS.WriteFile(GeoPlistPath, geoPlist, 0o644); err != nil {
		return fmt.Errorf("write geo plist: %w", err)
	}
	geoTarget := "system/" + sysexec.GeoLabel
	if err := sysexec.Bootout(ctx, deps.Runner, geoTarget); err != nil {
		return fmt.Errorf("unload existing geo service: %w", err)
	}
	if err := sysexec.Bootstrap(ctx, deps.Runner, "system", GeoPlistPath); err != nil {
		return fmt.Errorf("load geo service: %w", err)
	}

	if err := deps.FS.WriteFile(NewsyslogPath, NewsyslogConfig(), 0o644); err != nil {
		return fmt.Errorf("write newsyslog config: %w", err)
	}
	return nil
}

// Uninstall unloads and removes twarp service definitions while preserving config and state.
func Uninstall(ctx context.Context, deps Deps) error {
	if deps.Sys == nil || deps.Sys.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	if deps.Runner == nil || deps.FS == nil {
		return errors.New("uninstall dependencies are incomplete")
	}

	var uninstallErrors []error
	if err := sysexec.Bootout(ctx, deps.Runner, sysexec.SystemTarget()); err != nil {
		uninstallErrors = append(uninstallErrors, fmt.Errorf("unload sing-box service: %w", err))
	}
	if err := sysexec.Bootout(ctx, deps.Runner, "system/"+sysexec.GeoLabel); err != nil {
		uninstallErrors = append(uninstallErrors, fmt.Errorf("unload geo service: %w", err))
	}
	for _, path := range []string{SingBoxPlistPath, GeoPlistPath, NewsyslogPath} {
		if err := deps.FS.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			uninstallErrors = append(uninstallErrors, fmt.Errorf("remove %q: %w", path, err))
		}
	}
	return errors.Join(uninstallErrors...)
}

func geoFilesMissing(filesystem FS, directory string) (bool, error) {
	for _, source := range geo.DefaultSources {
		path := filepath.Join(directory, source.Name)
		if _, err := filesystem.Stat(path); errors.Is(err, os.ErrNotExist) {
			return true, nil
		} else if err != nil {
			return false, fmt.Errorf("inspect geo rule-set %q: %w", path, err)
		}
	}
	return false, nil
}
