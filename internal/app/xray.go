package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/fsutil"
	"github.com/tiptop32/twarp/internal/launchd"
	"github.com/tiptop32/twarp/internal/sysexec"
	"github.com/tiptop32/twarp/internal/uri"
	"github.com/tiptop32/twarp/internal/xray"
)

// InstallXray validates and starts the named tunnel's non-root login agent.
// It operates independently of the system TUN and never restarts sing-box.
func (s *Service) InstallXray(ctx context.Context, name string) error {
	job, err := s.xrayJob(name)
	if err != nil {
		return err
	}
	release, err := s.lockXrayJob(job)
	if err != nil {
		return err
	}
	defer release()
	cfg, err := config.Load(job.paths.ConfigFile())
	if err != nil {
		return err
	}
	for _, tunnel := range cfg.VPN.Tunnels {
		if tunnel.Name == name && tunnel.Xray != nil {
			return s.installXray(ctx, job, tunnel)
		}
	}
	return fmt.Errorf("VPN tunnel %q has no xray configuration", name)
}

func (s *Service) installXray(ctx context.Context, job xrayJob, tunnel config.Tunnel) error {
	secrets, err := config.LoadSecrets(job.paths.SecretsFile())
	if err != nil {
		return err
	}
	raw := secrets.VPNURIs[tunnel.Name]
	profile, err := uri.Parse(raw)
	if err != nil {
		return fmt.Errorf("VPN tunnel %q: import a valid VPN URI first", tunnel.Name)
	}
	if secrets.ClashSecret == "" {
		return fmt.Errorf("VPN tunnel %q: generate local credentials with twarp import", tunnel.Name)
	}
	binary, err := exec.LookPath("xray")
	if err != nil || !filepath.IsAbs(binary) {
		return errors.New("cannot find Xray at an absolute path on PATH; install it with Homebrew")
	}
	data, err := xray.ClientConfig(tunnel, secrets.ClashSecret, profile)
	if err != nil {
		return err
	}
	check := exec.CommandContext(ctx, binary, "run", "-test", "-c", "stdin:", "-format", "json")
	check.Env = []string{}
	check.Stdin = bytes.NewReader(data)
	if err := check.Run(); err != nil {
		// Xray's parser output can contain profile fields.
		return fmt.Errorf("validate Xray config for %q: %w", tunnel.Name, err)
	}
	plist, err := launchd.XrayPlist(job.label, binary, job.config, job.log)
	if err != nil {
		return err
	}
	if err := s.deps.FS.MkdirAll(filepath.Dir(job.plist), 0o755); err != nil {
		return err
	}
	output, printErr := s.deps.Runner.Run(ctx, "launchctl", "print", job.target)
	state := sysexec.PrintState(output, printErr)
	if state == sysexec.ServiceUnknown {
		return fmt.Errorf("inspect Xray login agent: %w", printErr)
	}
	if err := xray.CheckPort(ctx, s.deps.Runner, job.target, tunnel.Xray.Listen); err != nil {
		return err
	}
	return s.activateXray(ctx, job, state != sysexec.ServiceMissing, data, plist, tunnel.Xray.Listen)
}

func (s *Service) activateXray(ctx context.Context, job xrayJob, loaded bool, data, plist []byte, port uint16) error {
	oldConfig, err := s.deps.FS.ReadFile(job.config)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	oldPlist, err := s.deps.FS.ReadFile(job.plist)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if loaded && (oldConfig == nil || oldPlist == nil) {
		return errors.New("loaded Xray login agent is missing its files; run twarp xray uninstall first")
	}
	restore := func(cause error) error {
		return errors.Join(cause, s.restoreXrayFile(job.config, oldConfig), s.restoreXrayFile(job.plist, oldPlist))
	}
	if err := s.deps.FS.WriteFile(job.config, data, 0o600); err != nil {
		return restore(err)
	}
	if err := s.deps.FS.WriteFile(job.plist, plist, 0o600); err != nil {
		return restore(err)
	}
	if loaded {
		if err := sysexec.Bootout(ctx, s.deps.Runner, job.target); err != nil {
			return restore(err)
		}
	}
	err = sysexec.Bootstrap(ctx, s.deps.Runner, job.domain, job.plist)
	if err == nil {
		err = xray.WaitReady(ctx, s.deps.Runner, job.target, port)
		if err == nil {
			return nil
		}
	}
	// The caller may have cancelled after the old agent was unloaded. Give
	// launchd a separate budget to remove a partial job and load the old one.
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), sysexec.BootoutTimeout+5*time.Second)
	defer cancel()
	if stopErr := sysexec.Bootout(recovery, s.deps.Runner, job.target); stopErr != nil {
		return restore(errors.Join(fmt.Errorf("start Xray login agent: %w; see %s", err, job.log), stopErr))
	}
	cause := fmt.Errorf("start Xray login agent: %w; see %s", err, job.log)
	restoreErr := restore(nil)
	if loaded && restoreErr == nil {
		return errors.Join(cause, sysexec.Bootstrap(recovery, s.deps.Runner, job.domain, job.plist))
	}
	return errors.Join(cause, restoreErr)
}

// UninstallXray stops the named login agent and removes its generated files.
// It is usable even after the tunnel has been removed from twarp.yaml.
func (s *Service) UninstallXray(ctx context.Context, name string) error {
	job, err := s.xrayJob(name)
	if err != nil {
		return err
	}
	release, err := s.lockXrayJob(job)
	if err != nil {
		return err
	}
	defer release()
	if err := sysexec.Bootout(ctx, s.deps.Runner, job.target); err != nil {
		return err
	}
	return errors.Join(s.restoreXrayFile(job.plist, nil), s.restoreXrayFile(job.config, nil))
}

func (s *Service) lockXrayJob(job xrayJob) (func(), error) {
	dir := filepath.Dir(job.config)
	if err := s.deps.FS.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := s.deps.FS.Stat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("directory %s must not be accessible by group or others", dir)
	}
	return fsutil.LockExclusive(job.config + ".lock")
}

func (s *Service) restoreXrayFile(path string, data []byte) error {
	if data != nil {
		return s.deps.FS.WriteFile(path, data, 0o600)
	}
	if err := s.deps.FS.Remove(path); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type xrayJob struct {
	label, domain, target, plist, config, log string
	paths                                     config.Paths
}

func (s *Service) xrayJob(name string) (xrayJob, error) {
	if s.isRoot() {
		return xrayJob{}, ErrRootForbidden
	}
	if !config.ValidXrayTunnelName(name) {
		return xrayJob{}, errors.New("invalid VPN tunnel name")
	}
	home := s.deps.Sys.Getenv("HOME")
	if !filepath.IsAbs(home) {
		return xrayJob{}, errors.New("HOME must be an absolute path")
	}
	paths, err := config.Resolve(s.deps.Sys)
	if err != nil {
		return xrayJob{}, err
	}
	label := xray.AgentLabel(name)
	domain := sysexec.GUIDomain(s.deps.Sys.Geteuid())
	private := filepath.Join(paths.Home, "xray")
	return xrayJob{
		label: label, domain: domain, target: domain + "/" + label,
		paths:  paths,
		plist:  filepath.Join(home, "Library", "LaunchAgents", label+".plist"),
		config: filepath.Join(private, name+".json"), log: filepath.Join(private, name+".log"),
	}, nil
}
