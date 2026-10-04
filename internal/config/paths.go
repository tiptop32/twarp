package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const defaultOut = "/usr/local/etc/twarp"

var singBoxCandidates = []string{
	"/opt/homebrew/opt/sing-box/bin/sing-box",
	"/usr/local/opt/sing-box/bin/sing-box",
}

// Paths contains resolved user, output, and sing-box locations.
type Paths struct {
	Home    string
	Out     string
	SingBox string
}

// ConfigFile returns the twarp.yaml path.
func (paths Paths) ConfigFile() string { return filepath.Join(paths.Home, "twarp.yaml") }

// SecretsFile returns the secrets.yaml path.
func (paths Paths) SecretsFile() string { return filepath.Join(paths.Home, "secrets.yaml") }

// GatewayIPsFile returns the persistent gateway IP list path.
func (paths Paths) GatewayIPsFile() string { return filepath.Join(paths.Home, "gateway-ips.json") }

// LockFile returns the gateway IP list lock path.
func (paths Paths) LockFile() string { return filepath.Join(paths.Home, "gateway-ips.lock") }

// AuditFile returns the user audit log path.
func (paths Paths) AuditFile() string { return filepath.Join(paths.Home, "audit.jsonl") }

// OutConfig returns the generated sing-box configuration path.
func (paths Paths) OutConfig() string { return filepath.Join(paths.Out, "config.json") }

// RulesDir returns the generated rule-set directory.
func (paths Paths) RulesDir() string { return filepath.Join(paths.Out, "rules") }

// GeoDir returns the downloaded geo rule-set directory.
func (paths Paths) GeoDir() string { return filepath.Join(paths.Out, "geo") }

// OutputDir returns the generated system configuration directory. Unlike
// Resolve, it does not require a user home or a sing-box installation.
func OutputDir(system Sys) string {
	if out := system.Getenv("TWARP_OUT"); out != "" {
		return out
	}
	return defaultOut
}

// Resolve computes all paths without creating or changing files.
func Resolve(system Sys) (Paths, error) {
	home, err := resolveHome(system)
	if err != nil {
		return Paths{}, err
	}

	out := OutputDir(system)

	singBox := system.Getenv("TWARP_SINGBOX")
	if singBox == "" {
		singBox, err = findSingBox(system)
		if err != nil {
			return Paths{}, err
		}
	}

	return Paths{Home: home, Out: out, SingBox: singBox}, nil
}

// SudoOwner returns the original user's numeric owner when sudo supplied both values.
func SudoOwner(system Sys) (uid, gid int, ok bool) {
	uid, err := strconv.Atoi(system.Getenv("SUDO_UID"))
	if err != nil || uid < 0 {
		return 0, 0, false
	}
	gid, err = strconv.Atoi(system.Getenv("SUDO_GID"))
	if err != nil || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

func resolveHome(system Sys) (string, error) {
	if system.Geteuid() == 0 && system.Getenv("SUDO_USER") == "" {
		return "", errors.New("run via sudo from your user account; SUDO_USER is empty")
	}
	if override := system.Getenv("TWARP_HOME"); override != "" {
		return override, nil
	}

	var home string
	if system.Geteuid() == 0 {
		sudoUser := system.Getenv("SUDO_USER")
		account, err := system.LookupUser(sudoUser)
		if err != nil {
			return "", fmt.Errorf("look up SUDO_USER %q: %w", sudoUser, err)
		}
		home = account.HomeDir
	} else {
		home = system.Getenv("HOME")
	}
	if home == "" {
		return "", errors.New("cannot resolve twarp home: HOME is empty")
	}
	return filepath.Join(home, ".config", "twarp"), nil
}

func findSingBox(system Sys) (string, error) {
	for _, candidate := range singBoxCandidates {
		if _, err := system.Stat(candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("stat sing-box candidate %q: %w", candidate, err)
		}
	}
	return "", nil
}
