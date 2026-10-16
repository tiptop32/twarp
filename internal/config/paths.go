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

// Owner returns the account that owns the twarp home under root: the sudo
// caller (SUDO_UID/SUDO_GID/SUDO_USER) or, for twarpd, the owner recorded in
// its launchd plist at install (TWARP_OWNER_UID/GID/USER). sudo wins. ok is
// false when neither source supplies valid numeric IDs.
func Owner(system Sys) (uid, gid int, name string, ok bool) {
	if uid, gid, ok := ownerIDs(system, "SUDO_UID", "SUDO_GID"); ok {
		return uid, gid, system.Getenv("SUDO_USER"), true
	}
	if uid, gid, ok := ownerIDs(system, "TWARP_OWNER_UID", "TWARP_OWNER_GID"); ok {
		return uid, gid, system.Getenv("TWARP_OWNER_USER"), true
	}
	return 0, 0, "", false
}

// SudoOwner returns the numeric owner from Owner.
func SudoOwner(system Sys) (uid, gid int, ok bool) {
	uid, gid, _, ok = Owner(system)
	return uid, gid, ok
}

func ownerIDs(system Sys, uidKey, gidKey string) (int, int, bool) {
	uid, err := strconv.Atoi(system.Getenv(uidKey))
	if err != nil || uid < 0 {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(system.Getenv(gidKey))
	if err != nil || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// ownerName is the user whose home root works in: SUDO_USER, else the
// twarpd owner.
func ownerName(system Sys) string {
	if name := system.Getenv("SUDO_USER"); name != "" {
		return name
	}
	if _, _, ok := ownerIDs(system, "TWARP_OWNER_UID", "TWARP_OWNER_GID"); ok {
		return system.Getenv("TWARP_OWNER_USER")
	}
	return ""
}

func resolveHome(system Sys) (string, error) {
	if system.Geteuid() == 0 && ownerName(system) == "" {
		return "", errors.New("run via sudo from your user account or through twarpd; SUDO_USER is empty")
	}
	if override := system.Getenv("TWARP_HOME"); override != "" {
		return override, nil
	}

	var home string
	if system.Geteuid() == 0 {
		owner := ownerName(system)
		account, err := system.LookupUser(owner)
		if err != nil {
			return "", fmt.Errorf("look up owner %q: %w", owner, err)
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
