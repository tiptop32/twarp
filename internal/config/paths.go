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

// Owner identifies the user a root process acts for.
type Owner struct {
	UID  int
	GID  int
	User string
}

// OwnerFromEnv returns the owner of a root process: the sudo user when sudo
// started it, otherwise TWARP_OWNER_UID, TWARP_OWNER_GID and TWARP_OWNER_USER,
// which install writes into the twarpd launchd plist. ok is false when
// neither source has a valid numeric uid and gid.
func OwnerFromEnv(system Sys) (owner Owner, ok bool) {
	for _, prefix := range []string{"SUDO_", "TWARP_OWNER_"} {
		uid, uidErr := strconv.Atoi(system.Getenv(prefix + "UID"))
		gid, gidErr := strconv.Atoi(system.Getenv(prefix + "GID"))
		if uidErr == nil && gidErr == nil && uid >= 0 && gid >= 0 {
			return Owner{UID: uid, GID: gid, User: system.Getenv(prefix + "USER")}, true
		}
	}
	return Owner{}, false
}

// SudoOwner returns the original user's numeric owner when sudo supplied both
// values. Install uses it: only a real sudo session may choose the owner.
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

// ownerUser is the account whose home holds twarp state for a root process.
func ownerUser(system Sys) string {
	if sudoUser := system.Getenv("SUDO_USER"); sudoUser != "" {
		return sudoUser
	}
	return system.Getenv("TWARP_OWNER_USER")
}

func resolveHome(system Sys) (string, error) {
	if system.Geteuid() == 0 && ownerUser(system) == "" {
		return "", errors.New("run via sudo from your user account or through twarpd; SUDO_USER is empty")
	}
	if override := system.Getenv("TWARP_HOME"); override != "" {
		return override, nil
	}

	var home string
	if system.Geteuid() == 0 {
		name := ownerUser(system)
		account, err := system.LookupUser(name)
		if err != nil {
			return "", fmt.Errorf("look up owner %q: %w", name, err)
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
