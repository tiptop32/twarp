package config

import (
	"os"
	"os/user"
)

// Sys isolates operating-system lookups so path resolution can be tested safely.
type Sys interface {
	Geteuid() int
	Getenv(string) string
	LookupUser(name string) (*user.User, error)
	Stat(path string) (os.FileInfo, error)
}

// OSSys delegates Sys operations to os and os/user.
type OSSys struct{}

// Geteuid returns the effective user ID.
func (OSSys) Geteuid() int { return os.Geteuid() }

// Getenv returns an environment variable.
func (OSSys) Getenv(name string) string { return os.Getenv(name) }

// LookupUser resolves an operating-system user by name.
func (OSSys) LookupUser(name string) (*user.User, error) { return user.Lookup(name) }

// Stat returns file information for path.
func (OSSys) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
