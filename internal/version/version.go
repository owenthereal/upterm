// Package version provides version management and compatibility checking for upterm/uptermd.
//
// This package centralizes version handling across the upterm ecosystem, including:
//   - Single source of truth for version constants
//   - Semantic version parsing and comparison
//   - SSH server version extraction and validation
//   - Host/server compatibility checking with detailed results
//
// The main entry point is CheckCompatibility() which compares the current host version
// with a server's SSH version string and returns detailed compatibility information.
//
// Example usage:
//
//	result := version.CheckCompatibility("SSH-2.0-uptermd-0.14.3")
//	if !result.Compatible {
//	    fmt.Printf("Warning: %s\n", result.Message)
//	    fmt.Printf("Host: %s, Server: %s\n", result.HostVersion, result.ServerVersion)
//	}
package version

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/go-version"
	"github.com/owenthereal/upterm/upterm"
)

// Version is the semantic version of upterm/uptermd
// This is the single source of truth for both client and server versions
const Version = "0.15.0"

// Parse parses a version string using hashicorp's go-version library
func Parse(v string) (*version.Version, error) {
	return version.NewVersion(v)
}

// ParseFromSSHVersion extracts version from SSH version strings like "SSH-2.0-uptermd-0.14.3"
// Uses regex for precise parsing and supports complex semantic versions like "1.0.0-beta.1+build.123"
func ParseFromSSHVersion(sshVersion string) (*version.Version, error) {
	// Build regex pattern using the constant to ensure consistency
	// Escape dots in the server version string for regex safety
	escapedServerVersion := regexp.QuoteMeta(upterm.ServerSSHServerVersion)
	pattern := fmt.Sprintf(`^%s-(.+)$`, escapedServerVersion)

	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(sshVersion)
	if len(matches) != 2 {
		return nil, fmt.Errorf("not a valid uptermd SSH version: %s", sshVersion)
	}

	// Extract and parse the version string
	versionStr := matches[1]
	v, err := Parse(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version format in SSH string %s: %w", sshVersion, err)
	}

	return v, nil
}

// Current returns the current version as a parsed version object
// Panics if Version constant is not a valid semantic version
func Current() *version.Version {
	v, err := Parse(Version)
	if err != nil {
		panic(fmt.Sprintf("invalid version constant %q: %v", Version, err))
	}
	return v
}

// String returns the current version as a string
func String() string {
	return Version
}

// ServerSSHVersion returns the SSH server version string with embedded version
func ServerSSHVersion() string {
	return fmt.Sprintf("%s-%s", upterm.ServerSSHServerVersion, Version)
}

// CompatibilityResult contains the result of version compatibility checking
type CompatibilityResult struct {
	Compatible    bool
	HostVersion   string
	ServerVersion string
	Message       string
}

// CheckCompatibility checks if the server version is compatible with the current host version
// Always returns a result - Compatible=false for unparseable server versions to indicate incompatibility
func CheckCompatibility(sshVersion string) *CompatibilityResult {
	hostVersion := Current()
	hostVersionStr := "v" + hostVersion.String()

	serverVersion, err := ParseFromSSHVersion(sshVersion)
	if err != nil {
		// Can't parse server version - could be older upterm server or non-upterm server
		return &CompatibilityResult{
			Compatible:    false,
			HostVersion:   hostVersionStr,
			ServerVersion: "unknown",
			Message:       "Unable to determine server version - possibly older upterm server or non-upterm server",
		}
	}

	serverVersionStr := "v" + serverVersion.String()

	// Check if major versions match (semantic versioning compatibility)
	hostMajor := hostVersion.Segments()[0]
	serverMajor := serverVersion.Segments()[0]

	if hostMajor != serverMajor {
		return &CompatibilityResult{
			Compatible:    false,
			HostVersion:   hostVersionStr,
			ServerVersion: serverVersionStr,
			Message:       fmt.Sprintf("Major version mismatch: host %s, server %s", hostVersionStr, serverVersionStr),
		}
	}

	return &CompatibilityResult{
		Compatible:    true,
		HostVersion:   hostVersionStr,
		ServerVersion: serverVersionStr,
		Message:       "",
	}
}
