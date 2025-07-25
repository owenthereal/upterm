package version

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/owenthereal/upterm/upterm"
)

// Version is the semantic version of upterm/uptermd
// This is the single source of truth for both client and server versions
const Version = "0.14.3"

// Parse parses a version string using hashicorp's go-version library
func Parse(v string) (*version.Version, error) {
	return version.NewVersion(v)
}

// ParseFromSSHVersion extracts version from SSH version strings like "SSH-2.0-uptermd-0.14.3"
func ParseFromSSHVersion(sshVersion string) (*version.Version, error) {
	// Handle SSH version strings that include version suffix
	if strings.HasPrefix(sshVersion, upterm.ServerSSHServerVersion) {
		parts := strings.Split(sshVersion, "-")
		if len(parts) >= 4 { // SSH-2.0-uptermd-0.14.3 has 4+ parts
			// Try to parse the last part as version
			versionStr := parts[len(parts)-1]
			if v, err := Parse(versionStr); err == nil {
				return v, nil
			}
		}
	}

	// If no version found in SSH string, return error
	return nil, fmt.Errorf("no version found in SSH version string: %s", sshVersion)
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
// Always returns a result - Compatible=true for unparseable server versions to allow graceful fallback
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
