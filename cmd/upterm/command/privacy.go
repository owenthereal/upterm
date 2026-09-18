package command

import (
	"github.com/owenthereal/upterm/internal/ci"
)

var (
	flagHideClientIP bool
)

// shouldHideClientIP determines if client IP addresses should be hidden from display.
//
// This function checks conditions in this priority order:
//  1. Explicit --hide-client-ip flag (overrides everything)
//  2. UPTERM_HIDE_CLIENT_IP environment variable (automatically bound by viper)
//  3. Auto-detect CI environment (if neither flag nor env var set)
//
// This is particularly useful for CI/CD pipelines where session output is logged
// and potentially publicly visible. By default, IPs are automatically hidden in
// detected CI environments to prevent accidental exposure in build logs.
//
// Usage:
//
//	upterm host --hide-client-ip              # Explicit flag
//	UPTERM_HIDE_CLIENT_IP=true upterm host    # Environment variable (auto-bound)
//	upterm host                               # Auto-detects CI (GitHub Actions, etc.)
func shouldHideClientIP() bool {
	// If flag is set (either via CLI flag or via UPTERM_HIDE_CLIENT_IP env var bound by viper)
	if flagHideClientIP {
		return true
	}

	// Auto-detect CI environments as fallback
	return isCI()
}

// isCI detects if the current process is running in a CI/CD environment.
//
// The environment-variable list lives in internal/ci, which is also what
// `upterm ci` detects its provider with. Two copies of it would drift, and the
// consequence of drifting here is a client IP printed into a public build log
// on whichever CI system only one of the copies knows about.
func isCI() bool {
	return ci.IsCI()
}
