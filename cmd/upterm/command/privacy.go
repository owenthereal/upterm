package command

import (
	"os"

	"github.com/spf13/cobra"
)

// --hide-client-ip's help: hideClientIPHelp on the commands that print
// guests' addresses, and the rest of host's own after what it hides them
// from.
const (
	hideClientIPDefaultHelp = "When it isn't set (by flag, environment or config file), they are hidden in CI only; --hide-client-ip=false shows them there too."
	hideClientIPHelp        = "Hide guests' IP addresses from upterm's output. " + hideClientIPDefaultHelp
)

var (
	flagHideClientIP bool

	// runningCmd is the command the root's pre-run last applied flags,
	// environment and config to: the one whose --hide-client-ip
	// shouldHideClientIP asks about. Set there, as suppliedFlags is.
	runningCmd *cobra.Command
)

// shouldHideClientIP determines if client IP addresses should be hidden from display.
//
// An explicit --hide-client-ip decides, true or false. It is given by the
// first of these that has a value:
//  1. The --hide-client-ip flag
//  2. The UPTERM_HIDE_CLIENT_IP environment variable (automatically bound by viper)
//  3. hide-client-ip in the config file
//
// Only a flag nobody gave a value falls back to detecting a CI environment.
// This is particularly useful for CI/CD pipelines where session output is
// logged and potentially publicly visible. By default, IPs are automatically
// hidden in detected CI environments to prevent accidental exposure in build
// logs, and --hide-client-ip=false turns that off for a run that wants them.
//
// Usage:
//
//	upterm host --hide-client-ip              # Explicit flag
//	upterm host --hide-client-ip=false        # Shown, even in CI
//	UPTERM_HIDE_CLIENT_IP=true upterm host    # Environment variable (auto-bound)
//	upterm host                               # Auto-detects CI (GitHub Actions, etc.)
func shouldHideClientIP() bool { return shouldHideClientIPFor(runningCmd) }

// shouldHideClientIPFor is shouldHideClientIP for a run of cmd. The flag has a
// value when Changed says so: the command line sets it, and so does an
// environment variable or config key that bindFlagsToEnv applies. An empty
// UPTERM_HIDE_CLIENT_IP gives it none.
func shouldHideClientIPFor(cmd *cobra.Command) bool {
	if cmd != nil {
		if f := cmd.Flag("hide-client-ip"); f != nil && f.Changed {
			return flagHideClientIP
		}
	}

	// Auto-detect CI environments as fallback
	return isCI()
}

// isCI detects if the current process is running in a CI/CD environment
// by checking for common CI environment variables.
func isCI() bool {
	ciEnvVars := []string{
		"CI",                     // Generic CI indicator (GitHub Actions, GitLab CI, etc.)
		"GITHUB_ACTIONS",         // GitHub Actions
		"GITLAB_CI",              // GitLab CI
		"CIRCLECI",               // CircleCI
		"TRAVIS",                 // Travis CI
		"JENKINS_URL",            // Jenkins
		"BUILDKITE",              // Buildkite
		"TF_BUILD",               // Azure Pipelines
		"TEAMCITY_VERSION",       // TeamCity
		"BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
	}

	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	return false
}
