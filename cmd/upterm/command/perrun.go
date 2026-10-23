package command

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The annotations below mark flags that env and config shouldn't set. One
// namespace serves every command, so a value meant for one run of one command
// (host's --name, say) reached every run of every command with a flag of that
// name.
const (
	annotationPerRun  = "upterm/per-run"  // env/config ignored, with a notice
	annotationCLIOnly = "upterm/cli-only" // never bound to env or config
)

// perRunIgnoredFrom is the release from which per-run values from env or
// config are ignored.
const perRunIgnoredFrom = "v0.40"

// perRun marks flags of fs as per-run.
func perRun(fs *pflag.FlagSet, names ...string) {
	for _, name := range names {
		// Only errors on an unknown flag name; the test of the per-run flags,
		// TestPerRunFlagsAreExactlyTheRunsOwnChoices, pins the list.
		_ = fs.SetAnnotation(name, annotationPerRun, []string{"true"})
	}
}

// hasAnnotation reports whether f carries the annotation key.
func hasAnnotation(f *pflag.Flag, key string) bool {
	_, ok := f.Annotations[key]
	return ok
}

// deprecation is one per-run value that came from env or config: Source is
// the environment variable, or the config file when InConfig. Command is
// the command's path when a flag of that name is still bound on another
// command (only session set's --join-timeout, host's being bound), since
// env and config keep setting it there; empty otherwise.
type deprecation struct {
	Flag, Source string
	InConfig     bool
	Command      string
}

// perRunDeprecations is a deprecation for each value env and config hold for
// the per-run flag name of cmd. An empty variable holds none: viper reads
// it as unset.
func perRunDeprecations(cmd *cobra.Command, name, configPath string, inConfig bool) []deprecation {
	var command string
	if boundElsewhere(cmd, name) {
		command = cmd.CommandPath()
	}
	var deps []deprecation
	if os.Getenv(envVarName(name)) != "" {
		deps = append(deps, deprecation{Flag: name, Source: envVarName(name), Command: command})
	}
	if inConfig {
		deps = append(deps, deprecation{Flag: name, Source: configPath, InConfig: true, Command: command})
	}
	return deps
}

// boundElsewhere reports whether some command in cmd's tree has a flag
// named name that env and config still set: one with neither annotation.
func boundElsewhere(cmd *cobra.Command, name string) bool {
	bound := false
	visitTreeFlags(cmd, func(f *pflag.Flag) {
		if f.Name == name && !hasAnnotation(f, annotationPerRun) && !hasAnnotation(f, annotationCLIOnly) {
			bound = true
		}
	})
	return bound
}

// ignoredLine is the notice for an env or config value that is ignored.
func (d deprecation) ignoredLine() string {
	what := d.Source
	if d.InConfig {
		what = fmt.Sprintf("the %s key in %s", d.Flag, d.Source)
	}
	if d.Command != "" {
		what += " for " + d.Command
	}
	return fmt.Sprintf("upterm: ignoring %s; pass --%s", what, d.Flag)
}

// warnDeprecations prints each deprecation's line on w, in the parent only:
// the daemon re-parses the same argv, env and config, so it has the same
// ones, and its stderr is the log.
func warnDeprecations(w io.Writer, deps []deprecation) {
	if isDaemonProcess() {
		return
	}
	for _, d := range deps {
		_, _ = fmt.Fprintln(w, d.ignoredLine())
	}
}
