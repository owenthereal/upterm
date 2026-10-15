package command

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func configCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage upterm configuration",
		Long: fmt.Sprintf(`Manage upterm configuration file.

Config file: %s

This follows the XDG Base Directory Specification.

Configuration priority (highest to lowest):
  1. Command-line flags
  2. Environment variables (UPTERM_ prefix)
  3. Config file
  4. Default values`, configPath),
	}

	cmd.AddCommand(configPathCmd())
	cmd.AddCommand(configViewCmd())
	cmd.AddCommand(configEditCmd())

	return cmd
}

func configPathCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Show the path to the config file",
		Long: fmt.Sprintf(`Show the path to the config file.

Config file: %s

The config file is optional and created manually by users.`, configPath),
		Example: `  # Show config file path:
  upterm config path

  # Create config file directory:
  mkdir -p "$(dirname "$(upterm config path)")"`,
		RunE: configPathRunE,
	}

	return cmd
}

func configViewCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "view",
		Short: "View the config file contents",
		Long: fmt.Sprintf(`View the config file contents.

Config file: %s

If the config file exists, this command displays its contents. If it doesn't
exist, this command shows an example config file that you can use as a template.`, configPath),
		Example: `  # View current config:
  upterm config view

  # View and save as new config:
  upterm config view > "$(upterm config path)"`,
		RunE: configViewRunE,
	}

	return cmd
}

func configEditCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit the config file",
		Long: fmt.Sprintf(`Edit the config file in your default editor.

Config file: %s

This command opens the config file in your editor (determined by $VISUAL, $EDITOR,
or a sensible default). If the config file doesn't exist, it creates a template
with example settings and comments.

The config directory is created automatically if it doesn't exist.`, configPath),
		Example: `  # Edit config file:
  upterm config edit

  # Use a specific editor:
  EDITOR=nano upterm config edit`,
		RunE: configEditRunE,
	}

	return cmd
}

func configPathRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()
	fmt.Println(configPath)
	return nil
}

func configViewRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Show example config
		fmt.Println("# Config file does not exist. Example config:")
		fmt.Println()
		fmt.Print(exampleConfig())
		return nil
	}

	// Read and display file
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	fmt.Print(string(content))
	return nil
}

func configEditRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()
	configDir := utils.UptermConfigDir()

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create example config if file doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.WriteFile(configPath, []byte(exampleConfig()), 0600); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	cmd, err := editorCommand(os.Getenv, configPath)
	if err != nil {
		return err
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// An editor that started and ended badly may not be done with the
		// file, so it isn't checked.
		var ended *exec.ExitError
		if errors.As(err, &ended) {
			if code := ended.ExitCode(); code >= 0 {
				return fmt.Errorf("the editor exited with status %d; %s wasn't checked", code, configPath)
			}
			return fmt.Errorf("the editor ended with %v; %s wasn't checked", ended, configPath)
		}
		return fmt.Errorf("failed to open editor: %w", err)
	}

	// Check the file as commands will read it, and say everything wrong with
	// it at once.
	if errs := validateConfigFile(c.Root(), configPath); len(errs) > 0 {
		return multierror.Append(nil, errs...)
	}

	return nil
}

// editorCommand is the command that opens path in the user's editor: $VISUAL
// (for full-screen editors), then $EDITOR (for line editors), then the
// platform's default; a variable that is blank counts as unset, and the space
// around a value is no part of it. The variable may carry arguments, as in
// code --wait; editorWords splits it.
func editorCommand(getenv func(string) string, path string) (*exec.Cmd, error) {
	variable, line := "", defaultEditor()
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if s := strings.TrimSpace(getenv(name)); s != "" {
			variable, line = name, s
			break
		}
	}

	words, err := editorWords(line)
	if err != nil {
		return nil, fmt.Errorf("can't read $%s: %w", variable, err)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("$%s names no program", variable)
	}
	return exec.Command(words[0], append(words[1:], path)...), nil
}

// editorWords is the program and arguments an editor variable holds. A value
// that names a file is that program whole: an unquoted path with spaces in it,
// such as /Applications/Sublime Text.app/Contents/SharedSupport/bin/subl or
// C:\Program Files\Notepad++\notepad++.exe, split at the spaces would name a
// program that isn't there. Anything else, a quoted path or a path with
// arguments, is split by editorArgs.
func editorWords(line string) ([]string, error) {
	if fi, err := os.Stat(line); err == nil && !fi.IsDir() {
		return []string{line}, nil
	}
	return editorArgs(line)
}

// defaultEditor is the editor when neither $VISUAL nor $EDITOR is set.
func defaultEditor() string {
	switch runtime.GOOS {
	case "windows":
		return "notepad"
	default:
		// Unix-like systems: prefer nano for better UX, fall back to vi
		if _, err := exec.LookPath("nano"); err == nil {
			return "nano"
		}
		return "vi"
	}
}

// fixConfig is what each problem with the config file ends on.
const fixConfig = "run upterm config edit to fix it"

// configProblem is one thing wrong with a config file: the key it is about,
// which orders the problems, and what is wrong with it.
type configProblem struct {
	key, what string
}

// validateConfigFile checks the config file at path the way commands read it
// and returns every problem, sorted by key (a file that isn't YAML is one
// problem, whole). Each names the file and ends on how to fix it. A key is a
// problem when it is unknown, has no value, or holds a value its flag refuses;
// and when its value passes the flag but fails a check that the command it
// belongs to makes before running (host's, and the session commands' output
// format), made by the functions that command itself calls. The checks are
// the table and the loop over the users below it. A file that doesn't exist
// has no problems, as commands read it.
//
// It applies the file's values to the flags under root, so those flags hold
// them afterwards: config edit's process exits after it.
func validateConfigFile(root *cobra.Command, path string) []error {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		var parseErr viper.ConfigParseError
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case errors.As(err, &parseErr):
			return []error{fmt.Errorf("%s: %w; %s", path, err, fixConfig)}
		default:
			return []error{fmt.Errorf("failed to read config file %s: %w", path, err)}
		}
	}

	known := knownFlagNames(root)
	settable := make(map[string][]*pflag.Flag)
	visitTreeFlags(root, func(f *pflag.Flag) {
		if f.Name != "help" && !hasAnnotation(f, annotationCLIOnly) {
			settable[f.Name] = append(settable[f.Name], f)
		}
	})

	var problems []configProblem
	failed := make(map[string]bool)
	problem := func(key, what string) {
		problems = append(problems, configProblem{key, what})
		failed[key] = true
	}

	keys := v.AllKeys()
	slices.Sort(keys)
	for _, key := range keys {
		switch {
		case !known[key]:
			problem(key, fmt.Sprintf("unknown key %q", key))
		case !v.IsSet(key):
			problem(key, key+": config key has no value")
		default:
			if err := setFlagsFromConfig(settable[key], key, v.Get(key)); err != nil {
				problem(key, err.Error())
			}
		}
	}

	// The checks a command makes before it runs, on the values just applied. A
	// default passes them, so a check runs only when the file holds the keys it
	// reads, and none of them was refused above. A problem is named after the
	// first key.
	held := make(map[string]bool, len(keys))
	for _, key := range keys {
		held[key] = true
	}
	for _, c := range []struct {
		keys  []string
		check func() error
	}{
		{[]string{"join-timeout"}, func() error { return validateJoinTimeout(flagJoinTimeout) }},
		{[]string{"read-only", "allow-local-tcp-forwarding"}, func() error {
			return validateReadOnlyForwarding(flagReadOnly, flagAllowLocalTCPForwarding)
		}},
		// detach is judged on accept's value, unless accept is itself refused.
		{[]string{"detach"}, func() error {
			if failed["accept"] {
				return nil
			}
			return validateDetachAccept(flagDetach, flagAccept)
		}},
		{[]string{"server"}, func() error { return validateServer(flagServer) }},
		{[]string{"proxy"}, func() error { _, err := parseProxyURL(flagProxy); return err }},
		{[]string{"escape-char"}, func() error { _, err := parseEscapeChar(flagHostEscapeChar); return err }},
		{[]string{"pty-size"}, func() error {
			if flagPtySize == "" {
				return nil
			}
			_, err := termsize.Parse(flagPtySize)
			return err
		}},
		{[]string{"force-command"}, func() error { _, err := parseForceCommand(flagForceCommand); return err }},
		{[]string{"name"}, func() error { return validateSessionNameFlag(flagName) }},
		// Valid for the commands that print a session, host's -o json among
		// them; a command that wants more of it (host needs --detach) asks
		// when it runs.
		{[]string{"output"}, func() error {
			if flagOutput == "" {
				return nil
			}
			_, err := sessionOutput(flagOutput)
			return err
		}},
	} {
		runs := true
		for _, key := range c.keys {
			runs = runs && held[key] && !failed[key]
		}
		if !runs {
			continue
		}
		if err := c.check(); err != nil {
			problem(c.keys[0], c.keys[0]+": "+err.Error())
		}
	}
	// Each user a flag names must be one host.ParseUserRef reads, as hosting
	// does; the legacy per-service flags are keys too.
	for _, flag := range userSpecs() {
		if !held[flag.flag] || failed[flag.flag] {
			continue
		}
		for _, spec := range flag.specs {
			if _, err := host.ParseUserRef(spec); err != nil {
				problem(flag.flag, flag.flag+": "+err.Error())
			}
		}
	}

	slices.SortStableFunc(problems, func(a, b configProblem) int { return strings.Compare(a.key, b.key) })
	errs := make([]error, 0, len(problems))
	for _, p := range problems {
		errs = append(errs, fmt.Errorf("%s: %s; %s", path, p.what, fixConfig))
	}
	return errs
}

// setFlagsFromConfig sets each of flags, all named name, to val, a value from
// the config file converted as bindFlagsToEnv converts it. It stops at the
// first flag that refuses.
func setFlagsFromConfig(flags []*pflag.Flag, name string, val any) error {
	for _, flag := range flags {
		if sv, ok := flag.Value.(pflag.SliceValue); ok {
			elems, err := toStringSlice(name, val)
			if err != nil {
				return err
			}
			if err := sv.Replace(elems); err != nil {
				return fmt.Errorf("%s: cannot use value %q: %w", name, strings.Join(elems, ","), err)
			}
			continue
		}

		scalar, err := toScalarString(name, val)
		if err != nil {
			return err
		}
		if err := flag.Value.Set(scalar); err != nil {
			return fmt.Errorf("%s: cannot use value %q: %w", name, scalar, err)
		}
	}
	return nil
}

// exampleConfig returns an example config file with comments.
func exampleConfig() string {
	return `# Upterm Configuration File
#
# This file follows the XDG Base Directory Specification.
# Settings here are overridden by environment variables (UPTERM_*) and command-line flags.
#
# Configuration priority (highest to lowest):
#   1. Command-line flags
#   2. Environment variables (UPTERM_* prefix)
#   3. This config file
#   4. Default values

# Debug logging (default: false)
# When enabled, writes debug-level logs to the log file.
# debug: true

# Default server address for hosting sessions (default: ssh://uptermd.upterm.dev:22)
# Supported protocols: ssh, ws, wss
# server: ssh://uptermd.upterm.dev:22

# HTTP proxy to connect to the server through (default: none)
# Applies to ssh, ws and wss servers. Without it, ws and wss connections
# use HTTPS_PROXY/HTTP_PROXY. Credentials go in the URL.
# proxy: http://user:pass@proxy.example.com:3128

# Force a specific command for clients (default: none)
# When set, clients cannot run arbitrary commands.
# force-command: "/bin/bash -l"

# Path to authorized_keys file for client authentication (default: none)
# authorized-keys: /path/to/authorized_keys

# Authorize users by fetching their public keys from a code-hosting service
# (default: none). Forms:
#   github:alice                 GitHub (honors GH_HOST when no host is given)
#   github:bob@ghe.example.com   GitHub Enterprise Server
#   gitea:carol@git.example.com  self-hosted Gitea or Forgejo (host required)
#   gitlab:erin, codeberg:frank, srht:dave
#   https://git.example.com/bob  any forge serving {url}.keys
# authorized-user:
#   - github:alice
#   - gitea:carol@git.example.com

# Identity files (default: SSH agent keys, then ~/.ssh/id_* files, then a
# generated key). Setting this makes the list the whole set, like OpenSSH's
# IdentitiesOnly: each file must load, a .pub selects that key in the agent,
# and other agent keys are not offered.
# private-key:
#   - /path/to/private/key1
#   - /path/to/id_ed25519_sk.pub

# Read-only mode (default: false)
# When enabled, clients can view but not interact with the session.
# read-only: false

# Allow clients to use SSH local TCP forwarding (ssh -L) (default: false)
# When enabled, clients can reach TCP destinations visible to the host.
# Cannot be combined with read-only.
# allow-local-tcp-forwarding: false

# Auto-accept clients without confirmation (default: false)
# WARNING: Only use this in trusted environments.
# accept: false

# Hide client IP addresses from logs and display (default: false)
# hide-client-ip: false
`
}
