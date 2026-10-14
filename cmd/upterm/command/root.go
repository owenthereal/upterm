package command

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// suppliedFlags records which flags were supplied from any origin: explicit
// command-line flags, environment variables, or the config file. The
// fail-closed guard in host.go needs the union, because pflag's
// SliceValue.Replace never sets flag.Changed and the sync loop below skips
// flags that already are Changed.
var suppliedFlags = map[string]bool{}

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Instant Terminal Sharing",
		Long: `Upterm is an open-source solution for sharing terminal sessions instantly over secure SSH tunnels to the public internet.

Configuration Priority (highest to lowest):
  1. Command-line flags
  2. Environment variables (UPTERM_ prefix)
  3. Config file (see below)
  4. Default values

Config File:
  ~/.config/upterm/config.yaml (Linux)
  ~/Library/Application Support/upterm/config.yaml (macOS)
  %LOCALAPPDATA%\upterm\config.yaml (Windows)

  Run 'upterm config path' to see your config file location.
  Run 'upterm config edit' to create and edit the config file.

Environment Variables:
  All flags can be set via environment variables with the UPTERM_ prefix.
  Flag names are converted by replacing hyphens (-) with underscores (_).

  Examples:
    --hide-client-ip  → UPTERM_HIDE_CLIENT_IP=true
    --read-only       → UPTERM_READ_ONLY=true
    --accept          → UPTERM_ACCEPT=true`,
		Example: `  # Host a terminal session running $SHELL, attaching client's IO to the host's:
  $ upterm host

  # Display the connection string for sharing with client(s):
  $ upterm session current
  Session: SESSION_ID

  Command:          /bin/bash
  Host:             ssh://uptermd.upterm.dev:22

  ➤ Join:
      upterm join ssh://TOKEN@uptermd.upterm.dev
  ➤ SSH:
      ssh TOKEN@uptermd.upterm.dev
  ➤ SFTP:
      sftp TOKEN@uptermd.upterm.dev
  ➤ SCP:
      scp <local> TOKEN@uptermd.upterm.dev:<remote>
      scp TOKEN@uptermd.upterm.dev:<remote> <local>

  Connected Clients:
    host local SSH-2.0-upterm-attach SHA256:FINGERPRINT

  # A client joins the host session, and rejoins on its own if the connection drops:
  $ upterm join ssh://TOKEN@uptermd.upterm.dev

  # Or with plain ssh (no install needed):
  $ ssh TOKEN@uptermd.upterm.dev

  # Set flags via environment variables:
  $ UPTERM_HIDE_CLIENT_IP=true upterm host`,
		// For every command: cobra checks the root's. Exit prints each error
		// once, as one line, and never the usage (D1); cobra would print
		// "Error: ...", often the usage block too, and then main its own copy.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// The root and the groups only print their help or name an
			// unknown command (reportUnknownCommands), and read no config:
			// a broken config file mustn't stop `upterm session` showing
			// the help it showed when cobra couldn't run it.
			if cmd.HasSubCommands() {
				return nil
			}

			// Bind all flags to environment variables with UPTERM_ prefix. A
			// config or env error fails only a command that reads config
			// (D11.1), and never `upterm config`, which repairs the file.
			supplied, deps, err := bindFlagsToEnv(cmd)
			if err != nil && readsConfig(cmd) && !isConfigCommand(cmd) {
				return err
			}
			suppliedFlags = supplied
			warnDeprecations(cmd.ErrOrStderr(), deps)

			debug, _ := cmd.Flags().GetBool("debug")

			logPath := utils.UptermLogFilePath()
			logOptions := []logging.Option{logging.File(logPath)}
			if debug {
				logOptions = append(logOptions, logging.Debug())
			}

			// A log file that can't be opened fails nothing either: logging
			// is off for the run, with one warning.
			warning := &logWarning{w: cmd.ErrOrStderr()}
			logger, err := logging.New(logOptions...)
			if err != nil {
				warning.warn(logPath, err)
				logger = logging.Must(logging.Discard())
			}

			ctx := uptermctx.WithLogger(cmd.Context(), logger)
			cmd.SetContext(context.WithValue(ctx, logWarningKey{}, warning))

			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if logger := uptermctx.Logger(cmd.Context()); logger != nil {
				return logger.Close()
			}

			return nil
		},
	}

	logPath := utils.UptermLogFilePath()
	rootCmd.PersistentFlags().Bool("debug", os.Getenv("DEBUG") != "",
		fmt.Sprintf("enable debug level logging (log file: %s).", logPath))

	rootCmd.AddCommand(attachCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(joinCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(upgradeCmd())
	rootCmd.AddCommand(versionCmd())

	reportUnknownCommands(rootCmd)
	for _, c := range rootCmd.Commands() {
		if c.HasSubCommands() {
			reportUnknownCommands(c)
		}
	}

	return rootCmd
}

// annotationConfig set to "none" on a command says it reads no config.
const annotationConfig = "upterm/config"

// readsConfig is false for a command annotated upterm/config=none (version,
// upgrade), for cobra's help, completion and its subcommands, and
// __complete; true otherwise. Flags don't decide it (P7).
func readsConfig(cmd *cobra.Command) bool {
	if cmd.Annotations[annotationConfig] == "none" {
		return false
	}
	// cobra's commands, by their place: a child of the root, or under one.
	top := cmd
	for top.HasParent() && top.Parent().HasParent() {
		top = top.Parent()
	}
	if top.HasParent() {
		switch top.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd:
			return false
		}
	}
	return true
}

// logWarning says that the log file can't be opened, and logging is off.
// The root's pre-run opens the log, and so does each spawn of upterm host's
// daemon (B2), so it is said once, by whichever finds it first, and only by
// the parent: the daemon's stderr is that log, or the null device.
type logWarning struct {
	w    io.Writer
	once sync.Once
}

func (l *logWarning) warn(path string, err error) {
	if isDaemonProcess() {
		return
	}
	l.once.Do(func() {
		_, _ = fmt.Fprintf(l.w, "upterm: warning: can't open the log file %s: %v; logging is off\n", path, logOpenReason(path, err))
	})
}

// logWarningKey holds the run's *logWarning in the command's context.
type logWarningKey struct{}

// logWarningFor is the run's logWarning, which the root's pre-run put in
// ctx, or one of its own on stderr.
func logWarningFor(ctx context.Context) *logWarning {
	if l, ok := ctx.Value(logWarningKey{}).(*logWarning); ok {
		return l
	}
	return &logWarning{w: os.Stderr}
}

// logOpenReason is what the system said about opening path: the
// *fs.PathError under logging's or the spawn's wrapping, without the path
// when it is the log's own, which the warning names already.
func logOpenReason(path string, err error) error {
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		return err
	}
	if pe.Path == path {
		return pe.Err
	}
	return pe
}

// reportUnknownCommands makes the root or a group runnable (P6), only to
// answer what follows it: nothing prints the help, as cobra does for a
// command it can't run; anything else is unknownCommandError. Left to
// cobra, a typo under a group printed the group's help and exited 0, and an
// unknown command printed a block of suggestions.
func reportUnknownCommands(c *cobra.Command) {
	c.Args = cobra.ArbitraryArgs
	c.RunE = func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			return c.Help()
		}
		return unknownCommandError(c, args[0])
	}
}

// bindFlagsToEnv binds cmd's flags to the config file and environment
// variables, and reports which flags were supplied from any origin
// (command line, environment, or config file) in the returned map, and the
// per-run values it applied from env or config in deps (D8a). A CLI-only
// flag is never bound.
//
// Configuration priority (highest to lowest):
//  1. Command-line flags
//  2. Environment variables with UPTERM_ prefix
//  3. Config file (XDG_CONFIG_HOME/upterm/config.yaml)
//  4. Default values
//
// Examples:
//
//	--hide-client-ip flag -> UPTERM_HIDE_CLIENT_IP env var -> hide-client-ip in config.yaml
//	--read-only flag -> UPTERM_READ_ONLY env var -> read-only in config.yaml
//
// The returned error is fatal: a malformed config file, a config key with no
// known flag, a config key with no value, or a value that a flag rejects all
// abort the command rather than silently ignoring the problem. Callers
// should let every command fail this way except `upterm config ...`, which
// must stay reachable to repair the file (see isConfigCommand), and those
// that read no config (see readsConfig).
func bindFlagsToEnv(cmd *cobra.Command) (supplied map[string]bool, deps []deprecation, err error) {
	supplied = make(map[string]bool)

	// Seed from the command line first; the sync loop below never visits these.
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			supplied[flag.Name] = true
		}
	})

	v := viper.New()

	configPath := utils.UptermConfigFilePath()
	v.SetConfigFile(configPath)

	if err := v.ReadInConfig(); err != nil {
		// Only a confirmed "does not exist" is benign. Probing with os.Stat
		// instead would treat a permission error as absence — if a parent
		// directory is unreadable, both the read and the stat fail, ingestion
		// continues, and a config-only authorization restriction silently
		// disappears. viper returns the underlying *fs.PathError here, so
		// errors.Is separates the two cases exactly.
		if !errors.Is(err, fs.ErrNotExist) {
			return supplied, nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	}

	// Snapshot the config's keys BEFORE binding any flags. viper's AllKeys
	// merges v.pflags as well as v.config, so taking this after BindPFlag would
	// report every bound flag as present in the config file — and every
	// ordinary run would then fail with "config key has no value".
	configKeys := make(map[string]bool)
	for _, k := range v.AllKeys() {
		configKeys[k] = true
	}

	// A config key with no matching flag anywhere in the command tree is
	// rejected outright. This is the last silent-drop path in ingestion:
	// `authorized_user:` (wrong separator), `authorized-users:` (plural), or a
	// key nested under a parent mapping would otherwise never be looked at,
	// authorizationRequested() would report false, and the session would
	// accept any client with no error or warning. There is no logger to warn
	// with either — it is installed after PersistentPreRunE calls this
	// function — so this has to be an error.
	known := knownFlagNames(cmd)
	for k := range configKeys {
		if !known[k] {
			return supplied, nil, fmt.Errorf("unknown config key %q in %s; remove it or correct the spelling", k, configPath)
		}
	}

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" && !hasAnnotation(flag, annotationCLIOnly) {
			_ = v.BindPFlag(flag.Name, flag)
		}
	})

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.SetEnvPrefix("UPTERM")

	// applied records a value env or config gave flag, and for a per-run
	// flag, the values it still takes from them (D8a, release N).
	applied := func(flag *pflag.Flag, inConfig bool) {
		supplied[flag.Name] = true
		if hasAnnotation(flag, annotationPerRun) {
			deps = append(deps, perRunDeprecations(cmd, flag.Name, configPath, inConfig)...)
		}
	}

	var bindErr error
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if bindErr != nil || flag.Name == "help" || hasAnnotation(flag, annotationCLIOnly) {
			return
		}

		// Presence is recorded before any attempt to resolve a value, because
		// the two are different questions. viper reports IsSet false for
		// `authorized-user:` with no value and for UPTERM_AUTHORIZED_USER=''
		// (allowEmptyEnv defaults to false), and InConfig reports false for the
		// null case too. Only AllKeys and a direct LookupEnv see them. Treating
		// either as "absent" would drop a requested restriction and start an
		// unrestricted session.
		inConfig := configKeys[flag.Name]
		if inConfig || envSupplied(flag.Name) {
			supplied[flag.Name] = true
		}

		if flag.Changed {
			return
		}

		if !v.IsSet(flag.Name) {
			if inConfig {
				bindErr = fmt.Errorf("%s: config key has no value; give it one or remove it", flag.Name)
				return
			}
			// Set-but-empty in the environment, with nothing else supplying a
			// value: neither the CLI (Changed returned above) nor the config
			// file (viper would report the key set). viper cannot see an empty
			// variable, so the flag would keep its default — for a slice flag
			// that may be a real list, which is not what an explicitly empty
			// variable says. Resolve it to the empty list it names. Scalars
			// keep their default: there is no empty value a bool or a string
			// flag could sensibly take here.
			//
			// Six pflag.SliceValue flags reach here: private-key and the five
			// authUserSliceValue flags — authorized-user and the four legacy
			// *-user flags. The rule is a no-op wherever the default is already
			// empty, which today is every one of them but private-key; a future
			// slice flag with a non-empty default would inherit this behaviour
			// silently.
			if envSupplied(flag.Name) {
				if sv, ok := flag.Value.(pflag.SliceValue); ok {
					if err := sv.Replace(nil); err != nil {
						bindErr = bindSetError(flag.Name, "", envVarName(flag.Name), err)
					}
				}
			}
			return
		}

		val := v.Get(flag.Name)

		if sv, ok := flag.Value.(pflag.SliceValue); ok {
			elems, err := toStringSlice(flag.Name, val)
			if err != nil {
				bindErr = err
				return
			}
			if err := sv.Replace(elems); err != nil {
				bindErr = bindSetError(flag.Name, strings.Join(elems, ","), valueOrigin(flag.Name, configPath, inConfig), err)
				return
			}
			applied(flag, inConfig)
			return
		}

		scalar, err := toScalarString(flag.Name, val)
		if err != nil {
			bindErr = err
			return
		}

		if err := cmd.Flags().Set(flag.Name, scalar); err != nil {
			bindErr = bindSetError(flag.Name, scalar, valueOrigin(flag.Name, configPath, inConfig), err)
			return
		}
		applied(flag, inConfig)
	})

	return supplied, deps, bindErr
}

// envVarName returns the UPTERM_-prefixed environment variable name that
// corresponds to a flag name.
func envVarName(name string) string {
	return "UPTERM_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// envSupplied reports whether the UPTERM_ variable for name is set, even to an
// empty string. viper's getEnv treats an empty variable as unset unless
// allowEmptyEnv is enabled, which would silently drop a supplied-but-empty
// authorization source.
func envSupplied(name string) bool {
	_, ok := os.LookupEnv(envVarName(name))
	return ok
}

// valueOrigin names where flag.Name's value came from, for use in an error
// message. The environment variable is preferred when both happen to be set,
// because it also outranks the config file in actual precedence.
func valueOrigin(name, configPath string, inConfig bool) string {
	if envSupplied(name) {
		return envVarName(name)
	}
	if inConfig {
		return configPath
	}
	return "an unknown source"
}

// bindSetError reports a flag-set failure together with the origin of the
// value that caused it. Without this, a bad UPTERM_DEBUG=yes or config value
// reads as a bug in upterm rather than a bad input: pflag's own error (e.g.
// `invalid argument "yes" for "--debug" flag: ...`) never says where "yes"
// came from.
func bindSetError(name, display, origin string, err error) error {
	return fmt.Errorf("%s: cannot use value %q (from %s): %w", name, display, origin, err)
}

// knownFlagNames returns the union of flag names across the whole command
// tree rooted at cmd.Root(). bindFlagsToEnv is called with whichever
// subcommand is actually running, and a subcommand's own flags (e.g. host's
// --authorized-user, which is persistent on hostCmd rather than root) would
// otherwise be invisible when validating a config key from a sibling command
// such as `upterm version`.
//
// A CLI-only flag's name is known too: another command may bind it.
func knownFlagNames(cmd *cobra.Command) map[string]bool {
	names := make(map[string]bool)
	visitTreeFlags(cmd, func(f *pflag.Flag) { names[f.Name] = true })
	return names
}

// visitTreeFlags calls fn for each flag of each command in the tree rooted
// at cmd.Root().
func visitTreeFlags(cmd *cobra.Command, fn func(*pflag.Flag)) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(fn)
		c.PersistentFlags().VisitAll(fn)
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(cmd.Root())
}

// toStringSlice converts a config or environment value into flag elements.
//
// It deliberately avoids viper's GetStringSlice: that is cast.ToStringSlice,
// which routes a plain string through strings.Fields — splitting on whitespace
// rather than commas, so UPTERM_AUTHORIZED_USER=a,b would collapse into one
// element — and discards conversion errors, turning a YAML mapping into a
// silent nil.
func toStringSlice(name string, val any) ([]string, error) {
	switch v := val.(type) {
	case string:
		return splitCSV(name, v)
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for i, elem := range v {
			s, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected a string, got %T", name, i, elem)
			}
			if strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("%s[%d]: empty value", name, i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: expected a list or comma-separated string, got %T", name, val)
	}
}

// splitCSV parses the comma-separated form used on the command line and in
// environment variables, which have no other encoding available.
//
// It uses encoding/csv because that is what pflag's own string-slice parsing
// uses: a plain strings.Split would silently break values that are valid
// today, such as UPTERM_PRIVATE_KEY='"/tmp/key,one"'.
func splitCSV(name, s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}

	reader := csv.NewReader(strings.NewReader(s))
	parts, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("%s: cannot parse %q as a comma-separated list: %w", name, s, err)
	}

	// Read returns one record. Anything behind it — UPTERM_AUTHORIZED_USER set
	// to "github:alice\ngithub:bob", say — would otherwise be dropped in
	// silence, shortening an authorization list without a word.
	if _, err := reader.Read(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: cannot parse %q as a comma-separated list: unexpected newline; separate values with commas", name, s)
	}

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%s: empty element in %q", name, s)
		}
		out = append(out, part)
	}
	return out, nil
}

// isConfigCommand reports whether cmd is `upterm config` or one of its
// subcommands. Those must stay reachable when the config file is malformed:
// they are the tools for repairing it.
func isConfigCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "config" {
			return true
		}
	}
	return false
}

// toScalarString converts a config or environment value for a non-slice
// flag. It rejects the collection types rather than letting fmt.Sprintf
// render them: fmt.Sprintf("%v", []any{"/bin/bash","-l"}) yields
// "[/bin/bash -l]", which pflag's stringValue accepts without error and
// shlex then splits into "[/bin/bash" — a silently broken force command.
func toScalarString(name string, val any) (string, error) {
	switch v := val.(type) {
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case string:
		return v, nil
	case []any, []string, map[string]any:
		return "", fmt.Errorf("%s: expected a single value, got %T%s", name, v, scalarHint(name, v))
	default:
		// For all other scalar types (int, float, etc.), use fmt.Sprintf.
		return fmt.Sprintf("%v", v), nil
	}
}

// scalarHint names the fix for a collection supplied where a scalar belongs.
// `force-command: ["/bin/bash", "-l"]` was this repo's own documented form, so
// the error has to say what to write instead and not merely what is wrong. The
// suggestion is built from the value itself rather than hardcoded, so it is
// never a suggestion for a different flag.
func scalarHint(name string, val any) string {
	const hint = "; write it as a single string"

	var parts []string
	switch v := val.(type) {
	case []any:
		for _, elem := range v {
			parts = append(parts, fmt.Sprint(elem))
		}
	case []string:
		parts = v
	}
	if len(parts) == 0 {
		return hint
	}

	return fmt.Sprintf("%s, e.g. %s: %q", hint, name, strings.Join(parts, " "))
}
