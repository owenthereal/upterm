package command

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

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

  # Display the SSH connection string for sharing with client(s):
  $ upterm session current
  === SESSION_ID
  Command:                /bin/bash
  Force Command:          n/a
  Host:                   ssh://uptermd.upterm.dev:22
  SSH Session:            ssh TOKEN@uptermd.upterm.dev

  # A client connects to the host session via SSH:
  $ ssh TOKEN@uptermd.upterm.dev

  # Set flags via environment variables:
  $ UPTERM_HIDE_CLIENT_IP=true upterm host`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind all flags to environment variables with UPTERM_ prefix
			supplied, err := bindFlagsToEnv(cmd)
			if err != nil && !isConfigCommand(cmd) {
				return err
			}
			suppliedFlags = supplied

			debug, _ := cmd.Flags().GetBool("debug")

			logOptions := []logging.Option{logging.File(utils.UptermLogFilePath())}
			if debug {
				logOptions = append(logOptions, logging.Debug())
			}

			logger, err := logging.New(logOptions...)
			if err != nil {
				return err
			}

			cmd.SetContext(uptermctx.WithLogger(cmd.Context(), logger))

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

	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(upgradeCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}

// bindFlagsToEnv binds all command flags to config file and environment variables.
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
func bindFlagsToEnv(cmd *cobra.Command) (map[string]bool, error) {
	supplied := make(map[string]bool)

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
			return supplied, fmt.Errorf("failed to read config file %s: %w", configPath, err)
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

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" {
			_ = v.BindPFlag(flag.Name, flag)
		}
	})

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.SetEnvPrefix("UPTERM")

	var bindErr error
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if bindErr != nil || flag.Name == "help" {
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
				bindErr = fmt.Errorf("failed to set %s: %w", flag.Name, err)
				return
			}
			supplied[flag.Name] = true
			return
		}

		if err := cmd.Flags().Set(flag.Name, toString(val)); err != nil {
			bindErr = fmt.Errorf("failed to set %s: %w", flag.Name, err)
			return
		}
		supplied[flag.Name] = true
	})

	return supplied, bindErr
}

// envSupplied reports whether the UPTERM_ variable for name is set, even to an
// empty string. viper's getEnv treats an empty variable as unset unless
// allowEmptyEnv is enabled, which would silently drop a supplied-but-empty
// authorization source.
func envSupplied(name string) bool {
	key := "UPTERM_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	_, ok := os.LookupEnv(key)
	return ok
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

	parts, err := csv.NewReader(strings.NewReader(s)).Read()
	if err != nil {
		return nil, fmt.Errorf("%s: cannot parse %q as a comma-separated list: %w", name, s, err)
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

// toString converts a value to string for flag setting.
// Handles bool and string slice types specially, uses fmt.Sprintf for others.
func toString(val any) string {
	switch v := val.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	case []string:
		// For string slice flags (e.g., --private-key), join with commas
		return strings.Join(v, ",")
	default:
		// For all other types (int, float, etc.), use fmt.Sprintf
		return fmt.Sprintf("%v", v)
	}
}
