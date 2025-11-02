package command

import (
	"fmt"
	"os"
	"strings"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

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
			if err := bindFlagsToEnv(cmd); err != nil {
				return err
			}

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
func bindFlagsToEnv(cmd *cobra.Command) error {
	v := viper.New()

	// Configure config file
	configPath := utils.UptermConfigFilePath()
	v.SetConfigFile(configPath)

	// Try to read config file (silent fail if not exists, but warn on parse errors)
	if err := v.ReadInConfig(); err != nil {
		// Only warn if the file exists but can't be parsed
		if _, statErr := os.Stat(configPath); statErr == nil {
			// File exists but couldn't be read - log warning if we have logger
			if logger := uptermctx.Logger(cmd.Context()); logger != nil {
				logger.Warn("Failed to read config file", "path", configPath, "error", err)
			}
		}
		// Otherwise silently continue - config file is optional
	}

	// Visit all flags and bind them to viper
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" {
			// Ignore binding errors - not all flags support environment variable binding
			_ = v.BindPFlag(flag.Name, flag)
		}
	})

	// Enable automatic environment variable reading
	v.AutomaticEnv()
	// Replace hyphens with underscores for env var names (--hide-client-ip -> HIDE_CLIENT_IP)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	// Set prefix so all env vars start with UPTERM_ (UPTERM_HIDE_CLIENT_IP)
	v.SetEnvPrefix("UPTERM")

	// Sync viper values back to flags
	// Priority: flags (if changed) > env vars > config file > defaults
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" && !flag.Changed && v.IsSet(flag.Name) {
			val := v.Get(flag.Name)
			// Ignore setting errors - not all flag types can be set from strings
			_ = cmd.Flags().Set(flag.Name, toString(val))
		}
	})

	return nil
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
