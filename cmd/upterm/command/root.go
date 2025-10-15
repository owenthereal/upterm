package command

import (
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

			logPath, err := utils.UptermLogFilePath()
			if err != nil {
				return err
			}

			logOptions := []logging.Option{logging.File(logPath)}
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

	rootCmd.PersistentFlags().Bool("debug", os.Getenv("DEBUG") != "", "enable debug logging")

	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(upgradeCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}

// bindFlagsToEnv binds all command flags to environment variables with UPTERM_ prefix.
// This allows any flag to be set via environment variable, e.g.:
//   --hide-client-ip flag -> UPTERM_HIDE_CLIENT_IP env var
//   --read-only flag -> UPTERM_READ_ONLY env var
func bindFlagsToEnv(cmd *cobra.Command) error {
	v := viper.New()

	// Visit all flags and bind them to viper
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" {
			if err := v.BindPFlag(flag.Name, flag); err != nil {
				// Log but don't fail - this is for convenience
				return
			}
		}
	})

	// Enable automatic environment variable reading
	v.AutomaticEnv()
	// Replace hyphens with underscores for env var names (--hide-client-ip -> HIDE_CLIENT_IP)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	// Set prefix so all env vars start with UPTERM_ (UPTERM_HIDE_CLIENT_IP)
	v.SetEnvPrefix("UPTERM")

	// Sync viper values back to flags
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" && !flag.Changed && v.IsSet(flag.Name) {
			val := v.Get(flag.Name)
			if err := cmd.Flags().Set(flag.Name, toString(val)); err != nil {
				// Log but don't fail
				return
			}
		}
	})

	return nil
}

// toString converts a value to string for flag setting
func toString(val interface{}) string {
	switch v := val.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	default:
		return ""
	}
}
