package command

import (
	"os"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Instant Terminal Sharing",
		Long:  "Upterm is an open-source solution for sharing terminal sessions instantly over secure SSH tunnels to the public internet.",
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
  $ ssh TOKEN@uptermd.upterm.dev`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
