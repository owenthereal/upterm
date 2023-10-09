package command

import (
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
	}

	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(upgradeCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}
