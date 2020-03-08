package command

import (
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Secure Terminal Sharing",
		Long:  "Upterm is an open-source solution for sharing terminal sessions instantly with the public internet over secure tunnels.",
		Example: `  # Host a terminal session by running $SHELL
  # The client's input/output is attached to the host's
  $ upterm host

  # Display the ssh connection string
  $ upterm session current
  === BO6NOSSTP9LL08DOQ0RG
  Command:                /bin/bash
  Force Command:          n/a
  Host:                   uptermd.upterm.dev:22
  SSH Session:            ssh bo6nosstp9ll08doq0rg:MTAuMC4xNzAuMTY0OjIy@uptermd.upterm.dev

  # Open a new terminal and connect to the session
  $ ssh bo6nosstp9ll08doq0rg:MTAuMC4xNzAuMTY0OjIy@uptermd.upterm.dev`,
	}

	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}
