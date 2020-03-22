package command

import (
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Secure Terminal Sharing",
		Long:  "Upterm is an open-source solution for sharing terminal sessions instantly with the public internet over secure tunnels.",
		Example: `  # Host a terminal session that runs $SHELL with
  # client's input/output attaching to the host's
  $ upterm host

  # Display the ssh connection string and share it with
  # the client(s)
  $ upterm session current
  === SESSION_ID
  Command:                /bin/bash
  Force Command:          n/a
  Host:                   ssh://uptermd.upterm.dev:22
  SSH Session:            ssh TOKEN@uptermd.upterm.dev

  # A client connects to the host session with ssh
  $ ssh TOKEN@uptermd.upterm.dev`,
	}

	rootCmd.AddCommand(hostCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}
