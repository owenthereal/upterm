package command

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jingweno/upterm/host"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagAdminSocket string
)

func Session() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Show current session info",
		Example: `  # Share a session by running $SHELL. Client's input & output are attached to the host's.
  upterm share
  # Share a session by running 'bash'. Client's input & output are attached to the host's.
  upterm share bash
  # Share a session by running 'tmux new pair'. Client runs 'tmux attach -t pair' to attach to the session.
  upterm share -t 'tmux attach -t pair' -- tmux new -t pair`,
		PreRunE: validateSessionRequiredFlags,
		RunE:    sessionRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagAdminSocket, "socket", "", os.Getenv(upterm.HostAdminSocketEnvVar), "admin unix domain socket")

	return cmd
}

func validateSessionRequiredFlags(c *cobra.Command, args []string) error {
	missingFlagNames := []string{}
	if flagAdminSocket == "" {
		missingFlagNames = append(missingFlagNames, "socket")
	}

	if len(missingFlagNames) > 0 {
		return fmt.Errorf(`required flag(s) "%s" not set`, strings.Join(missingFlagNames, ", "))
	}

	return nil
}

func sessionRunE(c *cobra.Command, args []string) error {
	client := host.AdminClient(flagAdminSocket)
	resp, err := client.GetSession(nil)
	if err != nil {
		return err
	}

	session := resp.GetPayload()
	user, err := api.EncodeIdentifierSession(session)
	if err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(session.Host)
	if err != nil {
		return err
	}

	// Format: ssh session:host-addr@host
	cmd := fmt.Sprintf("ssh session: ssh -o ServerAliveInterval=30 %s@%s", user, host)
	if port != "22" {
		cmd = fmt.Sprintf("%s -p %s", cmd, port)
	}
	log.Info(cmd)

	return nil
}
