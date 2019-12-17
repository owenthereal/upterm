package command

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/jingweno/upterm/host"
	"github.com/jingweno/upterm/host/api/swagger/client"
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

	cmd.PersistentFlags().StringVarP(&flagAdminSocket, "socket", "", os.Getenv(host.UptermAdminSocketEnvVar), "admin unix domain socket")

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
	cfg := client.DefaultTransportConfig()
	t := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	t.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", flagAdminSocket)
		},
	}

	client := client.New(t, nil)
	resp, err := client.AdminService.GetSession(nil)
	if err != nil {
		return err
	}

	session := resp.GetPayload()

	host, port, err := net.SplitHostPort(session.Host)
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("ssh session: ssh -o ServerAliveInterval=30 %s@%s", session.SessionID, host)
	if port != "22" {
		cmd = fmt.Sprintf("%s -p %s", cmd, port)
	}
	log.Info(cmd)

	return nil
}
