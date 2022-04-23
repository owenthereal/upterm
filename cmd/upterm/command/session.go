package command

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
)

var (
	flagAdminSocket string
)

func sessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "session",
		Aliases: []string{"se"},
		Short:   "Display session",
	}
	cmd.AddCommand(current())
	cmd.AddCommand(list())
	cmd.AddCommand(show())

	return cmd
}

func list() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "l"},
		Short:   "List shared sessions",
		Long:    `List shared sessions. Session admin sockets are located in ~/.upterm.`,
		Example: `  # List shared sessions
  upterm session list`,
		RunE: listRunE,
	}

	return cmd
}

func show() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info",
		Aliases: []string{"i"},
		Short:   "Display session by name",
		Long:    `Display session by name.`,
		Example: `  # Display session by name
  upterm session info NAME`,
		RunE: infoRunE,
	}

	return cmd
}

func current() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "current",
		Aliases: []string{"c"},
		Short:   "Display the current session",
		Long:    `Display the current session. By default, the command fetches the current session from the admin socket path defined in the UPTERM_ADMIN_SOCKET environment variable. The UPTERM_ADMIN_SOCKET environment variable is set after a session is shared with 'upterm host'.`,
		Example: `  # Display the current session defined in $UPTERM_ADMIN_SOCKET
  upterm session current
  # Display the current session with a custom path
  upterm session current --admin-socket ADMIN_SOCKET_PATH`,
		PreRunE: validateCurrentRequiredFlags,
		RunE:    currentRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagAdminSocket, "admin-socket", "", currentAdminSocketFile(), "admin unix domain socket (required)")

	return cmd
}

func listRunE(c *cobra.Command, args []string) error {
	uptermDir, err := utils.CreateUptermDir()
	if err != nil {
		return err
	}

	sessions, err := listSessions(uptermDir)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		fmt.Println("No session is found. Create one with `upterm host`.")
		return nil
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Current", "Session", "Command", "Force Command", "Host"})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetCenterSeparator("|")
	table.AppendBulk(sessions)

	table.Render()
	return nil
}

func infoRunE(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing session name")
	}

	uptermDir, err := utils.UptermDir()
	if err != nil {
		return err
	}

	return displaySessionFromAdminSocketPath(filepath.Join(uptermDir, host.AdminSocketFile(args[0])))
}

func currentRunE(c *cobra.Command, args []string) error {
	return displaySessionFromAdminSocketPath(flagAdminSocket)
}

func listSessions(dir string) ([][]string, error) {
	result := make([][]string, 0)

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	currentAdminSocket := currentAdminSocketFile()
	for _, file := range files {
		// continue if the file is not SESSION.sock
		if filepath.Ext(file.Name()) != host.AdminSockExt {
			continue
		}

		adminSocket := filepath.Join(dir, file.Name())
		session, err := session(adminSocket)
		if err != nil {
			continue
		}

		var current string
		if adminSocket == currentAdminSocket {
			current = "*"
		}

		result = append(
			result,
			[]string{
				current,
				session.SessionId,
				strings.Join(session.Command, " "),
				naIfEmpty(strings.Join(session.ForceCommand, " ")),
				session.Host,
			})
	}

	return result, nil
}

func displaySessionFromAdminSocketPath(path string) error {
	session, err := session(path)
	if err != nil {
		return err
	}

	return displaySession(session)
}

func parseURL(str string) (u *url.URL, scheme string, host string, port string, err error) {
	u, err = url.Parse(str)
	if err != nil {
		return
	}

	scheme = u.Scheme
	host, port, err = net.SplitHostPort(u.Host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return
		}

		err = nil
		host = u.Host
		switch u.Scheme {
		case "ssh":
			port = "22"
		case "ws":
			port = "80"
		case "wss":
			port = "443"
		}
	}

	return
}

func displaySession(session *api.GetSessionResponse) error {
	user := session.SessionId

	u, scheme, host, port, err := parseURL(session.Host)
	if err != nil {
		return err
	}

	var hostPort string
	if port == "" || port == "80" || port == "443" {
		hostPort = host
	} else {
		hostPort = host + ":" + port
	}

	var sshCmd string
	if scheme == "ssh" {
		sshCmd = fmt.Sprintf("ssh %s@%s", user, host)
		if port != "22" {
			sshCmd = fmt.Sprintf("%s -p %s", sshCmd, port)
		}
	} else {
		sshCmd = fmt.Sprintf("ssh -o ProxyCommand='upterm proxy %s://%s:nopass@%s' %s@%s", scheme, user, hostPort, user, host+":"+port)
	}

	data := [][]string{
		{"Command:", strings.Join(session.Command, " ")},
		{"Force Command:", naIfEmpty(strings.Join(session.ForceCommand, " "))},
		{"Host:", u.Scheme + "://" + hostPort},
		{"SSH Session:", sshCmd},
	}

	isFirst := true
	for _, c := range session.ConnectedClients {
		var header string
		if isFirst {
			header = "Connected Client(s):"
			isFirst = false
		}
		data = append(data, []string{header, clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint)})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"=== " + session.SessionId})
	table.SetHeaderLine(false)
	table.SetAutoWrapText(false)
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("")
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data)
	table.Render()

	return nil
}

func clientDesc(addr, clientVer, fingerprint string) string {
	return fmt.Sprintf("%s %s %s", addr, clientVer, fingerprint)
}

func currentAdminSocketFile() string {
	return os.Getenv(upterm.HostAdminSocketEnvVar)
}

func session(adminSocket string) (*api.GetSessionResponse, error) {
	c, err := host.AdminClient(adminSocket)
	if err != nil {
		return nil, err
	}

	return c.GetSession(context.Background(), &api.GetSessionRequest{})
}

func validateCurrentRequiredFlags(c *cobra.Command, args []string) error {
	missingFlagNames := []string{}
	if flagAdminSocket == "" {
		missingFlagNames = append(missingFlagNames, "admin-socket")
	}

	if len(missingFlagNames) > 0 {
		return fmt.Errorf(`required flag(s) "%s" not set`, strings.Join(missingFlagNames, ", "))
	}

	return nil
}

func naIfEmpty(s string) string {
	if s == "" {
		return "n/a"
	}

	return s
}
