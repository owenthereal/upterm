package command

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
)

var (
	flagAdminSocket string
	flagOutput      string
)

// sessionTemplateData holds data for template output
type sessionTemplateData struct {
	SessionID    string `json:"sessionId"`
	ClientCount  int    `json:"clientCount"`
	Host         string `json:"host"`
	Command      string `json:"command"`
	ForceCommand string `json:"forceCommand"`
}

func sessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "session",
		Aliases: []string{"se"},
		Short:   "Display and manage terminal sessions",
	}
	cmd.AddCommand(current())
	cmd.AddCommand(list())
	cmd.AddCommand(show())

	return cmd
}

func list() *cobra.Command {
	runtimeDir := utils.UptermRuntimeDir()
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "l"},
		Short:   "List shared sessions",
		Long: fmt.Sprintf(`List shared sessions.

Sockets are stored in: %s

Follows the XDG Base Directory Specification with fallback to $HOME/.upterm
in constrained environments where XDG directories are unavailable.`, runtimeDir),
		Example: `  # List shared sessions:
  upterm session list`,
		RunE: listRunE,
	}

	return cmd
}

func show() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info",
		Aliases: []string{"i"},
		Short:   "Display terminal session by name",
		Long:    `Display terminal session by name.`,
		Example: `  # Display session by name:
  upterm session info NAME`,
		RunE: infoRunE,
	}

	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")

	return cmd
}

func current() *cobra.Command {
	runtimeDir := utils.UptermRuntimeDir()
	cmd := &cobra.Command{
		Use:     "current",
		Aliases: []string{"c"},
		Short:   "Display the current terminal session",
		Long: fmt.Sprintf(`Display the current terminal session.

By default, reads the admin socket path from $UPTERM_ADMIN_SOCKET (automatically set
when you run 'upterm host').

Sockets are stored in: %s

Follows the XDG Base Directory Specification with fallback to $HOME/.upterm
in constrained environments where XDG directories are unavailable.

Output formats:
  -o json                           JSON output
  -o go-template='{{.ClientCount}}' Custom Go template

Template variables: SessionID, ClientCount, Host, Command, ForceCommand`, runtimeDir),
		Example: `  # Display the active session as defined in $UPTERM_ADMIN_SOCKET:
  upterm session current

  # Output as JSON:
  upterm session current -o json

  # Custom format for shell prompt (outputs nothing if not in session):
  upterm session current -o go-template='🆙 {{.ClientCount}} '

  # For terminal title:
  upterm session current -o go-template='upterm: {{.ClientCount}} clients | {{.SessionID}}'`,
		PreRunE: validateCurrentRequiredFlags,
		RunE:    currentRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagAdminSocket, "admin-socket", "", currentAdminSocketFile(), "Admin socket path (required).")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: json or go-template='...'")
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")

	return cmd
}

func listRunE(c *cobra.Command, args []string) error {
	sessions, err := listSessions(c.Context(), utils.UptermRuntimeDir())
	if err != nil {
		return err
	}

	model := tui.NewSessionListModel(sessions)
	_, err = tui.RunModel(model)
	return err
}

// fetchSessionDetail returns session details for an admin socket
func fetchSessionDetail(ctx context.Context, adminSocket string) (tui.SessionDetail, error) {
	sess, err := session(ctx, adminSocket)
	if err != nil {
		return tui.SessionDetail{}, err
	}
	return buildSessionDetail(sess)
}

func infoRunE(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing session name")
	}

	adminSocket := filepath.Join(utils.UptermRuntimeDir(), host.AdminSocketFile(args[0]))
	detail, err := fetchSessionDetail(c.Context(), adminSocket)
	if err != nil {
		return err
	}

	tui.PrintSessionDetail(detail, false) // no hint for session info
	return nil
}

func currentRunE(c *cobra.Command, args []string) error {
	// If output format specified, use special handling (non-interactive)
	if flagOutput != "" {
		return outputSession(c.Context(), flagAdminSocket, flagOutput)
	}

	detail, err := fetchSessionDetail(c.Context(), flagAdminSocket)
	if err != nil {
		return err
	}

	tui.PrintSessionDetail(detail, true) // show hint for session current
	return nil
}

// outputSession handles -o/--output flag for session current
func outputSession(ctx context.Context, adminSocket, format string) error {
	// Error if not in upterm session (no admin socket)
	if adminSocket == "" {
		return fmt.Errorf("not in upterm session (UPTERM_ADMIN_SOCKET not set)")
	}

	// Validate format
	if format != "json" && !strings.HasPrefix(format, "go-template=") {
		return fmt.Errorf("invalid output format %q: must be 'json' or 'go-template=<template>'", format)
	}

	// Try to get session
	sess, err := session(ctx, adminSocket)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Build template data
	data := sessionTemplateData{
		SessionID:    sess.SessionId,
		ClientCount:  len(sess.ConnectedClients),
		Host:         sess.Host,
		Command:      strings.Join(sess.Command, " "),
		ForceCommand: strings.Join(sess.ForceCommand, " "),
	}

	// Handle json output
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	// Handle go-template output
	tmplStr := strings.TrimPrefix(format, "go-template=")
	// Remove surrounding quotes if present
	tmplStr = strings.Trim(tmplStr, "'\"")

	tmpl, err := template.New("session").Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	return tmpl.Execute(os.Stdout, data)
}

func listSessions(ctx context.Context, dir string) ([]tui.SessionDetail, error) {
	var result []tui.SessionDetail

	files, err := os.ReadDir(dir)
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
		sess, err := session(ctx, adminSocket)
		if err != nil {
			continue
		}

		detail, err := buildSessionDetail(sess)
		if err != nil {
			continue
		}

		detail.IsCurrent = adminSocket == currentAdminSocket
		detail.AdminSocket = adminSocket
		result = append(result, detail)
	}

	return result, nil
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

// buildSessionDetail returns session detail for TUI display
func buildSessionDetail(sess *api.GetSessionResponse) (tui.SessionDetail, error) {
	user := sess.SshUser
	if user == "" {
		// Fallback to encoding for backward compatibility with older servers
		user = routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sess.SessionId, sess.NodeAddr)
	}

	u, scheme, host, port, err := parseURL(sess.Host)
	if err != nil {
		return tui.SessionDetail{}, err
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
		sshCmd = fmt.Sprintf("ssh -o ProxyCommand='upterm proxy %s://%s@%s' %s@%s", scheme, user, hostPort, user, host+":"+port)
	}

	var clients []string
	for _, c := range sess.ConnectedClients {
		clients = append(clients, clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint))
	}

	// Build SCP commands if SFTP is enabled and using direct SSH
	// Uses standard OpenSSH path syntax: relative paths from home, or absolute paths
	var scpDownload, scpUpload string
	sftpEnabled := !sess.SftpDisabled && scheme == "ssh"
	if sftpEnabled {
		// Show standard SCP syntax: <remote> is relative to home or an absolute path
		if port != "" && port != "22" {
			scpDownload = fmt.Sprintf("scp -P %s %s@%s:<remote> <local>", port, user, host)
			scpUpload = fmt.Sprintf("scp -P %s <local> %s@%s:<remote>", port, user, host)
		} else {
			scpDownload = fmt.Sprintf("scp %s@%s:<remote> <local>", user, host)
			scpUpload = fmt.Sprintf("scp <local> %s@%s:<remote>", user, host)
		}
	}

	return tui.SessionDetail{
		SessionID:        sess.SessionId,
		Command:          strings.Join(sess.Command, " "),
		ForceCommand:     strings.Join(sess.ForceCommand, " "),
		Host:             u.Scheme + "://" + hostPort,
		SSHCommand:       sshCmd,
		SFTPEnabled:      sftpEnabled,
		SCPDownload:      scpDownload,
		SCPUpload:        scpUpload,
		AuthorizedKeys:   displayAuthorizedKeys(sess.AuthorizedKeys),
		ConnectedClients: clients,
	}, nil
}

func clientDesc(addr, clientVer, fingerprint string) string {
	if shouldHideClientIP() {
		addr = "[redacted]"
	}
	return fmt.Sprintf("%s %s %s", addr, clientVer, fingerprint)
}

func currentAdminSocketFile() string {
	return os.Getenv(upterm.HostAdminSocketEnvVar)
}

func session(ctx context.Context, adminSocket string) (*api.GetSessionResponse, error) {
	c, err := host.AdminClient(adminSocket)
	if err != nil {
		return nil, err
	}

	return c.GetSession(ctx, &api.GetSessionRequest{})
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

func displayAuthorizedKeys(keys []*api.AuthorizedKey) string {
	var aks []string
	for _, ak := range keys {
		if len(ak.PublicKeyFingerprints) == 0 {
			aks = append(aks, fmt.Sprintf("[!] %s (no SSH keys configured)", ak.Comment))
		} else {
			var fps []string
			for _, fp := range ak.PublicKeyFingerprints {
				fps = append(fps, fmt.Sprintf("- %s", fp))
			}
			aks = append(aks, fmt.Sprintf("%s:\n%s", ak.Comment, strings.Join(fps, "\n")))
		}
	}

	return strings.Join(aks, "\n")
}
