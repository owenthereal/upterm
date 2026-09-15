package command

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
)

var (
	flagAdminSocket string
	flagOutput      string
)

// sessionQueryTimeout bounds every wait a read-only session command makes on
// something another process owns: a registry lock, or an answer from an admin
// socket.
//
// Cobra's Execute leaves the command context as context.Background(), so
// without this these commands have no deadline at all — and both things they
// wait on can be held indefinitely by a process that is stopped rather than
// slow, which no amount of patience resolves. Ten seconds is far longer than
// either takes when the owner is alive, and short enough that a person waiting
// on `session list` gets an answer instead of a hang.
const sessionQueryTimeout = 10 * time.Second

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
in constrained environments where XDG directories are unavailable.`, sessiondir.SessionsRoot(runtimeDir)),
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
		Long: `Display terminal session by name.

A session that has ended still answers, from the record it left behind: its
admin socket died with its process, but its outcome did not.

Output formats:
  -o json                           JSON output`,
		Example: `  # Display session by name:
  upterm session info NAME

  # Output as JSON:
  upterm session info NAME -o json`,
		RunE: infoRunE,
	}

	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: json")
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

Template variables: SessionID, ClientCount, Host, Command, ForceCommand`, sessiondir.SessionsRoot(runtimeDir)),
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

// reapSessions removes the runtime directories of sessions whose owner is
// gone. A crash leaves a directory and a free lock behind, and nothing else
// ever cleans it up: without this, `Reap` exists but is never called, and a
// name stays taken until the next Claim happens to recover it.
//
// `list` is where it belongs because it is the one command that already walks
// every name, and a name with no process behind it should not be in the list
// it prints.
//
// It never fails the listing. A reap that cannot take the registry lock is a
// tidiness failure; refusing to show a user their sessions over it would be a
// worse answer than showing one stale entry.
func reapSessions(ctx context.Context) {
	if err := sessiondir.Reap(ctx, utils.UptermRuntimeDir()); err != nil {
		if logger := uptermctx.Logger(ctx); logger != nil {
			logger.Debug("failed to reap stale session directories", "error", err)
		}
	}
}

// pruneRecords drops the records of sessions that ended long enough ago that
// nobody is still asking how they went. Nothing sweeps in the background, so
// without a call from here every record a session ever wrote stays forever.
//
// `list` is where it belongs for the same reason the reap is: it is the one
// command a person runs to see the state of things, and it already pays to
// walk the directory.
//
// It never fails the listing, again for the same reason.
func pruneRecords(ctx context.Context) {
	if err := sessiondir.Prune(ctx, utils.UptermStateDir(), sessiondir.RecordRetention); err != nil {
		if logger := uptermctx.Logger(ctx); logger != nil {
			logger.Debug("failed to prune expired session records", "error", err)
		}
	}
}

// tidySessions clears away what dead sessions left behind, before a listing
// shows it to anyone.
//
// Bounded, because both halves wait on a registry lock whose holder may be a
// process that is stopped rather than slow. Tidying is not what the user asked
// for: a list with one stale entry in it is a better answer than a list that
// never arrives.
func tidySessions(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	reapSessions(ctx)
	pruneRecords(ctx)
}

func listRunE(c *cobra.Command, args []string) error {
	tidySessions(c.Context())

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

// sessionInfo is the single shape `session info -o json` returns, live or not.
// A caller must not have to parse two formats depending on whether it happened
// to ask while the process was still running.
type sessionInfo struct {
	Name             string   `json:"name"`
	LaunchID         string   `json:"launchId,omitempty"`
	Status           string   `json:"status"`
	SessionID        string   `json:"sessionId,omitempty"`
	Command          string   `json:"command,omitempty"`
	ForceCommand     string   `json:"forceCommand,omitempty"`
	SSHCommand       string   `json:"sshCommand,omitempty"`
	ClientCount      int      `json:"clientCount"`
	ConnectedClients []string `json:"connectedClients,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	ExitCode         *int     `json:"exitCode,omitempty"`
	Signal           string   `json:"signal,omitempty"`
}

// statusEnded is the reader's inference, not a status any session writes:
// sessiondir records what a session published, and "ended" is what a free lock
// means regardless of what the record still says.
const statusEnded = "ended"

// lookup resolves a session by name.
//
// Record and ownership come from one Inspect call, under the registry lock. An
// earlier draft read them separately, which could mix generations — A's record
// with B's ownership — and, more immediately, could dereference a nil record:
// ReadRecord returns not-found, a claim completes, IsHeld returns true.
//
// The response is the one this lookup validated, and is nil unless the admin
// socket answered and its session ID matched the record. Handing it back is
// what stops a caller that wants the full live detail from asking again: a
// second query returns whatever holds the name at that instant, which need
// not be the session the first one confirmed.
func lookup(ctx context.Context, name string) (sessionInfo, *api.GetSessionResponse, error) {
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermRuntimeDir(), utils.UptermStateDir(), name)
	if err != nil {
		return sessionInfo{}, nil, err
	}

	if rec == nil {
		// No record at all, held or not: not found within retained history.
		// Checked before either branch uses rec, which is the nil dereference
		// the earlier draft had.
		return sessionInfo{}, nil, fmt.Errorf("no session named %q", name)
	}

	if !held {
		// Nobody owns the name. Whatever the record says about status — and
		// after a SIGKILL it frequently says "ready" — this session is over.
		// Only its outcome is still meaningful.
		return infoFromRecord(rec, statusEnded), nil, nil
	}

	// Held: the recorded status is current and refines liveness — starting,
	// ready or disconnected.
	info := infoFromRecord(rec, rec.Status)

	// A record with no session ID has not reached ready, so there is nothing
	// for the admin socket to confirm and nothing to compare against. Skip it
	// rather than issue a query whose generation check could not succeed.
	if rec.SessionID == "" {
		return info, nil, nil
	}

	adminSocket, err := sessiondir.AdminSocketPath(utils.UptermRuntimeDir(), name)
	if err != nil {
		return sessionInfo{}, nil, err
	}

	// Live detail is a second observation, taken outside the lock, so it is
	// validated rather than merged on faith: between Inspect and this call the
	// session could have ended and a replacement claimed the name. The session
	// ID is the generation marker.
	sess, err := session(ctx, adminSocket)
	if err != nil || sess.SessionId != rec.SessionID {
		return info, nil, nil
	}
	return withLiveDetail(info, sess), sess, nil
}

// infoFromRecord reports what the record knows, under the status the caller
// has decided on.
func infoFromRecord(rec *sessiondir.Record, status string) sessionInfo {
	return sessionInfo{
		Name:         rec.Name,
		LaunchID:     rec.LaunchID,
		Status:       status,
		SessionID:    rec.SessionID,
		Command:      strings.Join(rec.Command, " "),
		ForceCommand: strings.Join(rec.ForceCommand, " "),
		Reason:       rec.Reason,
		ExitCode:     rec.ExitCode,
		Signal:       rec.Signal,
	}
}

// withLiveDetail adds what only a running session can answer: who is connected
// and how to join them.
func withLiveDetail(info sessionInfo, sess *api.GetSessionResponse) sessionInfo {
	detail, err := buildSessionDetail(sess)
	if err != nil {
		// The record's own view stands. A host URL we cannot parse is a reason
		// to report less, not to fail a lookup that already has an answer.
		return info
	}

	info.Command = detail.Command
	info.ForceCommand = detail.ForceCommand
	info.SSHCommand = detail.SSHCommand
	info.ConnectedClients = detail.ConnectedClients
	info.ClientCount = len(detail.ConnectedClients)
	return info
}

func infoRunE(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing session name")
	}
	name := args[0]

	// One deadline for the whole lookup, which waits on the registry and then
	// on the admin socket: budgeting them separately would let a name that is
	// slow twice take twice as long.
	ctx, cancel := context.WithTimeout(c.Context(), sessionQueryTimeout)
	defer cancel()

	info, live, err := lookup(ctx, name)
	if err != nil {
		return err
	}

	if flagOutput != "" {
		if flagOutput != "json" {
			return fmt.Errorf("invalid output format %q: must be 'json'", flagOutput)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	// The full detail is worth printing over the summary, because the socket
	// answered with more than the record holds: the host URL, the authorized
	// keys, the SFTP commands. It is built from the response the lookup
	// validated rather than from a fresh query, so what gets printed is the
	// session that was asked about even if another one has since taken the
	// name.
	if live != nil {
		adminSocket, err := sessiondir.AdminSocketPath(utils.UptermRuntimeDir(), name)
		if err != nil {
			return err
		}
		if detail, err := buildSessionDetail(live); err == nil {
			detail.Name = name
			detail.AdminSocket = adminSocket
			tui.PrintSessionDetail(detail)
			return nil
		}
	}

	printSessionSummary(info)
	return nil
}

// printSessionSummary prints what the record knows, for a session whose admin
// socket is gone. Answering only while the process is alive would make
// `session info` useless for the question people ask it afterwards, which is
// how the thing ended.
func printSessionSummary(info sessionInfo) {
	fmt.Printf("Name:      %s\n", info.Name)
	fmt.Printf("Status:    %s\n", info.Status)
	if info.Reason != "" {
		fmt.Printf("Reason:    %s\n", info.Reason)
	}
	if info.ExitCode != nil {
		fmt.Printf("Exit code: %d\n", *info.ExitCode)
	}
	if info.Signal != "" {
		fmt.Printf("Signal:    %s\n", info.Signal)
	}
}

func currentRunE(c *cobra.Command, args []string) error {
	// One deadline for whichever branch runs. Both ask the admin socket, and
	// a host that was stopped rather than killed accepts the connection and
	// then never answers on it — which for the shell-prompt use this command
	// exists for means a prompt that never returns.
	ctx, cancel := context.WithTimeout(c.Context(), sessionQueryTimeout)
	defer cancel()

	// If output format specified, use special handling (non-interactive)
	if flagOutput != "" {
		return outputSession(ctx, flagAdminSocket, flagOutput)
	}

	detail, err := fetchSessionDetail(ctx, flagAdminSocket)
	if err != nil {
		return err
	}

	tui.PrintSessionDetail(detail)
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

	entries, err := os.ReadDir(sessiondir.SessionsRoot(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}

	currentAdminSocket := currentAdminSocketFile()
	for _, entry := range entries {
		if !entry.IsDir() || sessiondir.ValidateName(entry.Name()) != nil {
			continue
		}

		adminSocket, err := sessiondir.AdminSocketPath(dir, entry.Name())
		if err != nil {
			continue
		}

		// Per socket, not once for the walk: a listing that hit the budget on
		// its first stopped host would then report nothing at all, when what
		// it owes the user is every session that can still answer.
		sess, err := sessionWithTimeout(ctx, adminSocket)
		if err != nil {
			continue
		}

		detail, err := buildSessionDetail(sess)
		if err != nil {
			continue
		}

		detail.IsCurrent = adminSocket == currentAdminSocket
		detail.AdminSocket = adminSocket
		detail.Name = entry.Name()
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
		userSplit := strings.SplitN(user, ":", 2)
		if len(userSplit) == 1 {
			u.User = url.User(userSplit[0])
		} else {
			u.User = url.UserPassword(userSplit[0], userSplit[1])
		}
		// SSH expands percent tokens before executing ProxyCommand in a shell.
		// Quote the URL for that shell, then the command for the caller's shell.
		proxyURL := strings.ReplaceAll(u.String(), "%", "%%")
		proxyCommand := "upterm proxy " + quoteShellArg(proxyURL)
		sshCmd = fmt.Sprintf("ssh -o ProxyCommand=%s %s@%s", quoteShellArg(proxyCommand), user, host+":"+port)
	}

	var clients []string
	for _, c := range sess.ConnectedClients {
		clients = append(clients, clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint))
	}

	// Build SFTP/SCP commands if enabled and using direct SSH
	var sftpCmd, scpUpload, scpDownload string
	sftpEnabled := !sess.SftpDisabled && scheme == "ssh"
	if sftpEnabled {
		// SFTP command (similar to SSH)
		if port != "" && port != "22" {
			sftpCmd = fmt.Sprintf("sftp -P %s %s@%s", port, user, host)
			scpUpload = fmt.Sprintf("scp -P %s <local> %s@%s:<remote>", port, user, host)
			scpDownload = fmt.Sprintf("scp -P %s %s@%s:<remote> <local>", port, user, host)
		} else {
			sftpCmd = fmt.Sprintf("sftp %s@%s", user, host)
			scpUpload = fmt.Sprintf("scp <local> %s@%s:<remote>", user, host)
			scpDownload = fmt.Sprintf("scp %s@%s:<remote> <local>", user, host)
		}
	}

	return tui.SessionDetail{
		SessionID:        sess.SessionId,
		Command:          strings.Join(sess.Command, " "),
		ForceCommand:     strings.Join(sess.ForceCommand, " "),
		Host:             u.Scheme + "://" + hostPort,
		SSHCommand:       sshCmd,
		SFTPEnabled:      sftpEnabled,
		SFTPCommand:      sftpCmd,
		SCPUpload:        scpUpload,
		SCPDownload:      scpDownload,
		AuthorizedKeys:   displayAuthorizedKeys(sess.AuthorizedKeys),
		ConnectedClients: clients,
	}, nil
}

func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

// sessionWithTimeout asks one admin socket for its session and gives up after
// sessionQueryTimeout. A host that was stopped rather than killed leaves a
// socket that accepts a connection and never answers on it, and an answer
// that never comes must cost a caller a pause rather than the command.
func sessionWithTimeout(ctx context.Context, adminSocket string) (*api.GetSessionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	return session(ctx, adminSocket)
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
