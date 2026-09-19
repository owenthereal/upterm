package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	cmd.AddCommand(stop())

	return cmd
}

func list() *cobra.Command {
	runtimeDir := utils.UptermRuntimeDir()
	stateDir := utils.UptermStateDir()
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "l"},
		Short:   "List shared sessions",
		Long: fmt.Sprintf(`List shared sessions.

Which sessions exist comes from the records in: %s
A session started under a different XDG_RUNTIME_DIR is listed from there too,
and reached through the admin socket path its record carries.

Sockets are stored in: %s

Follows the XDG Base Directory Specification with fallback to $HOME/.upterm
in constrained environments where XDG directories are unavailable.`, sessiondir.ResultsRoot(stateDir), sessiondir.SessionsRoot(runtimeDir)),
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

// stopWaitTimeout bounds how long `session stop` waits for the name to be
// released once the daemon has acknowledged. The teardown's worst case is
// about sixteen seconds -- hangupGrace plus three DefaultStopGraces, as
// DefaultStopGrace's own comment says -- plus the record's publication;
// thirty seconds is that with room, and a daemon still holding the name
// past it is one to name a pid for.
var stopWaitTimeout = 30 * time.Second

// stopPollInterval is how often the release is checked for.
const stopPollInterval = 200 * time.Millisecond

func stop() *cobra.Command {
	return &cobra.Command{
		Use:   "stop NAME",
		Short: "Stop a running session",
		Long: `Stop a running session by name.

The session's command is hung up, then terminated, then killed if it stays,
and every attached terminal is released. The session's record keeps its
outcome: 'upterm session info NAME' reports it as stopped.

A session that has already ended is reported as such and is not an error.`,
		Example: `  # Stop the session named build-shell:
  upterm session stop build-shell`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			c.SilenceUsage = true
			return stopSession(c.Context(), args[0], os.Stdout)
		},
	}
}

// stopSession asks the session named to end and waits for it to have ended.
func stopSession(ctx context.Context, name string, out io.Writer) error {
	stateRoot := utils.UptermStateDir()
	lookupCtx, cancelLookup := context.WithTimeout(ctx, sessionQueryTimeout)
	rec, held, err := sessiondir.Inspect(lookupCtx, stateRoot, name)
	cancelLookup()
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("no session named %q", name)
	}
	if !held {
		_, err := fmt.Fprintf(out, "session %s has already ended (%s)\n", name, describeOutcome(rec))
		return err
	}

	adminSocket, err := adminSocketFor(utils.UptermRuntimeDir(), rec)
	if err != nil {
		return err
	}
	client, err := host.AdminClient(adminSocket)
	if err != nil {
		return err
	}
	rpcCtx, cancelRPC := context.WithTimeout(ctx, sessionQueryTimeout)
	_, err = client.StopSession(rpcCtx, &api.StopSessionRequest{})
	cancelRPC()
	if err != nil {
		if rec.Status == sessiondir.StatusStarting {
			return fmt.Errorf("session %s is still starting and cannot be stopped yet (%s); try again in a moment", name, pidOf(rec))
		}
		// A socket that answers, with the one code that means the method
		// does not exist there: the session is held by an upterm from
		// before `session stop`. Nothing this command can send will end it,
		// so name the pid and let the operator do it.
		if status.Code(err) == codes.Unimplemented {
			return fmt.Errorf("session %s was started by an upterm that predates 'session stop' and cannot be stopped this way; end it yourself (%s)", name, pidOf(rec))
		}
		return fmt.Errorf("session %s is not answering on its admin socket (%s): %w", name, pidOf(rec), err)
	}

	// Acknowledged. The name is free once this launch has released it, or
	// once another launch holds it, which is the same thing from here.
	deadline := time.Now().Add(stopWaitTimeout)
	for {
		pollCtx, cancelPoll := context.WithTimeout(ctx, sessionQueryTimeout)
		cur, curHeld, err := sessiondir.Inspect(pollCtx, stateRoot, name)
		cancelPoll()
		if err == nil && (!curHeld || cur == nil || cur.LaunchID != rec.LaunchID) {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("session %s acknowledged the stop but is still running after %s (%s)", name, stopWaitTimeout, pidOf(rec))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(stopPollInterval):
		}
	}
	final, err := sessiondir.ReadRecord(stateRoot, name)
	if err != nil || final == nil || final.LaunchID != rec.LaunchID {
		_, err := fmt.Fprintf(out, "session %s stopped\n", name)
		return err
	}
	_, err = fmt.Fprintf(out, "session %s stopped (%s)\n", name, describeOutcome(final))
	return err
}

// pidOf names the session's process for a human, or says the record
// predates the field.
func pidOf(rec *sessiondir.Record) string {
	if rec.Pid == 0 {
		return "pid unknown"
	}
	return fmt.Sprintf("pid %d", rec.Pid)
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

	sessions, err := listSessions(c.Context(), utils.UptermRuntimeDir(), utils.UptermStateDir())
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
	Name      string `json:"name"`
	LaunchID  string `json:"launchId,omitempty"`
	Status    string `json:"status"`
	SessionID string `json:"sessionId,omitempty"`
	// AdminSocket is the socket the session bound when it claimed its name,
	// published while the name is held and taken from the record: see
	// adminSocketFor. Absent once the session has ended, since there is
	// nothing left to dial.
	AdminSocket string `json:"adminSocket,omitempty"`
	// AttachSocket is where `upterm attach` dials to put a terminal on this
	// session, taken from the record for the reason AdminSocket is: the
	// session bound it under the runtime root it claimed its name with, which
	// a reader need not share. Absent once the session has ended.
	AttachSocket string `json:"attachSocket,omitempty"`
	// LogPath is where the session's process logs, from the record: the
	// daemon publishes it, since the reader's state root need not be its.
	LogPath string `json:"logPath,omitempty"`
	// Pid is the process that claimed the name, from the record. What
	// `session stop` names when the socket does not answer.
	Pid          int    `json:"pid,omitempty"`
	Command      string `json:"command,omitempty"`
	ForceCommand string `json:"forceCommand,omitempty"`
	SSHCommand   string `json:"sshCommand,omitempty"`
	ClientCount  int    `json:"clientCount"`
	// GuestCount is ClientCount without the session's own terminals. A script
	// waiting for someone to join has to watch this one: the host's terminal
	// is a client of the session, so clientCount is at least one from the
	// moment a foreground session starts.
	GuestCount       int      `json:"guestCount"`
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
// The response is the one this lookup validated, and is nil unless the record
// says ready, the admin socket answered and its session ID matched the record.
// Handing it back is what stops a caller that wants the full live detail from
// asking again: a second query returns whatever holds the name at that
// instant, which need not be the session the first one confirmed.
func lookup(ctx context.Context, name string) (sessionInfo, *api.GetSessionResponse, error) {
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
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

	// Where the session answers, published for the caller and used for the
	// dial below. The record's path, not one built under this process's
	// runtime root: see adminSocketFor.
	adminSocket, err := adminSocketFor(utils.UptermRuntimeDir(), rec)
	if err != nil {
		return sessionInfo{}, nil, err
	}
	info.AdminSocket = adminSocket
	// And where a terminal would attach, which is the record's path for the
	// same reason. Empty for a record written before attach sockets existed,
	// and omitted from the JSON rather than published as a path nothing is
	// bound at.
	info.AttachSocket = rec.AttachSocket

	// A record with no session ID has not reached ready, so there is nothing
	// for the admin socket to confirm and nothing to compare against. Skip it
	// rather than issue a query whose generation check could not succeed.
	if rec.SessionID == "" {
		return info, nil, nil
	}

	// The socket answers about a session, and only ready says its answer is
	// one anyone can act on. After a tunnel loss the host keeps its command
	// and its admin server running until the session ends — stage 1 has no
	// way back from disconnected — so a disconnected session's socket
	// answers as readily as a live one's, with a connect string that cannot
	// connect. The record's view is the whole answer. A later stage that
	// reconnects needs nothing more here: a record back at ready is dialled
	// again.
	if rec.Status != sessiondir.StatusReady {
		return info, nil, nil
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
		LogPath:      rec.LogPath,
		Pid:          rec.Pid,
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
	info.GuestCount = countGuests(sess.ConnectedClients)
	return info
}

// countGuests counts the clients that came in by the guest door. The response
// is what it is counted from rather than the rendered descriptions: the kind
// is a field, and reading it back out of a formatted line would make a
// display change a counting change.
func countGuests(clients []*api.Client) int {
	var n int
	for _, c := range clients {
		if c.Kind != api.Client_HOST {
			n++
		}
	}
	return n
}

// adminSocketFor returns the admin socket a held record's session answers at.
//
// The record carries the path because the session claimed its name under a
// runtime root the reader need not share: on Linux a cron job, a systemd unit
// and an ssh login each get their own XDG_RUNTIME_DIR, and all of them publish
// into the one state root the reader finds the record through. A path built
// under the reader's root named a socket nothing was bound at, so every such
// session was found and then shown as if nothing answered for it. The path
// under runtimeRoot survives for one case: a record written before records
// carried the field.
//
// The recorded path is dialled as it is. What makes that safe is what makes
// the record worth reading at all: the results root and every directory
// under it are created 0700, the record 0600, and only a record whose lock
// is held is dialled — so whoever could plant a path here could already
// plant the whole record.
func adminSocketFor(runtimeRoot string, rec *sessiondir.Record) (string, error) {
	if rec.AdminSocket != "" {
		return rec.AdminSocket, nil
	}
	return sessiondir.AdminSocketPath(runtimeRoot, rec.Name)
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
		if detail, err := buildSessionDetail(live); err == nil {
			detail.Name = name
			// The status the lookup settled on, which the socket's answer does
			// not carry: the summary below prints one for a session that has
			// ended, and `session list` prints one for every row, so the one
			// case that answered "how is NAME?" without saying was this one.
			detail.Status = info.Status
			// And the path the lookup dialled, which is the record's. Built
			// again here it would come out under this process's runtime root
			// and disagree with the socket that just answered.
			detail.AdminSocket = info.AdminSocket
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

// listSessions reports every session that exists right now, carrying whatever
// live detail its socket can confirm.
//
// Which sessions exist comes from the records, not from the sessions directory
// under runtimeRoot: a name is held on both roots, and only the results root is
// the same directory for every host on the machine. Walking the runtime root
// hid any session started under a different XDG_RUNTIME_DIR — which on Linux is
// a cron job, a systemd unit or an ssh login, depending on how the box is set
// up — from the one command that is supposed to show a user their sessions,
// while `session info NAME` answered for it perfectly well.
//
// The socket a record names refines its row; it never decides whether there
// is one.
func listSessions(ctx context.Context, runtimeRoot, stateRoot string) ([]tui.SessionDetail, error) {
	// Bounded on its own rather than across the whole walk, for the reason
	// each socket query is: the registry lock and every admin socket are
	// separate things a stopped process can hold, and one of them must not be
	// able to spend the budget the rest need.
	listCtx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	records, err := sessiondir.ListLive(listCtx, stateRoot)
	if err != nil {
		return nil, err
	}

	currentAdminSocket := currentAdminSocketFile()
	var result []tui.SessionDetail
	for _, rec := range records {
		// What the record knows is the whole row until a socket says more.
		// The status especially: it is the record's to publish, and it is all
		// that distinguishes a session still starting from one running out of
		// this environment's reach.
		detail := tui.SessionDetail{
			Name:         rec.Name,
			Status:       rec.Status,
			SessionID:    rec.SessionID,
			Command:      strings.Join(rec.Command, " "),
			ForceCommand: strings.Join(rec.ForceCommand, " "),
		}

		if live, ok := liveDetail(ctx, runtimeRoot, rec); ok {
			// The record stays authoritative for what it owns: the socket
			// answers about a session, not about a name or its status.
			live.Name = rec.Name
			live.Status = rec.Status
			live.IsCurrent = live.AdminSocket == currentAdminSocket
			detail = live
		}

		result = append(result, detail)
	}

	return result, nil
}

// liveDetail returns what a running session can fill in that its record
// cannot — who is connected, and how to join them.
//
// The answer is accepted only if its session ID is the record's, the same
// generation check `session info` makes: between the listing and this query
// the session can end and a successor can claim the name, and a successor's
// connect string printed under this session's name sends whoever reads it to
// the wrong terminal.
func liveDetail(ctx context.Context, runtimeRoot string, rec sessiondir.Record) (tui.SessionDetail, bool) {
	// A record with no session ID has not reached ready, so there is nothing
	// for a socket to confirm and no generation to compare against.
	if rec.SessionID == "" {
		return tui.SessionDetail{}, false
	}

	// And a session that has one but is not ready is not joinable, whatever
	// its socket says: the tunnel-loss path keeps the admin server up, so a
	// disconnected session answers with a connect string nobody can use. The
	// same gate `session info` keeps in front of its dial.
	if rec.Status != sessiondir.StatusReady {
		return tui.SessionDetail{}, false
	}

	adminSocket, err := adminSocketFor(runtimeRoot, &rec)
	if err != nil {
		return tui.SessionDetail{}, false
	}

	// Per socket, not once for the walk: a listing that hit the budget on
	// its first stopped host would then report nothing at all, when what
	// it owes the user is every session that can still answer.
	sess, err := sessionWithTimeout(ctx, adminSocket)
	if err != nil || sess.SessionId != rec.SessionID {
		return tui.SessionDetail{}, false
	}

	detail, err := buildSessionDetail(sess)
	if err != nil {
		// A host URL that will not parse is a reason to show the row the
		// record already supports, not to drop the session from the listing.
		return tui.SessionDetail{}, false
	}

	detail.AdminSocket = adminSocket
	return detail, true
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
		clients = append(clients, clientDesc(c.Kind, c.Addr, c.Version, c.PublicKeyFingerprint))
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

// clientDesc describes one connected client, starting with the door it came
// in by. A session's own terminals are clients of it now, and a line that did
// not say which was which would show an operator a stranger where their own
// window is.
func clientDesc(kind api.Client_Kind, addr, clientVer, fingerprint string) string {
	if shouldHideClientIP() {
		addr = "[redacted]"
	}
	return fmt.Sprintf("%s %s %s %s", kindName(kind), addr, clientVer, fingerprint)
}

// kindName names a client's door for a person reading it. The proto's own
// String() shouts (GUEST, HOST) and is a wire detail; these are the words the
// README and `session info` use.
func kindName(k api.Client_Kind) string {
	if k == api.Client_HOST {
		return "host"
	}
	return "guest"
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
