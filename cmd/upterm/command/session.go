package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/join"
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
	// flagListOutput is `session list`'s own, not flagOutput: the list takes
	// its format from the command line alone, and sharing the variable of the
	// commands that also take it from env and config would let their value
	// reach it.
	flagListOutput string
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

// waitUnavailableCode is what `session wait` exits when the session produced
// no exit status of its own.
//
// 125 by the convention git uses for "the tool could not produce a result".
// It is NOT distinct from every hosted-command code -- a command can exit 125
// itself -- and no single integer could be. A caller that must tell the two
// apart reads `reason` from `session info -o json`; this is a convenience for
// the common case, not a discriminator.
const waitUnavailableCode = 125

// notFoundCode is what `session info`, `session stop` and `session set` exit
// with when no record for the name exists within retention: 4, after
// systemctl's "no such unit". Every other failure of those commands keeps 1,
// so a script can tell "no such session" from "could not ask" without reading
// stderr.
//
// `session current` exits with it too, for its own condition: not in a
// session, because $UPTERM_ADMIN_SOCKET is unset or no session answers at it.
//
// Not `session wait`: it passes the hosted command's own exit code through,
// so no code of its own could be unambiguous there, and it keeps
// waitUnavailableCode for every lookup failure.
const notFoundCode = 4

// errNoSession is the not-found failure, carrying notFoundCode. Its message
// is the one these commands have always printed.
func errNoSession(name string) error {
	return ExitCodeError{Code: notFoundCode, Err: fmt.Errorf("no session named %q", name)}
}

// resolved is what a session argument named: the session's name, and, when it
// was given by ID, the launch that ID belongs to.
//
// The launch is what makes an ID name one session. A name is free the moment
// its session ends, so a command that kept only the name could go on to stop
// or change whichever session took it over. Every step after resolution
// reads the record by name and checks it against LaunchID, when there is one:
// see matchesLaunch.
//
// Every record upterm writes has a launch ID. One without, written by hand or
// damaged, is pinned by the session ID the argument matched instead.
type resolved struct {
	Name string
	// LaunchID is empty when the argument was a name, which names whatever
	// launch holds it now, as it always has, or when the record the ID matched
	// has no launch ID.
	LaunchID string
	// SessionID is the ID the argument matched, and empty when it was a name.
	// It lets a report of a session whose name another launch took say whose
	// ID it was given, when that session's own record is gone, and it pins
	// the session when its record has no launch ID.
	SessionID string
}

// afterResolve, when a test sets it, runs between resolveSession and the
// first read of the session it resolved, so that the test can end the session
// and let another take its name at the one point that can happen. Nil outside
// tests.
var afterResolve func()

// resolveSession is the session an argument names: an exact name when one
// has a record, held or ended, else the session whose ID is exactly arg, with
// its launch. An argument that is neither comes back as itself, to be found
// missing by the step that reads it, which says so in its own words and exit
// code.
//
// The name comes first because it always has: an ID that happens to be some
// other session's name must not make that name unreachable. Both are exact.
func resolveSession(ctx context.Context, arg string) (resolved, error) {
	r, err := resolveArg(ctx, arg)
	if err != nil {
		return resolved{}, err
	}
	if afterResolve != nil {
		afterResolve()
	}
	return r, nil
}

func resolveArg(ctx context.Context, arg string) (resolved, error) {
	stateRoot := utils.UptermStateDir()

	// What is not a valid name is not looked up as one: Inspect would refuse
	// it, and the step that reads it will say why.
	if sessiondir.ValidateName(arg) == nil {
		rec, _, err := sessiondir.Inspect(ctx, stateRoot, arg)
		if err != nil {
			return resolved{}, err
		}
		if rec != nil {
			return resolved{Name: arg}, nil
		}
	}

	name, launchID, found, err := sessiondir.FindByID(ctx, stateRoot, arg)
	if err != nil {
		return resolved{}, err
	}
	if !found {
		return resolved{Name: arg}, nil
	}
	return resolved{Name: name, LaunchID: launchID, SessionID: arg}, nil
}

// matchesLaunch is the check every step after resolveSession makes of the
// record it reads by name: when the argument was an ID, a record for any other
// session means the one it named has ended and its name was reused. The launch
// tells them apart, and for a record that has none (every record upterm writes
// has one, so it was written by hand or damaged) the session ID the argument
// matched does; a record with no session ID yet is not that session. A name
// argument has neither to check, so it matches.
func matchesLaunch(r resolved, rec *sessiondir.Record) bool {
	switch {
	case r.LaunchID != "":
		return rec.LaunchID == r.LaunchID
	case r.SessionID != "":
		return rec.SessionID == r.SessionID
	}
	return true
}

// goneRecord stands for a session given by ID whose name another launch holds
// now. Its own record went when that launch claimed the name, and with it the
// only account of how it ended, so this says that the session is over, which
// the ID established, and nothing about how. The ID is the one the argument
// matched, so it is still this session's own.
func goneRecord(r resolved) *sessiondir.Record {
	return &sessiondir.Record{Name: r.Name, LaunchID: r.LaunchID, SessionID: r.SessionID, Reason: sessiondir.ReasonUnknown}
}

// named is subject, the session's name as a line writes it, followed by the ID
// the argument gave when it was one. It is for the lines about a session whose
// name another launch holds now: the name alone would read as that other
// session, which these commands have not touched. An argument that was a name
// has no ID to add, and its line is the name's.
func (r resolved) named(subject string) string {
	if r.SessionID == "" {
		return subject
	}
	return subject + " (ID " + r.SessionID + ")"
}

// replacedNotStopped and replacedNotChanged are what `session stop` and
// `session set` say when the session they were asked about is no longer the
// one holding its name. Nothing was sent to the one that does. The pointer
// names the name, which shows what holds it.
func replacedNotStopped(r resolved) error {
	return fmt.Errorf("session %s has been replaced since it was read and was not stopped; inspect it again with 'upterm session info %s'", r.named(r.Name), r.Name)
}

func replacedNotChanged(r resolved) error {
	return fmt.Errorf("session %s has been replaced since it was read and was not changed; inspect it again with 'upterm session info %s'", r.named(r.Name), r.Name)
}

// waitExitCode maps a finished session's recorded outcome onto this command's
// exit status. Every reason is named; a default returning 0 would report an
// outcome nobody established as a success, which is the one answer a waiter
// must never invent.
func waitExitCode(rec *sessiondir.Record) int {
	switch rec.Reason {
	case sessiondir.ReasonExited:
		// "exited" with no code is incoherent, not successful.
		if rec.ExitCode == nil {
			return waitUnavailableCode
		}
		return *rec.ExitCode
	case sessiondir.ReasonJoinTimeout, sessiondir.ReasonStopped:
		// Nobody joined, or somebody asked. Neither is a failed build, and
		// reddening the first would make --join-timeout unusable in CI.
		return 0
	case sessiondir.ReasonSignaled:
		if rec.SignalNumber == nil || *rec.SignalNumber < 1 || *rec.SignalNumber > 126 {
			return waitUnavailableCode
		}
		return 128 + *rec.SignalNumber
	default:
		return waitUnavailableCode
	}
}

// currentInfo is what `session current -o json` prints and what its template
// reads. It is its own struct rather than sessionInfo because its presence
// rules differ field by field: the five keys the command has always printed
// are always there, and everything the daemon's answer may not carry is left
// out when it doesn't. It is built from that answer alone, so the command
// needs no record and answers wherever the admin socket does.
type currentInfo struct {
	// The five keys the command has always printed, present even when empty,
	// from fields every daemon sends. The template has always read them by
	// these names.
	SessionID    string `json:"sessionId"`
	ClientCount  int    `json:"clientCount"`
	Host         string `json:"host"`
	Command      string `json:"command"`
	ForceCommand string `json:"forceCommand"`

	// Always present too, and from the same kind of field: the connected
	// clients and the authorized keys, which every daemon sends. ClientCount
	// includes the session's own terminals and GuestCount doesn't, as in
	// `session info`. The counts are the daemon's, so CountsKnown is always
	// true here. Access is "anyone" when there are no authorized keys, else
	// "allowlist". ConnectedClients is left out when nobody is connected.
	GuestCount       int      `json:"guestCount"`
	CountsKnown      bool     `json:"countsKnown"`
	Access           string   `json:"access"`
	ConnectedClients []string `json:"connectedClients,omitempty"`

	// From fields a daemon has sent since 0.32.0 (launch_id and join_state)
	// and since 0.37.0 (open). The launch is the daemon's: it sends none when
	// it claimed no name (see launch_id in host/api/api.proto), and the key is
	// left out then. Open is printed only when true, and as the daemon gives it
	// whatever the status, where `session info` leaves it out for a session
	// that isn't connected. The join fields are read as `session info` reads
	// them: only when join_state is there, with a guest's join disabling the
	// timeout. Times are UTC.
	LaunchID           string    `json:"launchId,omitempty"`
	Open               bool      `json:"open,omitempty"`
	JoinStateSource    string    `json:"joinStateSource,omitempty"`
	JoinTimeout        string    `json:"joinTimeout,omitempty"`
	JoinDeadline       time.Time `json:"joinDeadline,omitzero"`
	FirstGuestJoinedAt time.Time `json:"firstGuestJoinedAt,omitzero"`

	// From the optional fields, which only a daemon newer than 0.38.0 sends.
	// Each is left out when the daemon doesn't send it, and a string is left
	// out when the daemon sends it empty too, which is how it says there is
	// nothing to report: no reconnect before the relay has said, no reason
	// while the tunnel is up. A false is the daemon's answer and is printed.
	// Times are UTC.
	Name                         string    `json:"name,omitempty"`
	Status                       string    `json:"status,omitempty"`
	Reconnect                    string    `json:"reconnect,omitempty"`
	TunnelReason                 string    `json:"tunnelReason,omitempty"`
	TunnelLostAt                 time.Time `json:"tunnelLostAt,omitzero"`
	NextAttemptAt                time.Time `json:"nextAttemptAt,omitzero"`
	StartConfirmed               *bool     `json:"startConfirmed,omitempty"`
	ReadOnly                     *bool     `json:"readOnly,omitempty"`
	FileTransfer                 string    `json:"fileTransfer,omitempty"`
	FileTransferApprovalRequired *bool     `json:"fileTransferApprovalRequired,omitempty"`
	LocalForwarding              *bool     `json:"localForwarding,omitempty"`

	// The connect strings, built from the host and SSH user every daemon
	// sends, but printed only when the status the daemon reports says guests
	// can use them, which is `session info`'s rule: a disconnected session
	// keeps a connect string that can't connect, and a daemon that doesn't
	// report its status doesn't say whether its can.
	SSHCommand  string `json:"sshCommand,omitempty"`
	JoinCommand string `json:"joinCommand,omitempty"`
}

// currentInfoFrom builds currentInfo from the daemon's answer alone. The
// join fields are read as `session info` reads a live answer
// (withLiveJoinState), the claim rule included.
func currentInfoFrom(sess *api.GetSessionResponse) currentInfo {
	info := currentInfo{
		SessionID:    sess.GetSessionId(),
		ClientCount:  len(sess.GetConnectedClients()),
		Host:         sess.GetHost(),
		Command:      strings.Join(sess.GetCommand(), " "),
		ForceCommand: strings.Join(sess.GetForceCommand(), " "),

		GuestCount:  countGuests(sess.GetConnectedClients()),
		CountsKnown: true,
		Access:      accessOf(sess.GetAuthorizedKeys()),

		LaunchID: sess.GetLaunchId(),
		Open:     sess.GetOpen(),

		Name:                         sess.GetName(),
		Status:                       sess.GetStatus(),
		Reconnect:                    sess.GetReconnect(),
		TunnelReason:                 sess.GetTunnelReason(),
		TunnelLostAt:                 unixNanoUTC(sess.GetTunnelLostAtUnixNano()),
		NextAttemptAt:                unixNanoUTC(sess.GetNextAttemptAtUnixNano()),
		StartConfirmed:               sess.StartConfirmed,
		ReadOnly:                     sess.ReadOnly,
		FileTransfer:                 sess.GetFileTransfer(),
		FileTransferApprovalRequired: sess.FileTransferApprovalRequired,
		LocalForwarding:              sess.LocalForwarding,
	}
	for _, c := range sess.GetConnectedClients() {
		info.ConnectedClients = append(info.ConnectedClients, clientDesc(c))
	}

	join := withLiveJoinState(sessionInfo{}, sess)
	info.JoinStateSource = join.JoinStateSource
	info.JoinTimeout = join.JoinTimeout
	info.JoinDeadline = join.JoinDeadline
	info.FirstGuestJoinedAt = join.FirstGuestJoinedAt

	if joinable(info.Status) {
		// A host URL that won't parse costs the connect strings, not the
		// answer: the rest of it is still the daemon's.
		if detail, err := buildSessionDetail(sess); err == nil {
			info.SSHCommand = detail.SSHCommand
			info.JoinCommand = detail.JoinCommand
		}
	}
	return info
}

// unixNanoUTC is the moment n names, in UTC, or the zero time for 0, which
// names none: the daemon leaves a time it doesn't have unset.
func unixNanoUTC(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// nameOrIDHelp says what the session argument of attach and the session
// commands is, as resolveSession reads it.
const nameOrIDHelp = `NAME|ID is the session's name (the one 'upterm host' printed, or --name
gave it) or its session ID; 'upterm session list' shows both.`

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
	cmd.AddCommand(setCmd())
	cmd.AddCommand(wait())

	return cmd
}

func list() *cobra.Command {
	stateDir := utils.UptermStateDir()
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "l"},
		Short:   "List running sessions",
		Long: fmt.Sprintf(`List the running sessions, one row each: name, status, session ID, command
and relay. * marks the session this terminal is in ($UPTERM_ADMIN_SOCKET).

The sessions come from the records in: %s
Sessions started under another XDG_RUNTIME_DIR are listed too. Listing
deletes the records of sessions that ended more than %s ago, after which
'upterm session info' and 'upterm session wait' no longer know them.

-o json prints a JSON array of what 'upterm session info NAME -o json'
prints, one per running session, and [] when none is running.

Exit status: 0, or 1 when the records directory can't be read, or for a usage
or configuration error. A session whose own record can't be read is left out
of the list.`, sessiondir.ResultsRoot(stateDir), retentionText(sessiondir.RecordRetention)),
		Example: `  # List the running sessions:
  upterm session list

  # As JSON, for a script:
  upterm session list -o json`,
		Args: cobra.ExactArgs(0),
		RunE: listRunE,
	}

	// Only the command line sets it: an output key or UPTERM_OUTPUT is meant
	// for the commands that take one, and must neither turn this listing into
	// JSON nor make it fail.
	cmd.Flags().StringVarP(&flagListOutput, "output", "o", "", "Output format: json (command line only)")
	_ = cmd.RegisterFlagCompletionFunc("output", completeValues("json"))
	_ = cmd.Flags().SetAnnotation("output", annotationCLIOnly, []string{"true"})
	// Registered here as `session info` registers it: env and config bind only
	// to a command's own flags, so without it the listing's JSON would print
	// the guest addresses they hide everywhere else.
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, hideClientIPHelp)

	return cmd
}

func show() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info NAME|ID",
		Aliases: []string{"i"},
		Short:   "Show a session, given its name or session ID",
		Long: `Show a session, given its name or session ID: its status, how guests join
it, who is connected, and what guests may do.

` + nameOrIDHelp + ` A name is
looked up before an ID.

A session that has ended still answers, from the record it left behind: how
it ended.

Output formats:
  -o json   JSON

Exits 4 when no session has the name, and 1 for any other failure.`,
		Example: `  # Show the session named build:
  upterm session info build

  # The same session, by its session ID:
  upterm session info d3k5fia7m4us73ehblug

  # As JSON:
  upterm session info build -o json`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessionNames,
		RunE:              infoRunE,
	}

	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: json")
	_ = cmd.RegisterFlagCompletionFunc("output", completeValues("json"))
	perRun(cmd.Flags(), "output")
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, hideClientIPHelp)

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

// waitPollFailureBudget bounds how long consecutive inspection failures are
// tolerated before one is reported.
//
// A read can fail transiently -- the registry lock is held by a session
// starting up, a rename is mid-flight. It can also fail permanently: a
// corrupt record, a directory that lost its permissions. The first draft
// treated every error as transient and would spin forever on the second
// kind, silently, even after the session had ended. A budget tells them
// apart without needing to classify the error.
const waitPollFailureBudget = 30 * time.Second

// wait blocks until the named session has ended and returns its outcome.
func wait() *cobra.Command {
	return &cobra.Command{
		Use:   "wait NAME|ID",
		Short: "Wait for a session to end",
		Long: fmt.Sprintf(`Wait for a session to end, given its name or session ID, and exit with its
outcome.

`+nameOrIDHelp+`

Given a name, it waits for the session that holds the name when it starts,
so let 'upterm host --detach' return before you wait, as in the example. A
session that has already ended is reported from its record, which
'upterm session list' deletes once it is %s old.

Exit status follows the session: its command's status when the command
exited; 0 when it was stopped, or no guest joined within its join timeout;
128+N when the host or its command was killed by signal N; 125 when the
outcome can't be known or read, when no session has the name, or for a usage
or configuration error. A command can exit 125 too; 'upterm session info
NAME -o json' has the reason. Ctrl-C stops waiting, with 130 on Unix, and
leaves the session running.`, retentionText(sessiondir.RecordRetention)),
		Example: `  # Wait for a detached session and take its exit status:
  upterm host --detach --accept --name build -- make
  upterm session wait build

  # Wait for a session given its session ID:
  upterm session wait d3k5fia7m4us73ehblug`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessionNames,
		// Usage and config errors exit with that failure code too, not only what
		// RunE returns.
		Annotations: map[string]string{failureCodeAnnotation: strconv.Itoa(waitUnavailableCode)},
		RunE: func(c *cobra.Command, args []string) error {
			code, err := waitSession(c.Context(), args[0], os.Stdout)
			if err != nil {
				return ExitCodeError{Code: waitUnavailableCode, Err: err}
			}
			if code != 0 {
				// Bare, with no Err, exactly as attachExitError returns it,
				// so that Exit prints nothing: this command succeeded; the
				// thing it watched did not.
				return ExitCodeError{Code: code}
			}
			return nil
		},
	}
}

// waitSession blocks until the named session has ended and returns the exit
// status this command should carry.
//
// Polls the record rather than the admin socket, for stopSession's reason:
// the socket dies with the process, so it can never answer "did it finish".
//
// Bound to the launch resolved on entry. A name is reused, so the session
// that answers at the end need not be the one the caller asked about. Given an
// ID, the launch is the one the ID names, from the start: a name that was
// reused before the first read is reported as the session that ended, not
// waited on.
func waitSession(ctx context.Context, arg string, out io.Writer) (int, error) {
	stateRoot := utils.UptermStateDir()

	lookupCtx, cancelLookup := context.WithTimeout(ctx, sessionQueryTimeout)
	r, err := resolveSession(lookupCtx, arg)
	if err != nil {
		cancelLookup()
		return 0, err
	}
	name := r.Name
	rec, held, err := sessiondir.Inspect(lookupCtx, stateRoot, name)
	cancelLookup()
	if err != nil {
		return 0, err
	}
	if rec == nil {
		// Absent means only "not found within retained history": Prune
		// removes anything unheld and older than RecordRetention.
		return 0, fmt.Errorf("no session named %q (a session that ended more than %s ago is no longer retained)", name, retentionText(sessiondir.RecordRetention))
	}
	if !matchesLaunch(r, rec) {
		return finishWait(out, r.named(name), goneRecord(r))
	}

	waited := rec
	if !held {
		return finishWait(out, name, rec)
	}

	var firstFailure time.Time
	for {
		select {
		case <-ctx.Done():
			// An observer. ^C here must not be a way to end a session.
			return 0, ctx.Err()
		case <-time.After(stopPollInterval):
		}

		pollCtx, cancelPoll := context.WithTimeout(ctx, sessionQueryTimeout)
		cur, curHeld, err := sessiondir.Inspect(pollCtx, stateRoot, name)
		cancelPoll()
		if err != nil {
			if firstFailure.IsZero() {
				firstFailure = time.Now()
			}
			if time.Since(firstFailure) > waitPollFailureBudget {
				return 0, fmt.Errorf("session %s could not be inspected for %s: %w", name, waitPollFailureBudget, err)
			}
			continue
		}
		firstFailure = time.Time{}

		if cur == nil {
			return 0, fmt.Errorf("session %s disappeared while waiting; its outcome is unavailable", name)
		}
		// The ID's pin as well as the launch: a record with no launch ID has
		// the same launch as any other that has none.
		if cur.LaunchID != waited.LaunchID || !matchesLaunch(r, cur) {
			return 0, waitLaunchChanged(name, waited, cur)
		}
		if curHeld {
			continue
		}
		// cur is the record Inspect just returned under the registry lock,
		// and its launch is the one waited on. Re-reading here would open a
		// replacement/pruning race after a valid outcome was already in hand.
		return finishWait(out, name, cur)
	}
}

func finishWait(out io.Writer, subject string, rec *sessiondir.Record) (int, error) {
	_, _ = fmt.Fprintln(out, waitLine(subject, endedFromRecord(rec)))
	return waitExitCode(rec), nil
}

// waitLaunchChanged is the error for a name reused while this command was
// waiting on it. Never followed silently: a waiter that switched to the
// replacement would report the new session's outcome as the old one's, and
// the caller cannot notice -- the name it asked about is the name that
// answered.
func waitLaunchChanged(name string, waited, found *sessiondir.Record) error {
	return fmt.Errorf("session %s was replaced while waiting: %s ended and %s holds the name now; its outcome is not this one's", name, launchLabel(waited), launchLabel(found))
}

// launchLabel is what a message calls the launch a record describes: its launch
// ID, or for a record that has none (see matchesLaunch) its session ID, so that
// the two a message sets side by side are never both blank.
func launchLabel(rec *sessiondir.Record) string {
	switch {
	case rec.LaunchID != "":
		return rec.LaunchID
	case rec.SessionID != "":
		return rec.SessionID
	}
	return "a session with no ID"
}

func stop() *cobra.Command {
	return &cobra.Command{
		Use:   "stop NAME|ID",
		Short: "Stop a running session",
		Long: `Stop a running session, given its name or session ID.

` + nameOrIDHelp + `

The session's command is hung up, then terminated, then killed if it stays,
and every attached terminal is released. The session's record keeps its
outcome: 'upterm session info NAME' reports it as stopped.

A session that has already ended is reported as such and is not an error.

Exits 4 when no session has the name, and 1 for any other failure.`,
		Example: `  # Stop the session named build-shell:
  upterm session stop build-shell

  # Stop a session given its session ID:
  upterm session stop d3k5fia7m4us73ehblug`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessionNames,
		RunE: func(c *cobra.Command, args []string) error {
			return stopSession(c.Context(), args[0], os.Stdout)
		},
	}
}

// stopSession asks the session named to end and waits for it to have ended.
func stopSession(ctx context.Context, arg string, out io.Writer) error {
	stateRoot := utils.UptermStateDir()
	lookupCtx, cancelLookup := context.WithTimeout(ctx, sessionQueryTimeout)
	r, err := resolveSession(lookupCtx, arg)
	if err != nil {
		cancelLookup()
		return err
	}
	name := r.Name
	rec, held, err := sessiondir.Inspect(lookupCtx, stateRoot, name)
	cancelLookup()
	if err != nil {
		return err
	}
	if rec == nil {
		return errNoSession(name)
	}
	// Before anything is sent: the stop below names the launch of the record
	// just read, which is whatever holds the name now. Given an ID whose
	// session has ended and whose name another took, that is the other
	// session's launch, and its daemon would accept the stop.
	if !matchesLaunch(r, rec) {
		return replacedNotStopped(r)
	}
	if !held {
		_, err := fmt.Fprintln(out, alreadyEndedLine(name, endedFromRecord(rec)))
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
	// The launch that was inspected, not just the name: the socket path
	// belongs to the name, and a session that ended between the read above
	// and this call hands both to whoever claimed the name next. The daemon
	// refuses a launch that is not its own, which is what keeps this from
	// stopping a session the operator never looked at.
	_, err = client.StopSession(rpcCtx, &api.StopSessionRequest{LaunchId: rec.LaunchID})
	cancelRPC()
	if err != nil {
		// A socket that answers, with the one code that means the method
		// does not exist there: the session is held by an upterm from
		// before `session stop`. Nothing this command can send will end it,
		// so name the pid and let the operator do it.
		//
		// Checked ahead of the status, because the two overlap: a daemon
		// that predates this RPC and is still starting answers Unimplemented
		// with a starting record, and "try again in a moment" is advice that
		// can never come good for it. Every later attempt reaches the same
		// missing method.
		if status.Code(err) == codes.Unimplemented {
			return fmt.Errorf("session %s was started by an upterm that predates 'session stop' and cannot be stopped this way; end it yourself (%s)", name, pidOf(rec))
		}
		// The daemon's way of saying the socket is no longer the launch that
		// was read: the session ended and another one claimed the name
		// between the two. Refused rather than stopped, because the run this
		// command was told to end is already over and the one holding the
		// name now is somebody else's. Checked here, before the status
		// below, for the reason Unimplemented is: it is an answer, and a
		// guess from the record cannot improve on one.
		if status.Code(err) == codes.FailedPrecondition {
			return replacedNotStopped(r)
		}
		if rec.Status == sessiondir.StatusStarting {
			return fmt.Errorf("session %s is still starting and cannot be stopped yet (%s); try again in a moment", name, pidOf(rec))
		}
		// What the socket said is for --debug: "rpc error: code = Unavailable
		// ..." tells a person nothing they can act on, where the log does.
		logCause(ctx, "the admin socket did not answer a stop", name, err)
		return errors.New(isntAnswering(name, rec) + seeLog("; see %s", rec.LogPath))
	}

	// Acknowledged. The name is free once this launch has released it, or
	// once another launch holds it, which is the same thing from here.
	deadline := time.Now().Add(stopWaitTimeout)
	var lastInspectErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastInspectErr != nil {
				return fmt.Errorf("session %s acknowledged the stop but its completion could not be confirmed after %s: %w", name, shortDuration(stopWaitTimeout), lastInspectErr)
			}
			return fmt.Errorf("session %s acknowledged the stop but is still running after %s (%s)", name, shortDuration(stopWaitTimeout), pidOf(rec))
		}
		pollCtx, cancelPoll := context.WithTimeout(ctx, min(sessionQueryTimeout, remaining))
		cur, curHeld, err := sessiondir.Inspect(pollCtx, stateRoot, name)
		cancelPoll()
		if err == nil && (!curHeld || cur == nil || cur.LaunchID != rec.LaunchID || !matchesLaunch(r, cur)) {
			break
		}
		lastInspectErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(stopPollInterval, max(0, time.Until(deadline)))):
		}
	}
	// The command can end on its own between the request and the teardown
	// it asked for. The record says which happened, and a stop that lost
	// that race says how the session did end rather than claim it stopped
	// it. A record that can't be read, or that another launch has written
	// since, says nothing about this launch, and the acknowledgement stands.
	final, err := sessiondir.ReadRecord(stateRoot, name)
	if err == nil && final != nil && final.LaunchID == rec.LaunchID && matchesLaunch(r, final) && final.Reason != sessiondir.ReasonStopped {
		_, err := fmt.Fprintln(out, alreadyEndedLine(name, endedFromRecord(final)))
		return err
	}
	_, err = fmt.Fprintf(out, "session %s stopped\n", name)
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

// setCmd changes a running session's settings. --join-timeout is the only one
// today, so its help says what it does now; the command is named for the verb
// so later settings can join it.
func setCmd() *cobra.Command {
	var joinTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "set NAME|ID",
		Short: "Change a session's join timeout",
		Long: `Change a session's join timeout, given its name or session ID.

` + nameOrIDHelp + `

--join-timeout D ends the session D from now unless a guest joins first. It
replaces any join timeout already set, including one given to
'upterm host --join-timeout', so each call restarts the window: running it
again with the same duration extends the deadline. 0 disables it. Before the
session is ready, the timeout counts from readiness.

A guest who joins, however briefly and whether by terminal or SFTP, claims the
session: the automatic join timeout is disabled for the rest of its life, and
a later set says so and changes nothing. After that, nothing ends the session
but its command exiting or 'upterm session stop'.

'upterm session wait NAME' blocks until the session ends; interrupting it
leaves the session running. 'upterm session stop NAME' ends it.

Durations are shown compact and normalised: 90m shows as 1h30m.

Exits 0 when the session took the change, was already claimed, is ending, or
has already ended, 4 when no session has the name, and 1 for any other
failure -- including a change that could not be confirmed, which may still
have taken effect: running set again restarts the window, and 'upterm session
info NAME' shows what the session holds.`,
		Example: `  # Debug a failed build: open the session first, give people 10 minutes to
  # join only if the build fails, and keep the build's exit status. Safe under
  # set -e and in zsh, where $status is read-only:
  upterm host --detach --accept --name build -- bash
  build_exit_code=0
  make || build_exit_code=$?
  if [ "$build_exit_code" -ne 0 ]; then
    # Ten minutes for someone to join; once they have, it runs until they exit.
    if upterm session set build --join-timeout 10m; then
      upterm session wait build || true
    fi
  fi
  upterm session stop build || true   # ends it either way; never masks the build's result
  exit "$build_exit_code"

  # Give 20 more minutes from now, replacing the current window:
  upterm session set build --join-timeout 20m

  # Turn the join timeout off:
  upterm session set build --join-timeout 0

  # Give a session 10 minutes, given its session ID:
  upterm session set d3k5fia7m4us73ehblug --join-timeout 10m`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessionNames,
		RunE: func(c *cobra.Command, args []string) error {
			if !c.Flags().Changed("join-timeout") {
				return fmt.Errorf("nothing to set: pass --join-timeout")
			}
			if joinTimeout < 0 {
				return fmt.Errorf("--join-timeout must not be negative, got %s", shortDuration(joinTimeout))
			}
			return setSession(c.Context(), args[0], joinTimeout, os.Stdout)
		},
	}
	cmd.Flags().DurationVar(&joinTimeout, "join-timeout", 0, "End the session this long from now unless a guest joins first (e.g. 10m). Replaces any join timeout already set; 0 disables it.")
	perRun(cmd.Flags(), "join-timeout")
	return cmd
}

// setSession sets the named session's join timeout and reports what the
// session answered.
func setSession(ctx context.Context, arg string, joinTimeout time.Duration, out io.Writer) error {
	stateRoot := utils.UptermStateDir()
	lookupCtx, cancelLookup := context.WithTimeout(ctx, sessionQueryTimeout)
	r, err := resolveSession(lookupCtx, arg)
	if err != nil {
		cancelLookup()
		return err
	}
	name := r.Name
	rec, held, err := sessiondir.Inspect(lookupCtx, stateRoot, name)
	cancelLookup()
	if err != nil {
		return err
	}
	if rec == nil {
		return errNoSession(name)
	}
	// Before anything is sent, for stopSession's reason.
	if !matchesLaunch(r, rec) {
		return replacedNotChanged(r)
	}
	if !held {
		_, err := fmt.Fprintln(out, alreadyEndedLine(name, endedFromRecord(rec)))
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
	// Dialled before anything is sent. The client connects lazily, so a
	// request that failed can't say whether it ever left; a dial that failed
	// can, and then the text can promise that nothing was changed. One budget
	// covers both: a socket that answers the dial answers at once.
	if err := dialAdmin(rpcCtx, adminSocket); err != nil {
		cancelRPC()
		return setFailed(ctx, r, rec, err, false, out)
	}
	// The launch that was inspected, for stopSession's reason: a session that
	// ended between the read and this call hands its name and socket on.
	resp, err := client.SetJoinTimeout(rpcCtx, &api.SetJoinTimeoutRequest{LaunchId: rec.LaunchID, TimeoutNanos: int64(joinTimeout)})
	cancelRPC()
	if err != nil {
		return setFailed(ctx, r, rec, err, true, out)
	}
	return printSetOutcome(out, name, resp)
}

// dialAdmin connects to the admin socket and hangs up, to find out whether
// anything is listening before a request is sent.
func dialAdmin(ctx context.Context, socket string) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// setFailed explains a SetJoinTimeout that got no answer. It reports what
// it has evidence for and nothing more: a request that timed out may have
// taken effect, and an unreachable socket does not mean the session is
// ending -- Unavailable can be transient -- so anything short of evidence is
// "could not confirm", exit 1, never a success.
//
// sent is whether the request left. When it didn't, cause is the dial's error
// and nothing was changed, which is the one thing that tells the two failures
// apart; the record is still read, since the session may have ended or been
// replaced while it was out of reach.
func setFailed(ctx context.Context, r resolved, rec *sessiondir.Record, cause error, sent bool, out io.Writer) error {
	name := r.Name
	// The failure for when nothing settles what became of the request.
	unresolved := func() error {
		logCause(ctx, "the admin socket did not confirm the change", name, cause)
		if !sent {
			return errors.New(isntAnswering(name, rec) + "; nothing was changed")
		}
		return notConfirmed(name)
	}

	if sent {
		switch status.Code(cause) {
		case codes.Unimplemented:
			return fmt.Errorf("session %s was started by an upterm older than 0.32.0 and cannot take a join timeout (%s); upgrading this upterm does not change a running session, so start it again with upterm 0.32.0 or newer", name, pidOf(rec))
		case codes.FailedPrecondition:
			return replacedNotChanged(r)
		case codes.Unavailable:
			// Unreachable: the record may say where the session is.
		default:
			return unresolved()
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	cur, curHeld, err := sessiondir.Inspect(lookupCtx, utils.UptermStateDir(), name)
	cancel()
	switch {
	case err != nil:
		return unresolved()
	case cur == nil:
		return errNoSession(name)
	case cur.LaunchID != rec.LaunchID || !matchesLaunch(r, cur):
		return replacedNotChanged(r)
	case !curHeld:
		// The name was released: the session is over.
		_, err := fmt.Fprintln(out, alreadyEndedLine(name, endedFromRecord(cur)))
		return err
	case cur.Status == sessiondir.StatusEnding:
		_, err := fmt.Fprintf(out, "session %s is ending\n", name)
		return err
	case cur.Status == sessiondir.StatusStarting:
		return fmt.Errorf("session %s is still starting and its admin socket is not up yet (%s); try again in a moment", name, pidOf(cur))
	default:
		return unresolved()
	}
}

// notConfirmed is the failure for a change nobody can vouch for either way.
func notConfirmed(name string) error {
	return fmt.Errorf("couldn't confirm the change to session %s; it may still have taken effect. upterm session info %s shows what it holds", name, name)
}

// isntAnswering is what `session stop` and `session set` say first when a
// held session's admin socket gives them nothing, with the pid so that a
// person can end the process themselves.
func isntAnswering(name string, rec *sessiondir.Record) string {
	return fmt.Sprintf("session %s isn't answering on its admin socket (%s)", name, pidOf(rec))
}

// logCause records what an admin socket said, for --debug. The error a person
// reads has the words that tell them what to do; the transport's own are here.
func logCause(ctx context.Context, msg, name string, cause error) {
	if logger := uptermctx.Logger(ctx); logger != nil {
		logger.Debug(msg, "session", name, "error", cause)
	}
}

// printSetOutcome says what the session did with the request, one line.
func printSetOutcome(out io.Writer, name string, resp *api.SetJoinTimeoutResponse) error {
	st := resp.GetState()
	var err error
	switch resp.GetOutcome() {
	case api.SetJoinTimeoutResponse_COUNTING:
		_, err = fmt.Fprintf(out, "session %s ends at %s unless a guest joins\n", name,
			time.Unix(0, st.GetDeadlineUnixNano()).UTC().Format(time.RFC3339))
	case api.SetJoinTimeoutResponse_PENDING:
		_, err = fmt.Fprintf(out, "session %s: join timeout %s, counting from when the session is ready\n", name,
			shortDuration(time.Duration(st.GetTimeoutNanos())))
	case api.SetJoinTimeoutResponse_DISABLED:
		_, err = fmt.Fprintf(out, "session %s: join timeout disabled\n", name)
	case api.SetJoinTimeoutResponse_CLAIMED:
		_, err = fmt.Fprintf(out, "session %s: a guest joined at %s; automatic join timeout disabled\n", name,
			time.Unix(0, st.GetFirstGuestJoinedUnixNano()).UTC().Format(time.RFC3339))
	case api.SetJoinTimeoutResponse_ENDING:
		_, err = fmt.Fprintf(out, "session %s is ending\n", name)
	default:
		return fmt.Errorf("session %s answered with an outcome this upterm does not know (%v), so the change may have taken effect; 'upterm session info %s' shows what the session holds", name, resp.GetOutcome(), name)
	}
	return err
}

func current() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "current",
		Aliases: []string{"c"},
		Short:   "Show the session this terminal is in",
		Long: `Show the session this terminal is in, from $UPTERM_ADMIN_SOCKET.

upterm host sets $UPTERM_ADMIN_SOCKET for the commands it runs, so a shell
in a session can show it, and a prompt can mark it. --admin-socket asks
another session's admin socket instead.

Output formats:
  -o json                             JSON
  -o go-template='{{.ClientCount}}'   a Go template

Template variables: SessionID, ClientCount (this session's terminals and
guests), GuestCount, CountsKnown, Host, Command, ForceCommand, Access,
ConnectedClients, LaunchID, Open, JoinStateSource, JoinTimeout, JoinDeadline,
FirstGuestJoinedAt, Name, Status, Reconnect, TunnelReason, TunnelLostAt,
NextAttemptAt, StartConfirmed, ReadOnly, FileTransfer,
FileTransferApprovalRequired, LocalForwarding, SSHCommand and JoinCommand.
From LaunchID on, a variable the session's upterm doesn't report is empty,
false, nil or a zero time (0001-01-01 ...), so test it first:
{{with .Name}}{{.}}{{end}}, or {{if not .TunnelLostAt.IsZero}}...{{end}}.

Exits 4 when not in a session ($UPTERM_ADMIN_SOCKET is unset, or no session
answers at it), and 1 for any other failure. With -o, not being in a session
prints nothing.`,
		Example: `  # Show the session this terminal is in:
  upterm session current

  # As JSON:
  upterm session current -o json

  # For a shell prompt (prints nothing outside a session):
  upterm session current -o go-template='🆙 {{.ClientCount}} '

  # For a terminal title, with the session's name when its upterm reports it:
  upterm session current -o go-template='upterm{{with .Name}} {{.}}{{end}}: {{.ClientCount}} clients'`,
		Args: cobra.ExactArgs(0),
		RunE: currentRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagAdminSocket, "admin-socket", "", currentAdminSocketFile(), "Admin socket of the session to show.")
	// The variable, not its value: the help and the generated docs show
	// where the default comes from, never this shell's socket.
	cmd.PersistentFlags().Lookup("admin-socket").DefValue = "$" + upterm.HostAdminSocketEnvVar
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: json or go-template='...'")
	_ = cmd.RegisterFlagCompletionFunc("output", completeValues("json", "go-template="))
	perRun(cmd.Flags(), "output")
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, hideClientIPHelp)

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
	// Checked before anything is read, so a format that cannot be answered
	// fails the same whether or not a session is running.
	if flagListOutput != "" && flagListOutput != "json" {
		return fmt.Errorf("invalid output format %q: must be 'json'", flagListOutput)
	}

	tidySessions(c.Context())

	if flagListOutput == "json" {
		infos, err := listInfos(c.Context(), utils.UptermRuntimeDir(), utils.UptermStateDir())
		if err != nil {
			return err
		}
		return writeSessionsJSON(os.Stdout, infos)
	}

	sessions, err := listSessions(c.Context(), utils.UptermRuntimeDir(), utils.UptermStateDir())
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		// On stderr, so a script that reads the table gets nothing rather than
		// a sentence to skip.
		_, _ = fmt.Fprintln(os.Stderr, "upterm: no sessions are running")
		return nil
	}

	// Only a terminal has a width to fit: a pipe gets every cell whole.
	width := 0
	if tui.IsTTY() {
		width = tui.TermWidth()
	}
	writeSessionTable(os.Stdout, sessionRows(sessions), width)
	return nil
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
	JoinCommand  string `json:"joinCommand,omitempty"`
	// Host is the relay the session was started against, as the daemon
	// reports it (`session current` prints the same value under the same
	// key). Absent unless the daemon answered for this launch.
	Host        string `json:"host,omitempty"`
	ClientCount int    `json:"clientCount"`
	// GuestCount counts currently connected guests, including forwarding but
	// excluding the session's own terminals. Scripts asking whether a terminal
	// or SFTP guest ever joined should use FirstGuestJoinedAt.
	GuestCount int `json:"guestCount"`
	// CountsKnown says whether the two counts came from the daemon. They are
	// counted only for a joinable session whose daemon answered for this
	// launch; otherwise they are 0, and false here is what tells that 0 from
	// a session nobody has joined.
	CountsKnown      bool     `json:"countsKnown"`
	ConnectedClients []string `json:"connectedClients,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	ExitCode         *int     `json:"exitCode,omitempty"`
	Signal           string   `json:"signal,omitempty"`
	SignalNumber     *int     `json:"signalNumber,omitempty"`
	// Open is true when anyone with the session ID can join and nobody was
	// asked: no allowlist, and started with --accept. Absent otherwise.
	Open bool `json:"open,omitempty"`
	// Access is who can join: "anyone" with the session ID, or the
	// "allowlist". It comes from the authorized keys every daemon reports,
	// so it is there whenever the daemon answered for this launch.
	Access string `json:"access,omitempty"`
	// What the host decided at startup, and guests may do: whether the host
	// confirmed the start rather than passing --accept, read-only, which
	// file transfers ("off", "downloads" or "all"), whether each transfer
	// waits for the host's approval, and local port forwarding. Each is the
	// daemon's own optional field, absent when the daemon doesn't report it:
	// unknown, not false. A daemon that reports them reports false as false.
	StartConfirmed               *bool  `json:"startConfirmed,omitempty"`
	ReadOnly                     *bool  `json:"readOnly,omitempty"`
	FileTransfer                 string `json:"fileTransfer,omitempty"`
	FileTransferApprovalRequired *bool  `json:"fileTransferApprovalRequired,omitempty"`
	LocalForwarding              *bool  `json:"localForwarding,omitempty"`
	// FirstGuestJoinedAt is when a terminal or SFTP guest first joined,
	// latched and never moved by a later join; zero and omitted when none
	// ever did. Unlike this timestamp, guestCount includes forwarding
	// presence and misses guests who have already left.
	FirstGuestJoinedAt time.Time `json:"firstGuestJoinedAt,omitzero"`
	// JoinTimeout is the join timeout set on the session, compact and
	// normalised (90m shows as 1h30m); absent when none is set or a guest has
	// joined. JoinDeadline is when the session ends unless a guest joins
	// first; absent unless the timeout is counting, or it was when the
	// session ended.
	JoinTimeout  string    `json:"joinTimeout,omitempty"`
	JoinDeadline time.Time `json:"joinDeadline,omitzero"`
	// JoinStateSource says where those two came from, in every state, empty
	// and claimed included: "daemon" when the daemon answered for this
	// launch, even to say there is no timeout; "record" otherwise. Without
	// it, "no timeout, confirmed" and "a timeout whose write failed, from a
	// daemon that is not answering" would look the same.
	JoinStateSource string `json:"joinStateSource,omitempty"`
	// Reconnect is "supported" or "unsupported", once the first connection
	// has shown which: whether the relay lets a dropped session come back
	// under the same connect string. The tunnel fields describe the current
	// outage, or the last one a session that ended was in: when it began, why
	// the latest attempt failed (a stable code), that attempt's raw error, and
	// when the next attempt is due. They are absent while the tunnel is up.
	Reconnect     string    `json:"reconnect,omitempty"`
	TunnelLostAt  time.Time `json:"tunnelLostAt,omitzero"`
	TunnelReason  string    `json:"tunnelReason,omitempty"`
	TunnelError   string    `json:"tunnelError,omitempty"`
	NextAttemptAt time.Time `json:"nextAttemptAt,omitzero"`
	// joinCaveat is why a held session's join fields came from the record,
	// for the human line; not part of the JSON.
	joinCaveat string
	// notAnswering is true for a held session whose admin socket gave no
	// answer for this launch, so that the human summary can say its status is
	// the record's word; not part of the JSON, which has joinStateSource.
	notAnswering bool
	// nameLabel is what the human summary's Name row says when the name alone
	// would name another session: a session given by ID whose name a later
	// launch holds. Empty otherwise; not part of the JSON, whose name is the
	// name and whose sessionId is the ID.
	nameLabel string
}

// statusEnded is the reader's inference, not a status any session writes:
// sessiondir records what a session published, and "ended" is what a free lock
// means regardless of what the record still says.
const statusEnded = "ended"

// Where a sessionInfo's join fields came from, and why a held session's
// came from the record.
const (
	joinStateFromDaemon = "daemon"
	joinStateFromRecord = "record"

	caveatUnanswered = "the session did not answer"
	caveatUnreported = "the session's upterm does not report it"
)

// lookup reports a resolved session: the one holding its name or, for a
// session given by ID whose name another launch has taken since, that session
// as ended (see goneRecord).
//
// Record and ownership come from one Inspect call, under the registry lock. An
// earlier draft read them separately, which could mix generations — A's record
// with B's ownership — and, more immediately, could dereference a nil record:
// ReadRecord returns not-found, a claim completes, IsHeld returns true.
//
// The daemon is asked for every held record, not only a ready one: its join
// state is what governs the session from the moment the name is claimed. Its
// answer is validated by launch ID -- by session ID only for a daemon from
// before that field -- so an answer from a launch that has since taken the
// name is ignored rather than trusted.
//
// The response is the one this lookup validated, and is nil unless the record
// says ready or reconnecting and the admin socket answered for this launch.
// Handing it back is what stops a caller that wants the full live detail from
// asking again: a second query returns whatever holds the name at that
// instant, which need not be the session the first one confirmed.
func lookup(ctx context.Context, r resolved) (sessionInfo, *api.GetSessionResponse, error) {
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), r.Name)
	if err != nil {
		return sessionInfo{}, nil, err
	}

	if rec == nil {
		// No record at all, held or not: not found within retained history.
		// Checked before either branch uses rec, which is the nil dereference
		// the earlier draft had.
		return sessionInfo{}, nil, errNoSession(r.Name)
	}

	if !matchesLaunch(r, rec) {
		// The session given by ID is over, whatever the record that holds its
		// name now says about the one that took it.
		info := infoFromRecord(goneRecord(r), statusEnded)
		info.nameLabel = r.named(r.Name)
		return info, nil, nil
	}

	if !held {
		// Nobody owns the name. Whatever the record says about status — and
		// after a SIGKILL it frequently says "ready" — this session is over.
		// Only its outcome is still meaningful.
		return infoFromRecord(rec, statusEnded), nil, nil
	}

	return heldInfo(ctx, utils.UptermRuntimeDir(), rec)
}

// heldInfo reports a session whose name is held: what its record says, and,
// when its admin socket answers for the run the record describes, what the
// daemon says too. lookup answers for one name with it, and the listing for
// each of the names it finds, so an element of the listing is the object
// `session info` returns for that session.
//
// The response is nil unless the record says ready or reconnecting and the
// socket answered for this launch: see lookup for why it is handed back.
func heldInfo(ctx context.Context, runtimeRoot string, rec *sessiondir.Record) (sessionInfo, *api.GetSessionResponse, error) {
	// Held: the recorded status is current and refines liveness — starting,
	// ready, reconnecting or disconnected.
	info := infoFromRecord(rec, rec.Status)

	// Where the session answers, published for the caller and used for the
	// dial below. The record's path, not one built under this process's
	// runtime root: see adminSocketFor.
	adminSocket, err := adminSocketFor(runtimeRoot, rec)
	if err != nil {
		return sessionInfo{}, nil, err
	}
	info.AdminSocket = adminSocket
	// And where a terminal would attach, which is the record's path for the
	// same reason. Empty for a record written before attach sockets existed,
	// and omitted from the JSON rather than published as a path nothing is
	// bound at.
	info.AttachSocket = rec.AttachSocket

	// Ask the daemon about any held session whose socket answers -- starting
	// once the socket is up, ready, reconnecting, disconnected -- so the join
	// timeout shown is the one the daemon enforces, not the last record
	// write. A socket that does not answer, or answers for another launch,
	// leaves the record's view, which JoinStateSource says.
	sess, err := session(ctx, adminSocket)
	if err != nil || !sameLaunch(rec, sess) {
		info.joinCaveat = caveatUnanswered
		info.notAnswering = true
		return info, nil, nil
	}
	info = withLiveJoinState(info, sess)
	info = withSessionReport(info, sess)

	// Only ready and reconnecting say the connect string is one anyone can
	// act on: a reconnecting session comes back under the same one. After a
	// tunnel loss the relay can't recover from, the host keeps its admin
	// server running with a connect string that cannot connect, so a
	// disconnected session gets its join state from the daemon and nothing
	// that would advertise it as joinable.
	if !joinable(rec.Status) {
		return info, nil, nil
	}
	return withLiveDetail(info, sess), sess, nil
}

// joinable reports whether a session with this status has a connect string
// worth showing: the tunnel is up, or is being redialled and will carry guests
// again under the same one.
func joinable(status string) bool {
	return status == sessiondir.StatusReady || status == sessiondir.StatusReconnecting
}

// sameLaunch reports whether sess answered for the run rec describes: between
// Inspect and the query the session could have ended and a replacement
// claimed the name. A daemon that publishes its launch is checked by launch;
// one from before that field by session ID, which a record carries from the
// moment readiness is published, whatever the tunnel is doing then or later
// (ready, reconnecting or disconnected), and not before, as lookup always did.
func sameLaunch(rec *sessiondir.Record, sess *api.GetSessionResponse) bool {
	if id := sess.GetLaunchId(); id != "" {
		return id == rec.LaunchID
	}
	return rec.SessionID != "" && sess.GetSessionId() == rec.SessionID
}

// withLiveJoinState takes the join fields from the daemon's memory. A daemon
// from before join state reports none, and the record's view stands, saying
// why.
func withLiveJoinState(info sessionInfo, sess *api.GetSessionResponse) sessionInfo {
	js := sess.GetJoinState()
	if js == nil {
		info.joinCaveat = caveatUnreported
		return info
	}
	info.JoinTimeout = ""
	if js.GetTimeoutNanos() > 0 {
		info.JoinTimeout = shortDuration(time.Duration(js.GetTimeoutNanos()))
	}
	info.JoinDeadline = time.Time{}
	if js.GetDeadlineUnixNano() != 0 {
		info.JoinDeadline = time.Unix(0, js.GetDeadlineUnixNano()).UTC()
	}
	if js.GetFirstGuestJoinedUnixNano() != 0 && info.FirstGuestJoinedAt.IsZero() {
		info.FirstGuestJoinedAt = time.Unix(0, js.GetFirstGuestJoinedUnixNano()).UTC()
	}
	info = withClaimRule(info)
	info.JoinStateSource = joinStateFromDaemon
	info.joinCaveat = ""
	return info
}

// withSessionReport adds what the daemon's answer says about the session as a
// whole, true whatever its tunnel is doing: the relay it was started against,
// who can join, and what guests may do. The last are the daemon's optional
// fields, each taken only when it is there, so a daemon from before them
// leaves them unknown rather than false.
func withSessionReport(info sessionInfo, sess *api.GetSessionResponse) sessionInfo {
	info.Host = sess.GetHost()
	info.Access = accessOf(sess.GetAuthorizedKeys())
	info.StartConfirmed = sess.StartConfirmed
	info.ReadOnly = sess.ReadOnly
	info.FileTransfer = sess.GetFileTransfer()
	info.FileTransferApprovalRequired = sess.FileTransferApprovalRequired
	info.LocalForwarding = sess.LocalForwarding
	return info
}

// accessOf is who can join a session with these authorized keys: anyone with
// the session ID when there are none, else the allowlist.
func accessOf(keys []*api.AuthorizedKey) string {
	if len(keys) == 0 {
		return tui.AccessAnyone
	}
	return tui.AccessAllowlist
}

// infoFromRecord reports what the record knows, under the status the caller
// has decided on. Its times are given in UTC, whatever zone the record was
// written in: the supervisor writes the tunnel's in local time.
func infoFromRecord(rec *sessiondir.Record, status string) sessionInfo {
	info := sessionInfo{
		Name:               rec.Name,
		LaunchID:           rec.LaunchID,
		Status:             status,
		SessionID:          rec.SessionID,
		Command:            strings.Join(rec.Command, " "),
		ForceCommand:       strings.Join(rec.ForceCommand, " "),
		LogPath:            rec.LogPath,
		Pid:                rec.Pid,
		Reason:             rec.Reason,
		ExitCode:           rec.ExitCode,
		Signal:             rec.Signal,
		SignalNumber:       rec.SignalNumber,
		FirstGuestJoinedAt: rec.FirstGuestJoinedAt.UTC(),
	}
	info = withRecordedTunnel(info, rec)
	if rec.JoinTimeout > 0 {
		info.JoinTimeout = shortDuration(rec.JoinTimeout)
	}
	info.JoinDeadline = rec.JoinDeadline.UTC()
	info = withClaimRule(info)
	info.JoinStateSource = joinStateFromRecord
	return info
}

// withRecordedTunnel adds the record's account of the tunnel: whether the
// relay reconnects, and the outage it is in or was in when it ended. Times
// in UTC; a zero time stays zero, and is left out of the JSON.
func withRecordedTunnel(info sessionInfo, rec *sessiondir.Record) sessionInfo {
	info.Reconnect = rec.Reconnect
	info.TunnelLostAt = rec.TunnelLostAt.UTC()
	info.TunnelReason = rec.TunnelReason
	info.TunnelError = rec.TunnelError
	info.NextAttemptAt = rec.NextAttemptAt.UTC()
	return info
}

// withClaimRule drops the join timeout from a session a guest has joined:
// joining claims it for good, so a deadline beside a join is stale, whatever
// the last write said.
func withClaimRule(info sessionInfo) sessionInfo {
	if !info.FirstGuestJoinedAt.IsZero() {
		info.JoinTimeout = ""
		info.JoinDeadline = time.Time{}
	}
	return info
}

// retentionText is a retention period as a person says it: in days when it is
// a whole number of them, since 168h0m0s is a week to nobody.
func retentionText(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == day:
		return "1 day"
	case d > 0 && d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	}
	return shortDuration(d)
}

// shortDuration writes d compact and normalised: Go's duration syntax
// without zero units, so 10m rather than 10m0s, 90m as 1h30m, and 1h0m30s as
// 1h30s. The result still parses as a --join-timeout value.
func shortDuration(d time.Duration) string {
	// Go writes minutes whenever there are hours, and seconds whenever there
	// are minutes, so zero minutes are always "h0m" and zero seconds a
	// trailing "0s" after "m" -- or after "h", once the minutes are gone.
	s := strings.Replace(d.String(), "h0m", "h", 1)
	if strings.HasSuffix(s, "m0s") || strings.HasSuffix(s, "h0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	return s
}

// absTime is t in the reader's local time with its date and zone, for
// deadlines and events in the past: a time of day alone doesn't say which day
// or where. The zone is always named. Go writes UTC for UTC, the zone
// database's abbreviation for any other, and the offset ("-0700") for a zone
// that has no abbreviation, as on a machine without a zone database.
func absTime(at time.Time) string {
	return absTimeIn(at, time.Local)
}

func absTimeIn(at time.Time, loc *time.Location) string {
	return at.In(loc).Format("2006-01-02 15:04:05 MST")
}

// joinTimeoutRow says what happened to the session's join timeout, not only
// what is set: a claimed session and one with no timeout would otherwise
// print the same nothing, and a held session shown from the record says so
// and why. An ended session's history is only as good as its last write -- a
// crash can leave a pending snapshot after counting began -- so only
// join_timeout, the outcome the session recorded itself, is stated as fact.
//
// It returns the row's label and its value, empty when there is nothing to say.
func joinTimeoutRow(info sessionInfo) (label, value string) {
	return joinTimeoutRowIn(info, time.Local)
}

func joinTimeoutRowIn(info sessionInfo, loc *time.Location) (label, value string) {
	if !info.FirstGuestJoinedAt.IsZero() {
		return "Join timeout:", "disabled (guest joined at " + absTimeIn(info.FirstGuestJoinedAt, loc) + ")"
	}
	if info.Status == statusEnded {
		switch {
		case info.Reason == sessiondir.ReasonJoinTimeout && !info.JoinDeadline.IsZero():
			return "Join timeout:", "fired at " + absTimeIn(info.JoinDeadline, loc)
		case !info.JoinDeadline.IsZero():
			return "Join deadline:", absTimeIn(info.JoinDeadline, loc) + " (last recorded before the session ended)"
		case info.JoinTimeout != "":
			return "Join timeout:", info.JoinTimeout + " (last recorded before the session ended)"
		default:
			return "", ""
		}
	}
	switch {
	case !info.JoinDeadline.IsZero():
		label, value = "Join deadline:", absTimeIn(info.JoinDeadline, loc)
	case info.JoinTimeout != "":
		label, value = "Join timeout:", info.JoinTimeout+" (counts from readiness)"
	case info.JoinStateSource == joinStateFromRecord:
		label, value = "Join timeout:", "none recorded"
	default:
		return "", "" // the daemon confirms there is none
	}
	if info.JoinStateSource == joinStateFromRecord {
		caveat := info.joinCaveat
		if caveat == "" {
			caveat = caveatUnanswered
		}
		value += " (from the record; " + caveat + ")"
	}
	return label, value
}

// withLiveDetail adds what only a running session can answer: who is connected
// and how to join them.
//
// Everything but the connect strings is the daemon's answer as it stands, so it
// is taken whether or not the relay's URL parses. A URL that does not is a
// reason to leave out the commands built from it, not the clients the daemon
// listed: a count of none beside countsKnown false would say the daemon had
// not answered, when it had.
func withLiveDetail(info sessionInfo, sess *api.GetSessionResponse) sessionInfo {
	info.Command = strings.Join(sess.GetCommand(), " ")
	info.ForceCommand = strings.Join(sess.GetForceCommand(), " ")
	for _, c := range sess.GetConnectedClients() {
		info.ConnectedClients = append(info.ConnectedClients, clientDesc(c))
	}
	info.ClientCount = len(sess.GetConnectedClients())
	info.GuestCount = countGuests(sess.GetConnectedClients())
	info.CountsKnown = true
	info.Open = sess.GetOpen()

	if detail, err := buildSessionDetail(sess); err == nil {
		info.SSHCommand = detail.SSHCommand
		info.JoinCommand = detail.JoinCommand
	}
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
	// Checked before anything is read, so a format that cannot be answered
	// fails the same whether or not the session exists.
	if flagOutput != "" && flagOutput != "json" {
		return fmt.Errorf("invalid output format %q: must be 'json'", flagOutput)
	}

	// One deadline for the whole lookup, which waits on the registry and then
	// on the admin socket: budgeting them separately would let a name that is
	// slow twice take twice as long.
	ctx, cancel := context.WithTimeout(c.Context(), sessionQueryTimeout)
	defer cancel()

	r, err := resolveSession(ctx, args[0])
	if err != nil {
		return err
	}
	info, live, err := lookup(ctx, r)
	if err != nil {
		return err
	}

	if flagOutput == "json" {
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
			detail.Name = r.Name
			// The status the lookup settled on, which the socket's answer does
			// not carry: the summary below prints one for a session that has
			// ended, and `session list` prints one for every row, so the one
			// case that answered "how is NAME?" without saying was this one.
			detail.Status = info.Status
			// And the path the lookup dialled, which is the record's. Built
			// again here it would come out under this process's runtime root
			// and disagree with the socket that just answered.
			detail.AdminSocket = info.AdminSocket
			// And the tunnel's state, which is the record's too.
			detail = withTunnelState(detail, info)
			detail.JoinLabel, detail.JoinValue = joinTimeoutRow(info)
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
	// On a terminal the sentences wrap to what is left of the line after the
	// label. Elsewhere the output may be piped to other tools, so each row
	// stays one line.
	valueWidth := 0
	if tui.IsTTY() {
		valueWidth = tui.TermWidth() - tui.LabelWidth
	}
	writeSessionSummary(os.Stdout, info, valueWidth)
}

// writeSessionSummary writes the summary's rows to w, in the view's label
// column so that the two read as one layout. The status, hint and join row
// are sentences, so they wrap to valueWidth at spaces, with continuation lines
// indented under the value; a valueWidth of 0 leaves them on one line.
func writeSessionSummary(w io.Writer, info sessionInfo, valueWidth int) {
	// The status, hint and relay note are the detail view's, so the two never
	// word the same outage differently.
	detail := withTunnelState(tui.SessionDetail{Status: info.Status}, info)

	name := info.Name
	if info.nameLabel != "" {
		name = info.nameLabel
	}
	writeSummaryRow(w, "Name:", name, 0)
	status := tui.StatusText(detail)
	if info.notAnswering && info.Status == sessiondir.StatusReady {
		// The record says ready, and the session was asked and said nothing:
		// without this the row reads as the session's own word.
		status += " (not answering)"
	}
	writeSummaryRow(w, "Status:", status, valueWidth)
	if hint := tui.StatusHint(detail); hint != "" {
		writeSummaryRow(w, "Hint:", hint, valueWidth)
	}
	if note := tui.ReconnectNote(detail); note != "" {
		writeSummaryRow(w, "Reconnect:", note, 0)
	}
	// Only a session that has ended has an outcome. Until then the record
	// holds the placeholder it was claimed with, and publishing that teardown
	// has begun leaves it there, so a reason before the end reads as one
	// nobody recorded.
	if info.Reason != "" && info.Status == statusEnded {
		writeSummaryRow(w, "Reason:", info.Reason, 0)
	}
	if info.ExitCode != nil {
		writeSummaryRow(w, "Exit code:", strconv.Itoa(*info.ExitCode), 0)
	}
	if info.Signal != "" {
		writeSummaryRow(w, "Signal:", info.Signal, 0)
	}
	if label, value := joinTimeoutRow(info); label != "" {
		writeSummaryRow(w, label, value, valueWidth)
	}
}

// writeSummaryRow writes a label and a sentence, wrapped to valueWidth with
// continuation lines indented to the label column. A valueWidth of 0 writes
// the sentence as it is.
func writeSummaryRow(w io.Writer, label, value string, valueWidth int) {
	lines := []string{value}
	if valueWidth > 0 {
		lines = tui.WrapProse(value, valueWidth)
	}
	for i, line := range lines {
		if i == 0 {
			_, _ = fmt.Fprintf(w, "%-*s%s\n", tui.LabelWidth, label, line)
		} else {
			_, _ = fmt.Fprintf(w, "%*s%s\n", tui.LabelWidth, "", line)
		}
	}
}

// withTunnelState gives detail the record's account of the tunnel, which a
// socket's answer does not carry, as the lookup read it.
func withTunnelState(detail tui.SessionDetail, info sessionInfo) tui.SessionDetail {
	detail.Reconnect = info.Reconnect
	detail.TunnelReason = info.TunnelReason
	detail.TunnelLostAt = info.TunnelLostAt
	detail.NextAttemptAt = info.NextAttemptAt
	return detail
}

// currentRunE tells "not in a session" apart from every other failure, because
// the way this command is used turns on it. A shell prompt calls it on every
// redraw, in and out of a session, and has to learn which from the status
// alone; printing the usage and the error twice for the common case, as it
// once did, is thirty lines on every prompt outside a session.
func currentRunE(c *cobra.Command, args []string) error {
	// The format is checked before the socket, so that a typo in a prompt's
	// config is reported outside a session too. Behind the quiet path it would
	// go unnoticed for as long as nobody happened to be sharing.
	quiet := flagOutput != ""
	var render func(io.Writer, *api.GetSessionResponse) error
	if quiet {
		var err error
		render, err = sessionOutput(flagOutput)
		if err != nil {
			return ExitCodeError{Code: 1, Err: err}
		}
	}

	if flagAdminSocket == "" {
		// The flag was given, and empty: the variable, if set, isn't what
		// is wrong here.
		if c.Flags().Changed("admin-socket") {
			return notInSession(quiet, "--admin-socket is empty")
		}
		return notInSession(quiet, "$UPTERM_ADMIN_SOCKET is not set")
	}

	// One deadline for the query. A host that was stopped rather than killed
	// accepts the connection and then never answers on it — which for the
	// shell-prompt use this command exists for means a prompt that never
	// returns.
	ctx, cancel := context.WithTimeout(c.Context(), sessionQueryTimeout)
	defer cancel()

	sess, err := session(ctx, flagAdminSocket)
	if err != nil {
		// Unavailable is the transport saying nobody is listening: a socket
		// path that does not exist, or a file a killed host left behind. The
		// host never answers with it itself. Here that reads as "no session
		// answers there", where `session set` has to treat it as possibly
		// transient because it acts on the answer: this is a read-only query,
		// so a misread costs one prompt without its badge.
		if status.Code(err) == codes.Unavailable {
			// The cause stays out of what a prompt prints, so --debug is
			// where to find why.
			if logger := uptermctx.Logger(ctx); logger != nil {
				logger.Debug("no session answers at the admin socket", "socket", flagAdminSocket, "error", err)
			}
			return notInSession(quiet, "no session answers at "+flagAdminSocket)
		}
		// Any other failure is "could not ask", and the bare gRPC status does not
		// say which socket it was, so it is named here for both modes.
		return ExitCodeError{Code: 1, Err: fmt.Errorf("failed to get session at %s: %w", flagAdminSocket, err)}
	}

	if render != nil {
		if err := render(os.Stdout, sess); err != nil {
			return ExitCodeError{Code: 1, Err: err}
		}
		return nil
	}

	detail, err := buildSessionDetail(sess)
	if err != nil {
		return ExitCodeError{Code: 1, Err: err}
	}

	tui.PrintSessionDetail(withReportedState(detail, sess))
	return nil
}

// withReportedState adds to detail what the daemon says of itself: its name,
// and, once the session isn't ready, its status and the outage behind it, and
// it takes the connect strings away where guests can't use them. All of it is
// the daemon's own answer and never a record's, since this command works from
// the socket alone; a daemon that sends none of it leaves the view as it was.
// A ready session has no status row, as before, but a relay that can't bring a
// dropped session back is said at every status.
func withReportedState(detail tui.SessionDetail, sess *api.GetSessionResponse) tui.SessionDetail {
	detail.Name = sess.GetName()
	detail.Reconnect = sess.GetReconnect()
	st := sess.GetStatus()
	// Where guests can't use a connect string, none is shown, as in
	// `session info` and the JSON. A daemon that reports no status doesn't
	// say, and keeps its lines.
	if st != "" && !joinable(st) {
		detail.JoinCommand, detail.SSHCommand = "", ""
		detail.SFTPEnabled, detail.SFTPCommand, detail.SCPUpload, detail.SCPDownload = false, "", "", ""
	}
	if st != "" && st != sessiondir.StatusReady {
		detail.Status = st
		detail.TunnelReason = sess.GetTunnelReason()
		detail.TunnelLostAt = unixNanoUTC(sess.GetTunnelLostAtUnixNano())
		detail.NextAttemptAt = unixNanoUTC(sess.GetNextAttemptAtUnixNano())
	}
	return detail
}

// notInSession is the answer to "is there a session here" when there is not
// one: notFoundCode, as `session info`, `session stop` and `session set` give
// for a name nobody holds. With -o it says nothing at all, which is what a
// prompt that renders the output wants to show; otherwise it is one line for a
// person, and why.
func notInSession(quiet bool, why string) error {
	if quiet {
		// A bare ExitCodeError, as `session wait` returns one: Exit prints
		// nothing for it, where an Err would be printed.
		return ExitCodeError{Code: notFoundCode}
	}
	return ExitCodeError{Code: notFoundCode, Err: errors.New("not in an upterm session: " + why)}
}

// sessionOutput builds the renderer for -o/--output, or the error that says why
// the format or the template is not one. It runs before any socket work so
// that a malformed format is reported the same wherever the command is run.
func sessionOutput(format string) (func(io.Writer, *api.GetSessionResponse) error, error) {
	if format != "json" && !strings.HasPrefix(format, "go-template=") {
		return nil, fmt.Errorf("invalid output format %q: must be 'json' or 'go-template=<template>'", format)
	}

	if format == "json" {
		return func(w io.Writer, sess *api.GetSessionResponse) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(currentInfoFrom(sess))
		}, nil
	}

	tmplStr := strings.TrimPrefix(format, "go-template=")
	// Remove surrounding quotes if present
	tmplStr = strings.Trim(tmplStr, "'\"")

	tmpl, err := template.New("session").Parse(tmplStr)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}

	return func(w io.Writer, sess *api.GetSessionResponse) error {
		return tmpl.Execute(w, currentInfoFrom(sess))
	}, nil
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

		// The tunnel is the record's to describe, in the row built from the
		// record alone and in the one a socket refined alike, so the detail
		// view of either says why a session is down.
		detail.Reconnect = rec.Reconnect
		detail.TunnelReason = rec.TunnelReason
		detail.TunnelLostAt = rec.TunnelLostAt
		detail.NextAttemptAt = rec.NextAttemptAt

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

	// And a session that has one but is neither ready nor reconnecting is not
	// joinable, whatever its socket says: the tunnel-loss path keeps the admin
	// server up, so a disconnected session answers with a connect string
	// nobody can use. The same gate `session info` keeps in front of its dial.
	if !joinable(rec.Status) {
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
		port = defaultPort(u.Scheme)
	}

	return
}

// defaultPort is the port a relay URL of the scheme means when it names none:
// ssh 22, ws 80, wss 443. It is empty for any other scheme.
func defaultPort(scheme string) string {
	switch scheme {
	case "ssh":
		return "22"
	case "ws":
		return "80"
	case "wss":
		return "443"
	}
	return ""
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

	// The Relay row leaves out the port only when it is the scheme's own, so a
	// wss relay on 80 or an ssh relay on 443 still says which port it is on.
	// The commands below keep the port whatever it is: a guest has to dial it.
	// net.JoinHostPort puts an IPv6 relay's brackets back (ssh://[::1]:2222),
	// and they stay when the port is then left out. It is given u.Hostname,
	// the address without brackets, because host keeps them for a URL that
	// names no port.
	relay := u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
	if port == "" || port == defaultPort(scheme) {
		relay = strings.TrimSuffix(relay, ":"+port)
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
		clients = append(clients, clientDesc(c))
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
		Host:             relay,
		JoinCommand:      joinCommand(u, user, host, port),
		SSHCommand:       sshCmd,
		SFTPEnabled:      sftpEnabled,
		SFTPCommand:      sftpCmd,
		SCPUpload:        scpUpload,
		SCPDownload:      scpDownload,
		AuthorizedKeys:   displayAuthorizedKeys(sess.AuthorizedKeys),
		ConnectedClients: clients,
		Open:             sess.GetOpen(),
		Access:           accessOf(sess.AuthorizedKeys),
		Guests:           guestPermissions(sess),
	}, nil
}

// guestPermissions is what guests may do, as the daemon reports it, or nil when
// it doesn't. A daemon that reports permissions sets all five of their fields
// together, so a response missing any one is an older daemon's: those fields
// are unknown, not false, and a row built from them would tell guests they
// can't do what nobody said they can't. A file_transfer value this version
// doesn't know is left unreported too, rather than guessed at.
func guestPermissions(sess *api.GetSessionResponse) *tui.GuestPermissions {
	if sess.StartConfirmed == nil || sess.ReadOnly == nil || sess.FileTransfer == nil ||
		sess.FileTransferApprovalRequired == nil || sess.LocalForwarding == nil {
		return nil
	}
	switch sess.GetFileTransfer() {
	case tui.FileTransferOff, tui.FileTransferDownloads, tui.FileTransferAll:
	default:
		return nil
	}
	return &tui.GuestPermissions{
		ReadOnly:         sess.GetReadOnly(),
		FileTransfer:     sess.GetFileTransfer(),
		ApprovalRequired: sess.GetFileTransferApprovalRequired(),
		LocalForwarding:  sess.GetLocalForwarding(),
	}
}

// joinCommand is the `upterm join` line for relay u, with the user, host and
// port parseURL and the ssh line use: the scheme's default port left out and
// an IPv6 literal in brackets, as join.Target.Relay writes them, its zone
// escaped as a URL's. It is empty when u has a path, a query or a fragment,
// which join doesn't take (the ssh line reaches such a relay through upterm
// proxy), and when join refuses the URL.
//
// The URL is quoted only when a shell would read it as something else: zsh
// aborts on an unquoted [::1] as a glob that matches nothing. Double quotes,
// because cmd.exe passes single quotes through, unless the URL holds a
// character that sh, PowerShell or fish would expand inside them.
func joinCommand(u *url.URL, user, host, port string) string {
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ""
	}
	// parseURL's missing-port branch leaves an IPv6 literal in its brackets.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	in := join.Target{Scheme: u.Scheme, User: user, Host: net.JoinHostPort(host, port)}.URL()
	t, err := join.ParseTarget(in.String())
	if err != nil {
		return ""
	}
	out := t.URL()
	out.Host = t.Relay()
	target := out.String()
	switch {
	case !strings.ContainsFunc(target, func(r rune) bool { return !strings.ContainsRune(shellSafe, r) }):
	case strings.ContainsAny(target, "$`\"\\!"):
		target = quoteShellArg(target)
	default:
		target = `"` + target + `"`
	}
	return "upterm join " + target
}

// shellSafe holds the characters the join URL may hold unquoted. sh, bash and
// zsh take each literally there, with one exception: zsh with the non-default
// MAGIC_EQUAL_SUBST expands the text after an '=' as an assignment's value, so
// a user's "==" base64 padding fails there as a command lookup, as it does on
// the ssh line.
const shellSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@:/._=+-"

func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// clientDesc describes one connected client, starting with the door it came
// in by. A session's own terminals are clients of it now, and a line that did
// not say which was which would show an operator a stranger where their own
// window is.
//
// A jump ends with where it goes. Its destinations say as much about the
// host's network as an address says about the guest, so they are hidden
// whenever addresses are.
func clientDesc(c *api.Client) string {
	hide := shouldHideClientIP()
	addr := c.GetAddr()
	if hide {
		addr = "[redacted]"
	}
	desc := fmt.Sprintf("%s %s %s %s", kindName(c.GetKind()), addr, c.GetVersion(), c.GetPublicKeyFingerprint())
	if c.GetKind() != api.Client_FORWARD || len(c.GetForwardDestinations()) == 0 {
		return desc
	}
	if hide {
		return desc + " → [redacted]"
	}
	desc += " → " + strings.Join(c.GetForwardDestinations(), ", ")
	// A count of forwards, not of destinations: past the list's bound the
	// host stops remembering where they went, which is what bounds it.
	if n := c.GetUnlistedForwards(); n > 0 {
		desc += fmt.Sprintf(" (+%d more forwards)", n)
	}
	return desc
}

// kindName names a client's door for a person reading it. The proto's own
// String() shouts (GUEST, HOST) and is a wire detail; these are the words the
// README and `session info` use. A jump came in by the guest door, but it
// reached past the session rather than into it.
func kindName(k api.Client_Kind) string {
	switch k {
	case api.Client_HOST:
		return "host"
	case api.Client_FORWARD:
		return "jump"
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
