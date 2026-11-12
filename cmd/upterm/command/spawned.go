package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type spawnFunc func(spawnOptions) (net.Conn, *os.Process, error)

// clientFunc attaches the local terminal to the attach socket, pinned to
// keys. src is the session the terminal's ~? reports on.
type clientFunc func(ctx context.Context, socket string, keys []ssh.PublicKey, src statusSource) (attach.Result, error)

type displayFunc func(ctx context.Context, sess *api.GetSessionResponse, name string) error

// defaultStartedWaitTimeout bounds how long a foreground parent whose terminal has
// already left waits to be told whether the command started. The daemon's
// own gate is DefaultInitialClientTimeout (10 s), after which it reports
// abandonment itself; this is that plus a margin.
const defaultStartedWaitTimeout = 15 * time.Second

// spawnedSession is upterm host as the process that starts a session: it
// spawns the daemon, runs the exchange, and then either attaches its
// terminal (foreground) or prints and leaves (--detach).
type spawnedSession struct {
	// handoff is the encoded handoff of a delegated run, the session process
	// is started with; "" for an ordinary run.
	handoff string
	name    string
	detach  bool
	jsonOut bool
	logPath string

	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	readSecret func(prompt string) ([]byte, error)

	spawn        spawnFunc
	display      displayFunc // shows the session and reports the operator's decision
	attachClient clientFunc  // nil with --detach
	logger       *slog.Logger
	logWarning   *logWarning // the run's, shared by every spawn in it
	logOff       bool        // the spawn couldn't open logPath

	// keyHint is what a foreground session says once it has started, after
	// the banner, on hintOut; "" says nothing. A detached session never says
	// it: there is no terminal attached to press the keys in.
	keyHint string
	hintOut io.Writer

	// Non-positive waits use the production defaults.
	startedWaitTimeout      time.Duration
	localClientDrainTimeout time.Duration
}

func (s *spawnedSession) waits() (started, drain time.Duration) {
	started, drain = s.startedWaitTimeout, s.localClientDrainTimeout
	if started <= 0 {
		started = defaultStartedWaitTimeout
	}
	if drain <= 0 {
		drain = defaultLocalClientDrainTimeout
	}
	return started, drain
}

// loggedTo is the log the daemon's output went to, or "" when the spawn
// couldn't open it.
func (s *spawnedSession) loggedTo() string {
	if s.logOff {
		return ""
	}
	return s.logPath
}

// seeLog is a line's pointer to the log, format with logPath in it, or
// nothing when there is no log to point at (logPath is "").
func seeLog(format, logPath string) string {
	if logPath == "" {
		return ""
	}
	return fmt.Sprintf(format, logPath)
}

type clientOutcome struct {
	res attach.Result
	err error // non-nil: never attached
}

func (s *spawnedSession) run(ctx context.Context) error {
	return s.runWithDetachContext(ctx, notifyDetachSignals)
}

func (s *spawnedSession) runWithDetachContext(ctx context.Context, notify func(context.Context) (context.Context, context.CancelFunc)) error {
	verdictWait, drainWait := s.waits()

	// A log the spawn can't open is warned about, and the daemon starts
	// without it: nothing of this session is in it to point at.
	conn, _, err := s.spawn(spawnOptions{name: s.name, handoff: s.handoff, logPath: s.logPath, logOff: func(err error) {
		s.logOff = true
		s.logWarning.warn(s.logPath, err)
	}})
	if err != nil {
		if _, statErr := os.Stat(s.logPath); statErr == nil {
			return fmt.Errorf("could not start the session daemon: %w%s", err, seeLog(" (see %s)", s.loggedTo()))
		}
		return fmt.Errorf("could not start the session daemon: %w", err)
	}
	parent := bootstrap.NewParent(conn, s.stdin, s.stderr, s.readSecret)
	defer func() { _ = parent.Close() }()

	var (
		claimed    *api.Claimed
		created    *api.GetSessionResponse
		displayErr error
		clientDone chan clientOutcome
		closedByUs atomic.Bool
	)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	// Atomic because the client's goroutine arms it and this one stops it:
	// the two are concurrent by construction, since the whole point of the
	// timer is to bound a wait that outlives the client.
	var verdictTimer atomic.Pointer[time.Timer]
	defer func() {
		if t := verdictTimer.Load(); t != nil {
			t.Stop()
		}
	}()

	// The attach client's cancel, held where the tail can reach it:
	// cancelling is how a client that will not come back on its own is made
	// to, and the handler that created it returned long before.
	var clientCancel atomic.Pointer[context.CancelFunc]
	cancelClientNow := func() {
		if c := clientCancel.Load(); c != nil {
			(*c)()
		}
	}
	// Every way out from listening onwards waits for the client, because the
	// client is what holds the terminal: attachLocalTerminal restores raw
	// mode only when its own callback returns, so returning here while the
	// client is still inside it exits with the operator's terminal raw. A
	// startup that fails after the gate opened is the ordinary way in —
	// `upterm host -- /no/such/binary` attaches, the gate opens, the exec
	// fails, and the daemon reports failed microseconds later.
	//
	// Deferred rather than written out before each return, so no path out
	// can skip it. A path that takes the outcome for itself nils the channel
	// afterwards, so this defer finds nothing left to drain.
	defer func() {
		if clientDone == nil {
			return
		}
		_ = s.drainClient(clientDone, cancelClientNow, drainWait)
	}()

	handlers := bootstrap.Handlers{
		Claimed: func(c *api.Claimed) { claimed = c },
		SessionCreated: func(sess *api.GetSessionResponse) api.Accept_Decision {
			created = sess
			displayErr = s.display(ctx, sess, s.name)
			// The attach client is about to take the terminal, and stderr is
			// that terminal: hintOut, where whoever is at the keyboard is
			// told things, is stderr exactly when stderr is a terminal.
			stderrHandedOver := displayErr == nil && !s.detach && s.attachClient != nil && s.hintOut == s.stderr
			// Nobody joins a delegated session with its ID, whatever the
			// answer says: its authority decides its guests.
			if displayErr == nil && sess.GetOpen() && !isDelegated(sess, nil) {
				// On stderr whatever the display was, the banner or nothing at
				// all: stdout may be the JSON a script is reading.
				//
				// On a stderr about to be handed over, the warning is written
				// as the key hint is, and for the same reason, whether or not
				// there is a hint to say: with --escape-char none there is
				// none, and the client takes the terminal all the same.
				// Anywhere else stderr may be a pipe nobody drains, and nothing
				// takes the terminal after it, so the write keeps its bound
				// rather than hold the session.
				warning := openSessionWarningFor(sess)
				if stderrHandedOver {
					_, _ = io.WriteString(s.stderr, warning+"\n")
				} else {
					logging.WriteWithin(s.stderr, logging.LogBound, warning+"\n")
				}
			}
			if displayErr == nil && !s.detach && s.keyHint != "" {
				// Last, so it is the line nearest the session it is about,
				// and said once: the attached terminal is the session's from
				// here, and nothing more is written into it unasked.
				//
				// Synchronously, as the banner is on a terminal, which is the
				// only place the hint is said: a terminal drains itself, and
				// the write returns before the accept that starts the attach
				// client. A write given up on at a bound would go on in the
				// background and could land, once a stopped terminal resumed,
				// amid the session's output, outside the output's turns and
				// unseen by its mode tracker.
				_, _ = io.WriteString(s.hintOut, s.keyHint+"\n")
			}
			switch {
			case displayErr == nil:
				return api.Accept_ACCEPTED
			case errors.As(displayErr, new(UserDiscardedError)):
				return api.Accept_DECLINED
			default:
				return api.Accept_INTERRUPTED
			}
		},
		Listening: func(l *api.Listening) {
			if s.detach || s.attachClient == nil {
				return
			}
			keys, err := parseHostKeys(l.HostKeys)
			// done, not the clientDone variable, is what the goroutine
			// below writes to: the tail nils clientDone once it has taken
			// the outcome, and a goroutine reading it would be racing that.
			done := make(chan clientOutcome, 1)
			clientDone = done
			if err != nil {
				done <- clientOutcome{err: err}
				closedByUs.Store(true)
				_ = parent.Close()
				return
			}
			// The launch this process started, which ~? checks what it reads
			// against: the name can pass to another launch while this
			// terminal is attached. Taken here, on the handlers' goroutine,
			// which is the one Claimed wrote it on.
			src := statusSource{Name: s.name}
			if claimed != nil {
				src.LaunchID, src.AdminSocket = claimed.LaunchId, claimed.AdminSocket
			}
			// From here a signal is a detach, exactly as it is for upterm
			// attach; before here the default disposition ends this process,
			// which closes the channel, which is abandonment.
			clientCtx, cancelClient := notify(ctx)
			clientCancel.Store(&cancelClient)
			go func() {
				defer cancelClient()
				res, err := s.attachClient(clientCtx, l.AttachSocket, keys, src)
				if err == nil {
					// Attached and gone. If the command has not started yet
					// the daemon still owes a verdict; wait for it, bounded.
					//
					// Armed before the outcome is delivered, so the deferred
					// Stop — which runs after the drain that receives it —
					// cannot miss a timer armed a moment too late.
					verdictTimer.Store(time.AfterFunc(verdictWait, cancelRun))
				}
				done <- clientOutcome{res: res, err: err}
				if err != nil {
					// Never attached: the gate has nobody, and EOF tells the
					// daemon now rather than after its timeout.
					logging.WarnWithin(s.logger, logging.LogBound, "could not attach the local terminal", "error", err)
					closedByUs.Store(true)
					_ = parent.Close()
				}
			}()
		},
	}

	outcome, runErr := parent.Run(runCtx, handlers)

	switch {
	case runErr != nil && closedByUs.Load():
		out := s.drainClient(clientDone, cancelClientNow, drainWait)
		clientDone = nil
		return fmt.Errorf("could not attach the local terminal to session %s: %w", s.name, out.err)
	case errors.Is(runErr, context.Canceled) && ctx.Err() == nil:
		return fmt.Errorf("session %s: the daemon did not report whether the command started within %s%s", s.name, verdictWait, seeLog("; see %s", s.loggedTo()))
	case runErr != nil:
		return fmt.Errorf("session %s: %w%s", s.name, runErr, seeLog(" (see %s)", s.loggedTo()))
	case outcome.Failed != nil:
		f := outcome.Failed
		switch {
		case f.NameInUse:
			return nameInUseError{name: s.name}
		case f.Abandoned && displayErr != nil:
			// The operator's own answer; shareRunE knows what to do with it.
			return displayErr
		case f.Abandoned:
			return fmt.Errorf("session %s was not started: %s", s.name, f.Error)
		case f.Verbatim:
			// The text as it was chosen for the operator, each line as it
			// was given, so that a command one of them gives can be copied
			// whole; the log goes on a line of its own.
			return verbatimError{text: safeText(f.Error) + seeLog("\n(see %s)", s.loggedTo()), nameTaken: f.NameTaken}
		default:
			return fmt.Errorf("session %s could not start: %s%s", s.name, f.Error, seeLog(" (see %s)", s.loggedTo()))
		}
	}

	if s.detach {
		return s.printStarted(ctx, claimed, created, outcome.Started)
	}
	if clientDone == nil {
		// Started without ever being told listening: not a daemon this
		// process built. Nothing to wait for.
		return nil
	}
	// Unbounded, and deliberately not the deferred drain: the command has
	// started, so this wait is the session itself running, for as long as the
	// operator keeps it. The bounded drain is for the ways out where the
	// session is already over and the client is only holding the terminal.
	out := <-clientDone
	clientDone = nil
	if out.err != nil {
		return fmt.Errorf("could not attach the local terminal to session %s: %w", s.name, out.err)
	}
	// The launch this process started, which the name may no longer be: the
	// advice the lines give is only for the session this terminal was
	// attached to.
	var launchID string
	if claimed != nil {
		launchID = claimed.LaunchId
	}
	// What the record confirms the authority of a delegated launch decided:
	// there is no telling an attached terminal while it is attached, so it is
	// told here, as it lets go.
	var withdrawn []string
	var stopped string
	if isDelegated(created, nil) {
		withdrawn, stopped = delegatedEndLines(ctx, created, s.name, launchID)
	}
	// Each line is the whole story, so the error carries only the script
	// exit code: an ExitCodeError with no message, for which Exit prints
	// nothing.
	switch out.res.Reason {
	case attach.Detached:
		s.writeEndLines(append([]string{detachedLine(s.name)}, withdrawn...))
		return nil
	case attach.Exited:
		// No line for an exit of 0, nor for a join timeout, whose notice
		// the daemon has already put in the stream.
		e := endedFromResult(out.res)
		line := endLine(e, false)
		if e.outcome() == outcomeStopped && stopped != "" {
			line = stopped
		}
		s.writeEndLine(line)
		if out.res.Status == 0 {
			return nil
		}
		return ExitCodeError{Code: out.res.Status}
	case attach.Disconnected:
		after := checkAfterDisconnect(ctx, s.name, launchID)
		lines := []string{disconnectLine(s.name, s.loggedTo(), after)}
		if after == stillRunning {
			lines = append(lines, withdrawn...)
		}
		s.writeEndLines(lines)
		return ExitCodeError{Code: exitDisconnected}
	}
	return nil
}

// delegatedEndLines is what a foreground delegated host says of its launch
// as its terminal lets go, beyond the line it says for any session, from
// what the record of the launch confirms: that the authority withdrew the
// remote access of a session still running, for a terminal that leaves it
// running. stopped is the line said in place of the generic stopped one when
// the record says it was the authority's stop. Nothing is said that the
// record, read within disconnectCheckTimeout, doesn't confirm. The record
// names the authority only where created, the daemon's answer as it created
// the session, agrees with it, by the guest address both give; where it
// doesn't, the authority is "the session's authority", as ~? has it.
func delegatedEndLines(ctx context.Context, created *api.GetSessionResponse, name, launchID string) (withdrawn []string, stopped string) {
	if launchID == "" {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(ctx, disconnectCheckTimeout)
	defer cancel()
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	if err != nil || rec == nil || rec.LaunchID != launchID || rec.Delegation == nil {
		return nil, ""
	}
	named := rec.Delegation
	if !confirmsDelegation(created, rec.Delegation) {
		named = nil
	}
	if rec.Delegation.Decision == sessiondir.DecisionStopped {
		stopped = "upterm: " + tui.StoppedNotice(named)
	}
	if held && rec.Status == sessiondir.StatusDisconnected && rec.TunnelReason == sessiondir.TunnelReasonWithdrawn {
		withdrawn = tui.WithdrawnNotice(named, name)
		withdrawn[0] = "upterm: " + withdrawn[0]
	}
	return withdrawn, stopped
}

// writeEndLine writes the session's last line, if there is one, after raw mode
// and so at a column of its own; bounded, because stderr may be the terminal
// that just stopped.
func (s *spawnedSession) writeEndLine(line string) {
	if line == "" {
		return
	}
	logging.WriteWithin(s.stderr, logging.LogBound, "\r\n"+line+"\r\n")
}

// writeEndLines is writeEndLine for a last line with more after it.
func (s *spawnedSession) writeEndLines(lines []string) {
	s.writeEndLine(strings.Join(lines, "\r\n"))
}

// drainClient waits for the attach client to finish and reports how it did.
//
// Freely for bound, because the client is draining the
// session's channel into stdout and restoring the terminal on its way out,
// and a stdout nobody reads must not hold the exit forever; and after
// cancelling it beyond that, but always until it has returned, since
// cancellation is what makes it finish and returning before it has is
// exiting with the terminal in raw mode.
func (s *spawnedSession) drainClient(done <-chan clientOutcome, cancel context.CancelFunc, bound time.Duration) clientOutcome {
	select {
	case out := <-done:
		return out
	case <-time.After(bound):
	}
	logging.WarnWithin(s.logger, logging.LogBound, "the local terminal did not finish draining; cancelling it", "timeout", bound)
	cancel()
	return <-done
}

// openSessionWarning is what upterm host says as an open session starts: one
// anyone with the session ID can join, with nobody asked.
const openSessionWarning = "upterm: warning: anyone with the session ID can join; restrict who can with --authorized-user or --authorized-keys"

// openSessionWarningFor is the warning for the open session sess, which
// says what is at stake when its guests' commands run without asking
// (--allow-exec): the daemon reports that execution as "granted".
func openSessionWarningFor(sess *api.GetSessionResponse) string {
	if sess.GetExecution() == "granted" {
		return "upterm: warning: anyone with the session ID can join and run commands as you; restrict who can with --authorized-user or --authorized-keys"
	}
	return openSessionWarning
}

// keyHint is the line a foreground upterm host says after the banner: the
// keys its escape character gives the attached terminal. Nothing with
// --escape-char none, which gives it none.
//
// Run over ssh, the outer client's own ~ escape takes ~. and ~? first, so with
// SSH_TTY set and upterm's escape ~ the line says how to get them past it.
// SSH_TTY can't tell which escape that client uses -- ssh -e none has none --
// so the line names the keys upterm's escape gives, and the doubled ones only
// as what ssh's default calls for. With another escape there is nothing to
// get past.
func keyHint(escape byte, sshTTY bool) string {
	if escape == 0 {
		return ""
	}
	e := string(escape)
	hint := "upterm: " + e + ". detaches, " + e + "? shows the session's status and keys, " + e + "a reviews requests"
	if sshTTY && escape == '~' {
		hint += "; with ssh's default ~ escape, type ~~., ~~? and ~~a"
	}
	return hint
}

// hostKeyHint is keyHint for the terminal lt describes, or "" where its keys
// don't work. The hint names ~. and ~?, so it is said only where both do:
// stdin is read, in raw mode, because this process is its foreground, and
// stdout is a terminal, the pty ~? needs to know it writes outside the
// session's sequences. Piped (upterm host -- cmd | tee log), ~. works and ~?
// doesn't; in the background, neither does.
func hostKeyHint(lt localTerminal, escape byte, sshTTY bool) string {
	if !lt.rawMode || lt.pty == nil {
		return ""
	}
	return keyHint(escape, sshTTY)
}

// hintOut is where the key hint goes: to whoever is at the keyboard, so
// stderr when it is a terminal, else stdout when that is one, as join's
// questions do. With neither a terminal there is nobody at one to tell, and a
// line about keys in a log or a pipe is only noise there.
func hintOut(stderr, stdout *os.File) io.Writer {
	switch {
	case term.IsTerminal(int(stderr.Fd())):
		return stderr
	case term.IsTerminal(int(stdout.Fd())):
		return stdout
	}
	return io.Discard
}

func parseHostKeys(lines []string) ([]ssh.PublicKey, error) {
	keys := make([]ssh.PublicKey, 0, len(lines))
	for _, l := range lines {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			return nil, fmt.Errorf("the daemon reported a host key that cannot be read: %w", err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("the daemon reported no host key to pin")
	}
	return keys, nil
}

// printStarted is --detach's output: the JSON session info a script parses,
// or one line saying how to reach the session.
func (s *spawnedSession) printStarted(ctx context.Context, claimed *api.Claimed, sess *api.GetSessionResponse, st *api.Started) error {
	if claimed == nil {
		return fmt.Errorf("session %s started but the daemon never reported its claim%s", s.name, seeLog(" (see %s)", s.loggedTo()))
	}
	if !s.jsonOut {
		line := fmt.Sprintf("Session %s is running in the background.", s.name)
		// A session that isn't ready is running, but not in the way the
		// sentence alone suggests: guests can't reach it. What the view's
		// Hint row would say about that goes right after it, as a sentence
		// of its own.
		if st.GetStatus() != sessiondir.StatusReady {
			if hint := recordedStatusHint(ctx, s.name, claimed.LaunchId, sess); hint != "" {
				line += " " + hint
			}
		}
		line += fmt.Sprintf(" Attach with upterm attach %s; stop it with upterm session stop %s.\n", s.name, s.name)
		_, err := io.WriteString(s.stdout, line)
		return err
	}
	// Refused rather than printed empty, and refused here rather than beside
	// the claim above: the line this function prints without -o json names no
	// status, so nothing there can be wrong, while a `"status": ""` hands a
	// script a value it cannot branch on and no daemon that speaks this
	// exchange sends one. The exchange is unreleased, so this is a bug in
	// this binary rather than an older daemon to accommodate.
	if st.Status == "" {
		return fmt.Errorf("session %s started but the daemon reported no status for it%s", s.name, seeLog(" (see %s)", s.loggedTo()))
	}
	info := sessionInfo{
		Name:     claimed.Name,
		LaunchID: claimed.LaunchId,
		// What the record said when the daemon published it, not an
		// assumption made here: a tunnel lost in the moment before that
		// write leaves "reconnecting" standing, or "disconnected" on a
		// relay that can't reconnect, and a session info run a second later
		// would answer that.
		Status:       st.Status,
		SessionID:    st.SessionId,
		AdminSocket:  claimed.AdminSocket,
		AttachSocket: claimed.AttachSocket,
		LogPath:      claimed.LogPath,
		Pid:          int(claimed.Pid),
		// What the record says at this moment, and what `session info -o
		// json` would answer if asked a moment later: the claim writes
		// ReasonUnknown and nothing has replaced it, since the session has
		// only just started. Set explicitly so the two shapes match —
		// reason is a key `session info` always publishes.
		Reason:          sessiondir.ReasonUnknown,
		JoinStateSource: joinStateFromRecord,
	}
	// The join fields are the daemon's own snapshot, taken as it reported
	// readiness with any timeout already counting, and applied the way
	// `session info` applies a live answer, so the two agree. Without one
	// nothing is guessed: the source stays "record".
	info = withLiveJoinState(info, &api.GetSessionResponse{JoinState: st.GetJoinState()})
	if sess != nil {
		if detail, err := buildSessionDetail(sess); err == nil {
			info.Command = detail.Command
			info.ForceCommand = detail.ForceCommand
			info.LoginCommand = detail.LoginCommand
			info.SSHCommand = detail.SSHCommand
			info.JoinCommand = detail.JoinCommand
			info.Open = detail.Open
		}
		// Present whatever the status, as the connect strings are, unless
		// the relay's SSH user or its address is one sshConfigFor won't write.
		if block, err := sshConfigFor(sess, claimed.Name); err == nil {
			info.SSHConfig = block
		}
		// The relay, who can join and what guests may do, as the daemon
		// reported them when it created the session: none of them can
		// change while it runs. The counts are not taken from it: it was
		// sent before anyone could connect, so they stay 0, with
		// countsKnown false beside them.
		info = withSessionReport(info, sess)
	}
	// The tunnel's state, which started doesn't carry: the record's, as
	// `session info` reads it a moment later. The outage only while the
	// record still says the status reported above, so that the object
	// describes one state of the session; a tunnel that has gone down or come
	// back since leaves it out rather than set beside a status it doesn't
	// describe. Whether the relay reconnects never changes once known, so
	// any record of this launch has it.
	rec := launchRecord(ctx, claimed.Name, claimed.LaunchId)
	if rec != nil {
		if rec.Status == st.Status {
			info = withRecordedTunnel(info, rec)
		} else {
			info.Reconnect = rec.Reconnect
		}
	}
	// A delegated session's delegation is its record's, published before its
	// relay was dialled, with its connect strings where the daemon's answer
	// confirms them, as the top-level ones are there whenever it answered.
	// Nobody joins it with its ID. An answer that disagrees with the record
	// leaves no address, and no way in, that both confirm, as `session info`
	// has it: neither the record's delegation nor the daemon's connect
	// strings are printed.
	var delegation *sessiondir.Delegation
	if rec != nil {
		delegation = rec.Delegation
	}
	if sess != nil && isDelegated(sess, delegation) {
		info.Open, info.Access = false, tui.AccessDelegated
		if !confirmsDelegation(sess, delegation) {
			delegation = nil
			info.SSHCommand, info.JoinCommand, info.SSHConfig = "", "", ""
		}
	}
	info.Delegation = delegationInfoOf(delegation, sess != nil && confirmsDelegation(sess, delegation))
	enc := json.NewEncoder(s.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

// statusHintTimeout bounds the record read behind --detach's hint and its
// JSON's tunnel fields: the session is up and the output is all that is left
// to print, so a registry that is slow to answer costs those, not the exit.
const statusHintTimeout = time.Second

// launchRecord is name's record as it is now, when launchID's: nil when it
// can't be read within statusHintTimeout or another launch holds the name.
func launchRecord(ctx context.Context, name, launchID string) *sessiondir.Record {
	ctx, cancel := context.WithTimeout(ctx, statusHintTimeout)
	defer cancel()
	rec, _, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	if err != nil || rec == nil || rec.LaunchID != launchID {
		return nil
	}
	return rec
}

// recordedStatusHint is the view's Hint for launchID's status as its record
// has it now, as a sentence of its own: the record has the reason the tunnel
// is down, which the daemon's report doesn't carry. The record names a
// delegated session's authority only where sess, the daemon's answer as it
// created the session, confirms it; where it doesn't, or there is none, the
// authority is "the session's authority". "" when the record can't be read in
// time, is another launch's, or doesn't say.
func recordedStatusHint(ctx context.Context, name, launchID string, sess *api.GetSessionResponse) string {
	rec := launchRecord(ctx, name, launchID)
	if rec == nil {
		return ""
	}
	named := rec.Delegation
	if !confirmsDelegation(sess, named) {
		named = nil
	}
	hint := tui.StatusHint(tui.SessionDetail{Status: rec.Status, TunnelReason: rec.TunnelReason, Delegation: named})
	if rec.TunnelReason == sessiondir.TunnelReasonWithdrawn {
		// Already a sentence's start: the authority's name as it is
		// given, or the capitalized phrase that stands for it.
		return hint
	}
	return capitalized(hint)
}

// capitalized is s with its first letter in upper case. The view's hints are
// written to follow a "Hint:" label, so they begin in lower case, and
// --detach's line puts one after a full stop instead. A hint that begins with
// the product's name keeps it as it is: upterm is written in lower case
// wherever it stands.
func capitalized(s string) string {
	if s == "" || strings.HasPrefix(s, "upterm") {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}
