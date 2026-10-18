package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/sessiondir"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	// exitDisconnected: the session closed the connection without an exit
	// status — a stalled or overflowed terminal, or a daemon that went away.
	// upterm's log says which.
	exitDisconnected = 254
	// exitAttachFailed: no such session, not running, or the socket refused.
	exitAttachFailed = 255
)

var flagEscapeChar string

// ExitCodeError carries an exit status for Exit to use. With an Err, Exit
// prints it as upterm's one line and exits with Code; with none, Code is the
// whole outcome and nothing is printed.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

func (e ExitCodeError) Unwrap() error { return e.Err }

func attachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach [NAME]",
		Short: "Attach this terminal to a running session",
		Long: `Attach this terminal to a running session, by name.

The session keeps running when this terminal detaches, and any number of
terminals can attach to it over time. With no NAME, the one running session
is attached to; with several, the name is required.

To detach, type the escape character at the start of a line followed by a
period: ~. by default. ~~ sends a literal ~. On Unix, ~^Z suspends this
terminal instead — fg resumes it. A session that keeps producing output
while this terminal is suspended may disconnect it before fg runs (the
same 254 below); 'upterm attach NAME' brings it back. Everything else is
sent to the session as typed. A SIGTERM or SIGHUP detaches too.

Exit status: 0 after a detach; the session's reported exit status once it
ends (0 when --join-timeout expires); 254 if the session disconnected this
terminal (a stalled or overflowed terminal, or a daemon that went away — see
the log for which); 255 if it could not attach.`,
		Example: `  # Attach to the session named build-shell:
  upterm attach build-shell

  # Attach with no escape character, so every keystroke reaches the session:
  upterm attach build-shell --escape-char none`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeSessionNames,
		RunE:              attachRunE,
		// Usage and config errors exit with that failure code too, not only what
		// RunE returns.
		Annotations: map[string]string{failureCodeAnnotation: strconv.Itoa(exitAttachFailed)},
	}
	cmd.Flags().StringVar(&flagEscapeChar, "escape-char", "~", "Escape character for detaching (ESC-CHAR followed by . at the start of a line) or suspending (ESC-CHAR followed by ^Z, Unix only), or 'none' to disable.")
	// ~? lists the session's guests, so attach hides their addresses on the
	// same flag, environment variable and config key as every other command
	// that prints them: each command reads only the flags it registers.
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")
	return cmd
}

func parseEscapeChar(s string) (byte, error) {
	if s == "none" {
		return 0, nil
	}
	if len(s) != 1 {
		return 0, fmt.Errorf("--escape-char must be a single ASCII character or 'none', got %q", s)
	}
	return s[0], nil
}

// resolveAttachName picks the session: the one the explicit argument names,
// by name or by ID, or the only live one.
func resolveAttachName(ctx context.Context, explicit string) (resolved, error) {
	if explicit != "" {
		return resolveSession(ctx, explicit)
	}
	live, err := sessiondir.ListLive(ctx, utils.UptermStateDir())
	if err != nil {
		return resolved{}, err
	}
	switch len(live) {
	case 0:
		return resolved{}, errors.New("no running session to attach to; start one with 'upterm host' or name one to attach to")
	case 1:
		return resolved{Name: live[0].Name}, nil
	}
	var names []string
	for _, r := range live {
		names = append(names, r.Name)
	}
	return resolved{}, fmt.Errorf("several sessions are running; name one: %s", strings.Join(names, ", "))
}

// target is what attach read from a session's record: the socket to dial and
// the keys to pin it with, the status the record had when it did, and the
// launch and admin socket it belongs to.
//
// The status comes back because it is what explains a failed dial: see
// attachFailure. The launch comes back because it is what a disconnect is
// checked against: the name can pass to another session while this terminal
// is attached, and the one to send it back to is the one it attached to.
type target struct {
	Socket, Status, LaunchID, AdminSocket string
	Keys                                  []ssh.PublicKey
}

// attachTarget resolves a session to the one to attach to. Starting, ready,
// reconnecting and disconnected (which a relay that can't reconnect leaves a
// session in) are all attachable — the command is alive and the socket is
// local, whatever the tunnel is doing — and a name nobody holds is not.
//
// A session given by ID is attached to only while its launch still holds the
// name: once it has ended and another has taken the name, the record found is
// the other's, and its socket is not the session that was asked for.
func attachTarget(ctx context.Context, r resolved) (target, error) {
	name := r.Name
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	if err != nil {
		return target{}, err
	}
	if rec == nil {
		return target{}, fmt.Errorf("no session named %q", name)
	}
	if sameLaunchOrReplaced(r, rec) != nil {
		return target{}, errors.New(refusalLine(name, endedFromRecord(goneRecord(r))))
	}
	if !held {
		return target{}, errors.New(refusalLine(name, endedFromRecord(rec)))
	}
	t := target{Status: rec.Status, LaunchID: rec.LaunchID, AdminSocket: rec.AdminSocket}
	noAttachSupport := fmt.Errorf("session %q was started by an upterm without attach support; restart it to attach", name)
	if rec.AttachSocket == "" {
		return t, noAttachSupport
	}
	// The keys are published when the attach door starts listening, which is
	// also when its socket becomes dialable. So a record without them is
	// either a session still starting — where the answer is to wait, exactly
	// as it is for the dial that would have failed a moment later — or one
	// from an upterm that predates attach. attachFailure tells those apart by
	// the status, which is the same thing it tells a failed dial apart by.
	if len(rec.HostKeys) == 0 {
		return t, attachFailure(name, rec.Status, noAttachSupport)
	}
	keys := make([]ssh.PublicKey, 0, len(rec.HostKeys))
	for _, k := range rec.HostKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			// Present but unreadable, which no amount of waiting fixes.
			return t, fmt.Errorf("session %q: its record names a host key that cannot be read; restart it to attach", name)
		}
		keys = append(keys, key)
	}
	t.Socket, t.Keys = rec.AttachSocket, keys
	return t, nil
}

// attachStatusSource is what ~? reports on for an attachment: the resolved
// session's name, since ~? looks the session up by name and an ID is not one,
// and the launch and admin socket the record named when the target was read.
func attachStatusSource(r resolved, t target) statusSource {
	return statusSource{Name: r.Name, LaunchID: t.LaunchID, AdminSocket: t.AdminSocket}
}

// attachFailure explains why an attachment could not be made.
//
// A record names its attach socket from the moment the name is claimed, but
// the daemon binds that socket only once the tunnel is up. So `upterm attach`
// against a session that is still starting loses a race it cannot see, and
// the dialer's own account of it — "no such file or directory" against a path
// the user never typed — reads like a broken session rather than an early
// one. The recorded status is what tells the two apart; anything other than
// starting is a failure the dialer describes better than this could.
func attachFailure(name, status string, err error) error {
	// Except for the one failure this must never reword. A key that did not
	// match says something answered the socket that is not the session, and
	// "try again in a moment" would send the user straight back to it.
	if errors.Is(err, attach.ErrHostKeyMismatch) {
		return err
	}
	if status == sessiondir.StatusStarting {
		return fmt.Errorf("session %q is still starting; try again in a moment", name)
	}
	return err
}

func attachExitError(name string, res attach.Result) error {
	switch res.Reason {
	case attach.Exited:
		if res.Status == 0 {
			return nil
		}
		return ExitCodeError{Code: res.Status}
	case attach.Disconnected:
		return ExitCodeError{Code: exitDisconnected}
	}
	return nil
}

func attachRunE(c *cobra.Command, args []string) error {
	// A bad escape character is a could-not-attach like the rest: the flag
	// parsed, its value is just not one this can use.
	escape, err := parseEscapeChar(flagEscapeChar)
	if err != nil {
		return ExitCodeError{Code: exitAttachFailed, Err: err}
	}
	logger := uptermctx.Logger(c.Context())
	if logger == nil {
		return fmt.Errorf("logger not available")
	}

	// A deadline on the lookup — it waits on the registry lock — and none on
	// the attachment.
	lookupCtx, cancelLookup := context.WithTimeout(c.Context(), sessionQueryTimeout)
	r, err := resolveAttachName(lookupCtx, firstArg(args))
	var t target
	if err == nil {
		t, err = attachTarget(lookupCtx, r)
	}
	cancelLookup()
	if err != nil {
		return ExitCodeError{Code: exitAttachFailed, Err: err}
	}
	// The name, whatever the argument was: everything below looks the session
	// up by name, and an ID is not one.
	name := r.Name

	ctx, cancel := notifyDetachSignals(c.Context())
	defer cancel()
	lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, resolveTerm("", os.Getenv("TERM")))
	src := attachStatusSource(r, t)
	res, err := attachLocalTerminal(ctx, t.Socket, t.Keys, lt, escape, src, os.Stdin, os.Stdout, logger.Logger)
	if err != nil {
		return ExitCodeError{Code: exitAttachFailed, Err: attachFailure(name, t.Status, err)}
	}

	// Asked before the line is written, and only for a disconnect: the line
	// advises a reattach only once the record says the session this terminal
	// attached to is still the one running.
	var after afterDisconnect
	if res.Reason == attach.Disconnected {
		after = checkAfterDisconnect(c.Context(), name, t.LaunchID)
	}
	// After raw mode, so it lands at a column of its own — and bounded,
	// because stderr may be the terminal that just stopped.
	if line := attachEndLine(name, attachLogPath(c.Context()), res, after); line != "" {
		logging.WriteWithin(os.Stderr, logging.LogBound, "\r\n"+line+"\r\n")
	}
	// The line above is the whole account of how this ended; the status
	// returned below is for a script, not for a reader, and Exit prints
	// nothing for it.
	return attachExitError(name, res)
}

// attachEndLine is how an attachment ended, as its last line, or "" when the
// daemon's own notice in the stream already said it (a join timeout). after
// is what checkAfterDisconnect found, for a disconnect, and logPath the log a
// disconnect's line points at, or "" for none.
func attachEndLine(name, logPath string, res attach.Result, after afterDisconnect) string {
	switch res.Reason {
	case attach.Detached:
		return attachDetachedLine
	case attach.Exited:
		return endLine(endedFromResult(res), true)
	case attach.Disconnected:
		return disconnectLine(name, logPath, after)
	}
	return ""
}

// attachLogPath is the log attach's lines point at: this run's, or "" when
// the root's pre-run could not open it, since nothing of this run is in it.
func attachLogPath(ctx context.Context) string {
	if logWarningFor(ctx).loggingOff() {
		return ""
	}
	return utils.UptermLogFilePath()
}

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}
