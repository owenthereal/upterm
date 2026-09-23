package command

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// ExitCodeError carries an exit status for main to use. Err is what cobra
// prints; main exits with Code, and says nothing more — logging Err again
// would put the same sentence on stderr twice.
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

Exit status: 0 after a detach; the command's own status once the session
ends; 254 if the session disconnected this terminal (a stalled or overflowed
terminal, or a daemon that went away — see the log for which); 255 if it
could not attach.`,
		Example: `  # Attach to the session named build-shell:
  upterm attach build-shell

  # Attach with no escape character, so every keystroke reaches the session:
  upterm attach build-shell --escape-char none`,
		Args: cobra.MaximumNArgs(1),
		RunE: attachRunE,
	}
	cmd.Flags().StringVar(&flagEscapeChar, "escape-char", "~", "Escape character for detaching (ESC-CHAR followed by . at the start of a line) or suspending (ESC-CHAR followed by ^Z, Unix only), or 'none' to disable.")
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

// resolveAttachName picks the session: the explicit name, or the only live
// one.
func resolveAttachName(ctx context.Context, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	live, err := sessiondir.ListLive(ctx, utils.UptermStateDir())
	if err != nil {
		return "", err
	}
	switch len(live) {
	case 0:
		return "", errors.New("no running session to attach to; start one with 'upterm host' or name one to attach to")
	case 1:
		return live[0].Name, nil
	}
	var names []string
	for _, r := range live {
		names = append(names, r.Name)
	}
	return "", fmt.Errorf("several sessions are running; name one: %s", strings.Join(names, ", "))
}

// attachTarget resolves a name to the socket to dial and the keys to pin it
// with, and to the status the record had when it did. Starting, ready and
// disconnected are all attachable — the command is alive and the socket is
// local, whatever the tunnel is doing — and a name nobody holds is not.
//
// The status comes back because it is what explains a failed dial: see
// attachFailure.
func attachTarget(ctx context.Context, name string) (string, []ssh.PublicKey, string, error) {
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	if err != nil {
		return "", nil, "", err
	}
	if rec == nil {
		return "", nil, "", fmt.Errorf("no session named %q", name)
	}
	if !held {
		return "", nil, "", fmt.Errorf("session %q has ended (%s)", name, describeOutcome(rec))
	}
	noAttachSupport := fmt.Errorf("session %q was started by an upterm without attach support; restart it to attach", name)
	if rec.AttachSocket == "" {
		return "", nil, rec.Status, noAttachSupport
	}
	// The keys are published when the attach door starts listening, which is
	// also when its socket becomes dialable. So a record without them is
	// either a session still starting — where the answer is to wait, exactly
	// as it is for the dial that would have failed a moment later — or one
	// from an upterm that predates attach. attachFailure tells those apart by
	// the status, which is the same thing it tells a failed dial apart by.
	if len(rec.HostKeys) == 0 {
		return "", nil, rec.Status, attachFailure(name, rec.Status, noAttachSupport)
	}
	keys := make([]ssh.PublicKey, 0, len(rec.HostKeys))
	for _, k := range rec.HostKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			// Present but unreadable, which no amount of waiting fixes.
			return "", nil, rec.Status, fmt.Errorf("session %q: its record names a host key that cannot be read; restart it to attach", name)
		}
		keys = append(keys, key)
	}
	return rec.AttachSocket, keys, rec.Status, nil
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

func describeOutcome(rec *sessiondir.Record) string {
	if rec.ExitCode != nil {
		return fmt.Sprintf("%s, status %d", rec.Reason, *rec.ExitCode)
	}
	if rec.Signal != "" {
		return fmt.Sprintf("%s by %s", rec.Reason, rec.Signal)
	}
	return rec.Reason
}

// commandExitedMessage is the account a terminal gets when the session's
// command ended under it. Shared with `upterm host`'s spawning parent,
// which keeps this contract: one sentence, then a status for the script.
func commandExitedMessage(name string, status int) string {
	return fmt.Sprintf("upterm: session %s ended: command exited (status %d)", name, status)
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
	// Set here rather than on the command, because where it is set is what
	// divides the two kinds of failure. Cobra raises unknown flags and too
	// many arguments before this line, and usage is the right answer to
	// those; everything below it is a failure to attach — a name nobody
	// holds, a session that has ended, a socket that refuses — and printing
	// seventeen lines of flags after "no session named" buries the one
	// sentence that answers the question.
	c.SilenceUsage = true

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
	name, err := resolveAttachName(lookupCtx, firstArg(args))
	var socket, status string
	var keys []ssh.PublicKey
	if err == nil {
		socket, keys, status, err = attachTarget(lookupCtx, name)
	}
	cancelLookup()
	if err != nil {
		return ExitCodeError{Code: exitAttachFailed, Err: err}
	}

	ctx, cancel := notifyDetachSignals(c.Context())
	defer cancel()
	lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, resolveTerm("", os.Getenv("TERM")))
	res, err := attachLocalTerminal(ctx, socket, keys, lt, escape, os.Stdin, os.Stdout, logger.Logger)
	if err != nil {
		return ExitCodeError{Code: exitAttachFailed, Err: attachFailure(name, status, err)}
	}

	// After raw mode, so it lands at a column of its own — and bounded,
	// because stderr may be the terminal that just stopped.
	var msg string
	switch res.Reason {
	case attach.Detached:
		msg = fmt.Sprintf("upterm: detached from session %s; the session continues", name)
	case attach.Exited:
		msg = fmt.Sprintf("upterm: session %s ended (status %d)", name, res.Status)
	case attach.Disconnected:
		msg = fmt.Sprintf("upterm: disconnected from session %s (see %s); reattach with 'upterm attach %s'", name, utils.UptermLogFilePath(), name)
	}
	logging.WriteWithin(os.Stderr, logging.LogBound, "\r\n"+msg+"\r\n")
	// The line above is the whole account of how this ended; the status
	// returned below is for a script, not for a reader.
	c.SilenceErrors = true
	return attachExitError(name, res)
}

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}
