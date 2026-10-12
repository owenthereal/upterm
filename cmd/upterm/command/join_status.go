package command

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/join"
	"golang.org/x/term"
)

// upterm join's own exit statuses. An exit status that arrives from the
// session is the session's, and leaving with ~. is 0.
const (
	exitJoinStopped = 130
	exitJoinFailed  = 255
)

const needsATerminal = "upterm: upterm join needs a terminal."

// joinStatus is the Events seam: it writes each event as its line on
// stderr, synchronously, so that Events returns once the line has been
// written. On a terminal a waiting line is rewritten in place at each
// attempt; anywhere else every event is a line of its own. What else upterm
// join writes while it runs goes through it too (see writer and promptOut),
// so that no two writes interleave and every line ends as the terminal's
// mode needs.
type joinStatus struct {
	mu  sync.Mutex
	w   io.Writer
	tty bool // w is a terminal
	// columns is the width of the terminal w is, measured as each waiting
	// line is written, or 0 when it can't be. Nil never measures it.
	columns func() int
	// rawMode says TakeTerminal has put the terminal in raw mode, where a
	// line ends "\r\n". It stays set once Run returns, when only last
	// writes, which doesn't read it.
	rawMode bool
	open    bool // an in-place waiting line has been written without its end
	rows    int  // the rows the open waiting line took: more than one when it wrapped
	// joined says a session has been ready, so its output may have left the
	// cursor anywhere on the line.
	joined bool
	t      join.Target
	wait   bool // --wait, which a first join's no-host line says
	now    func() time.Time
}

func newStatus(w io.Writer, tty bool, t join.Target, wait bool) *joinStatus {
	return &joinStatus{w: w, tty: tty, t: t, wait: wait, now: time.Now}
}

// statusOn is the status on f, which is stderr: when f is a terminal, its
// waiting lines are measured against its width as it is when each is
// written.
func statusOn(f *os.File, t join.Target, wait bool) *joinStatus {
	s := newStatus(f, term.IsTerminal(int(f.Fd())), t, wait)
	s.columns = func() int {
		size, err := tty.Size(f)
		if err != nil {
			return 0
		}
		return size.Cols
	}
	return s
}

// raw sets the line ending: "\r\n" once TakeTerminal has put the terminal in
// raw mode, where "\n" alone moves down without going back to the margin.
// A file or a pipe keeps "\n" either way. It waits on the status's lock, so
// nothing calls it once Run has returned (see finishJoin).
func (s *joinStatus) raw(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawMode = on
}

func (s *joinStatus) eol() string {
	if s.tty && s.rawMode {
		return "\r\n"
	}
	return "\n"
}

// event is join.Config.Events.
func (s *joinStatus) event(e join.Event) {
	line := renderEvent(e, s.t, s.now(), s.wait)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Kind == join.Joined {
		s.joined = true
	}
	if s.tty && e.Kind == join.Waiting {
		_, _ = io.WriteString(s.w, s.rewind()+line)
		s.open, s.rows = true, s.rowsOf(line)
		return
	}
	// A first join says nothing, and still ends the waiting line, so that
	// the session's output starts at the margin.
	s.endLine()
	if line != "" {
		_, _ = io.WriteString(s.w, line+s.eol())
	}
}

// rewind takes the cursor back to the start of the open waiting line and
// clears it, so that the next one is written over it. "\033[K" clears only
// the row the cursor is on, which for a line that wrapped is its last; so
// the cursor goes up to the line's first row, and "\033[J" clears from there
// to the end of the screen. The caller holds mu.
func (s *joinStatus) rewind() string {
	if s.open && s.rows > 1 {
		return fmt.Sprintf("\r\033[%dA\033[J", s.rows-1)
	}
	return "\r\033[K"
}

// rowsOf is how many rows line takes on the terminal, at its width now: one
// when it fits, and when the width isn't known. Each rune is taken to be one
// column wide.
func (s *joinStatus) rowsOf(line string) int {
	cols := 0
	if s.columns != nil {
		cols = s.columns()
	}
	n := utf8.RuneCountInString(line)
	if cols <= 0 || n <= cols {
		return 1
	}
	return (n + cols - 1) / cols
}

// endLine ends an open waiting line, so that what follows starts a line of
// its own. The caller holds mu.
func (s *joinStatus) endLine() {
	if s.open {
		_, _ = io.WriteString(s.w, s.eol())
		s.open = false
	}
}

// writer is stderr for what others write while upterm join runs: the lines
// about skipped keys, the "Permanently added" line, which
// --skip-host-key-check writes from inside a handshake, after TakeTerminal
// too, and the prompts when stderr is a terminal (see promptOut). It ends an
// open waiting line first, and each of its lines as the status's end.
func (s *joinStatus) writer() io.Writer { return statusWriter{s, s.w} }

// promptOut is where upterm join asks the guest something: a key's
// passphrase, and whether to trust an unknown relay key. A question has to
// reach the terminal its answer is typed at, so with stderr redirected, as
// in 2>join.log, it goes to stdout, which upterm join requires to be a
// terminal; in the file, a passphrase prompt, which turns echo off, would
// leave a join that looks hung. Nothing else writes to stdout before the
// first session, and every question comes before that, in cooked mode,
// before TakeTerminal. When stderr is a terminal, a question is written
// there like any other line.
func (s *joinStatus) promptOut(stdout io.Writer) io.Writer {
	if s.tty {
		return s.writer()
	}
	return statusWriter{s, stdout}
}

// statusWriter writes to w under the status's lock, as writer describes.
type statusWriter struct {
	s *joinStatus
	w io.Writer
}

func (w statusWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.s.endLine()
	text := string(p)
	if eol := w.s.eol(); eol != "\n" {
		text = strings.ReplaceAll(text, "\n", eol)
	}
	if _, err := io.WriteString(w.w, text); err != nil {
		return 0, err
	}
	return len(p), nil
}

// last writes the run's last line, once the terminal is restored. On a
// terminal it starts a line of its own after a waiting line or a session's
// output, as upterm attach's last line does. The write is bounded, because
// stderr may be the terminal that just stopped taking output, and it waits
// within that bound for a status line that join abandoned as it stopped.
func (s *joinStatus) last(line string) {
	logging.Within(logging.LogBound, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		text := line + "\n"
		if s.tty {
			text = line + "\r\n"
			if s.open || s.joined {
				text = "\r\n" + text
			}
		}
		s.open = false
		_, _ = io.WriteString(s.w, text)
	})
}

// renderEvent is e as the guest reads it; "" for an event that says nothing,
// a first join. now is what "next try in N s" counts from; wait is --wait.
func renderEvent(e join.Event, t join.Target, now time.Time, wait bool) string {
	switch e.Kind {
	case join.Joined:
		if !e.Rejoin {
			return ""
		}
		return fmt.Sprintf("upterm: rejoined session %s after %s", t.SessionID(), e.Down.Round(time.Second))
	case join.Lost:
		return fmt.Sprintf("upterm: lost the connection to session %s (%v); rejoining. Enter retries now, Ctrl-C stops.", t.SessionID(), e.Err)
	case join.Waiting:
		line := waitingLine(e, t, now, wait)
		if e.Long {
			line += ". The session may have ended or moved; check with the host."
		}
		return line
	}
	return ""
}

func waitingLine(e join.Event, t join.Target, now time.Time, wait bool) string {
	since := e.Since.Local().Format("15:04:05")
	next := max(0, int(math.Ceil(e.Next.Sub(now).Seconds())))
	switch e.Why {
	case join.NoHost:
		switch {
		case e.First && wait:
			return fmt.Sprintf("upterm: no host is connected for session %s right now; waiting (Ctrl-C to stop)", t.SessionID())
		case e.First:
			return fmt.Sprintf("upterm: no host is connected for session %s right now; retrying for 30 s (Ctrl-C to stop)", t.SessionID())
		}
		return fmt.Sprintf("upterm: waiting for the host since %s; next try in %d s", since, next)
	case join.Unreachable:
		return fmt.Sprintf("upterm: can't reach %s since %s (%v); next try in %d s", t.Relay(), since, e.Err, next)
	case join.RelayLookup:
		return fmt.Sprintf("upterm: the relay can't look up sessions since %s; next try in %d s", since, next)
	case join.Upstream:
		return fmt.Sprintf("upterm: the relay can't reach the host since %s; next try in %d s", since, next)
	case join.IdentityFailure:
		return fmt.Sprintf("upterm: your SSH agent can't sign since %s (%v); next try in %d s", since, agentCause(e.Err), next)
	}
	// Setup, which is also what join makes of anything it doesn't recognise.
	return fmt.Sprintf("upterm: can't start the session since %s (%v); next try in %d s", since, e.Err, next)
}

// renderOutcome is how a run ended, as its last line and the exit status.
// typed is the target as the guest typed it, which a line that suggests -i
// repeats.
func renderOutcome(o join.Outcome, t join.Target, src join.KeySource, typed string) (line string, code int) {
	switch o.Kind {
	case join.Exited:
		return fmt.Sprintf("upterm: connection to session %s ended (status %d)", t.SessionID(), o.Status), o.Status
	case join.Left:
		return fmt.Sprintf("upterm: left session %s", t.SessionID()), 0
	case join.Stopped:
		return "upterm: stopped", exitJoinStopped
	}
	return failureLine(o.Err, t, src, typed), exitJoinFailed
}

// failureLine is why a join failed. A failure with no line of its own is
// told as its error.
func failureLine(err error, t join.Target, src join.KeySource, typed string) string {
	id := t.SessionID()
	var (
		deadline *join.DeadlineError
		refused  *join.RefusedError
		identity *join.IdentityError
		hostKey  *join.HostKeyError
	)
	switch {
	case errors.As(err, &deadline):
		switch deadline.Why {
		case join.NoHost:
			return fmt.Sprintf("upterm: no host is connected for session %s on %s. It may have ended, or the ID may be wrong.", id, t.Relay())
		case join.Unreachable:
			return fmt.Sprintf("upterm: can't reach %s: %v", t.Relay(), deadline.Err)
		case join.RelayLookup:
			return "upterm: the relay can't look up sessions right now. Try again shortly."
		case join.Upstream:
			return fmt.Sprintf("upterm: the relay can't reach the host of session %s. Try again shortly.", id)
		case join.Setup:
			return fmt.Sprintf("upterm: can't start session %s: %v", id, deadline.Err)
		}
	case errors.As(err, &refused):
		// Without evidence the key itself may not have been refused, so that
		// comes first.
		switch {
		case refused.Ambiguous:
			return fmt.Sprintf("upterm: session %s refused your keys, or the relay has no such session.", id)
		case src.Generated:
			return fmt.Sprintf("upterm: session %s admits only authorized users, and you have no SSH key. Create one with ssh-keygen -t ed25519 and ask the host to add it.", id)
		}
		return fmt.Sprintf("upterm: session %s refused your keys%s. If another key is authorized, pass it with upterm join -i PATH %s; otherwise ask the host to add one of yours.", id, keyCounts(src), typed)
	case errors.As(err, &identity):
		switch {
		case identity.Key != "":
			return fmt.Sprintf("upterm: your SSH agent couldn't sign with %s: %v", identity.Key, agentCause(identity.Err))
		case identity.List:
			return fmt.Sprintf("upterm: couldn't list your SSH agent's keys: %v. Fix the agent, or pass a key with upterm join -i PATH %s.", identity.Err, typed)
		case len(identity.Load) > 0:
			return fmt.Sprintf("upterm: couldn't load your SSH keys (%s). Fix them, or pass a key with upterm join -i PATH %s.", strings.Join(identity.Load, "; "), typed)
		}
	case errors.As(err, &hostKey):
		switch {
		case hostKey.Changed && hostKey.Err != nil:
			// ssh's mismatch warning, which the host package's error is.
			return hostKey.Err.Error()
		case hostKey.Declined || errors.Is(hostKey, join.ErrHostKeyUnknown):
			// An unknown key once the terminal was taken, when nobody could
			// be asked, or a "no": running again asks again.
			return "upterm: the relay's key is not one you trust; run upterm join again to check it."
		}
	case errors.Is(err, join.ErrUpstreamHostKey):
		return fmt.Sprintf("upterm: the relay couldn't verify the host of session %s.", id)
	}
	return fmt.Sprintf("upterm: %v", err)
}

// keyCounts is " (N from the agent, M from files)", naming only the sources
// that were used.
func keyCounts(src join.KeySource) string {
	var used []string
	if src.Agent > 0 {
		used = append(used, fmt.Sprintf("%d from the agent", src.Agent))
	}
	if src.Files > 0 {
		used = append(used, fmt.Sprintf("%d from files", src.Files))
	}
	if len(used) == 0 {
		return ""
	}
	return " (" + strings.Join(used, ", ") + ")"
}

// agentCause is why the agent failed to sign, without the wrappers whose
// own text names the key again, which the line already does.
func agentCause(err error) error {
	var identity *join.IdentityError
	if errors.As(err, &identity) && identity.Err != nil {
		err = identity.Err
	}
	var refused *host.AgentRefusedError
	if errors.As(err, &refused) {
		return refused.Err
	}
	var unavailable *host.AgentUnavailableError
	if errors.As(err, &unavailable) {
		return unavailable.Err
	}
	return err
}

func skipLine(file string, err error) string {
	return fmt.Sprintf("upterm: skipping %s: %v", file, err)
}

func agentSkipLine(err error) string {
	return fmt.Sprintf("upterm: skipping the SSH agent: %v", err)
}

// notATargetLine refuses typed, naming the target it reaches when it is an
// ssh command upterm printed.
func notATargetLine(typed string, err error) string {
	var bad *join.TargetError
	if errors.As(err, &bad) && bad.Suggestion != "" {
		return fmt.Sprintf("upterm: not a join target: %s. Did you mean upterm join %s?", typed, bad.Suggestion)
	}
	return fmt.Sprintf("upterm: not a join target: %s. Use ssh://ID@host, wss://ID@host or ID@host.", typed)
}
