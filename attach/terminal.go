package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/run"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// outputDrainTimeout bounds how long Run waits, after the session has ended,
// for what the session sent to reach Stdout. A var so a test can shorten it.
var outputDrainTimeout = 5 * time.Second

// inputFlushTimeout bounds what a detach still owes the session — the Enter
// that preceded ~., or an escape byte held at EOF — so that a session no
// longer taking input cannot keep the detach from happening. A var so a test
// can shorten it.
var inputFlushTimeout = time.Second

// inputBacklogLimit bounds what may sit unwritten in forwardInput's queue
// while the session is not taking input. 1 MiB, the same figure as
// uio.DefaultGuestBufferSize: more than a terminal can be typed at, and
// small enough that a client holds no meaningful amount of what it will
// never deliver. A var so a test can shorten it.
var inputBacklogLimit = 1 << 20

// testHookFeeding, when a test sets it, runs inside trackerMu just before the
// output copy feeds a chunk to the tracker, so that the test can hold a feed
// in progress. Nil outside tests.
var testHookFeeding func()

// testHookTracker, when a test sets it, is handed the output's mode tracker as
// Run creates it, so that the test can read what the client recorded once
// Released has closed. Nil outside tests.
var testHookTracker func(*uio.ModeTracker)

// statusSafeTimeout bounds how long ~?'s lines wait for the session's output
// to leave an escape sequence before they are dropped. It is about as long as
// the lookup that produced them is given: lines that can't be shown by then
// would arrive long after the key that asked for them. A var so a test can
// shorten it.
var statusSafeTimeout = time.Second

// Pty is a pty request: the terminal type and geometry the client's own
// terminal has. A client that requests one is eligible to be the session's
// primary client; one that does not is a viewer.
type Pty struct {
	Term string
	Size termsize.Size
}

// Terminal runs a terminal session on an established connection: the pty
// request, the shell, the I/O between the session and a pair of streams, the
// escapes, a suspend, and on the way out the drain and the mode restore.
// Client is a Terminal on the session's attach socket.
type Terminal struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Pty     *Pty
	Resizes <-chan termsize.Size
	Escape  byte

	// Suspend stops the process this client runs in and returns once it is
	// running again, with the terminal's size and whether the terminal is
	// this client's again — for a local terminal: restore the terminal,
	// SIGTSTP, re-enter raw mode if still the foreground, measure. owned is
	// false after bg: the terminal is the foreground job's, and the
	// attachment ends there, writing nothing more to it. Nil disables the ~^Z
	// sequence, and the bytes reach the session instead.
	//
	// It is the embedder's because what "suspend" means is the terminal's
	// business, not the protocol's: this package never touches termios and
	// never signals its own process.
	Suspend func() (size termsize.Size, owned bool)

	// DeclareInteractive sends upterm.AttachInteractiveEnvVar, which says
	// this client displays on a terminal and forwards its keystrokes, so it
	// can answer the terminal queries a primary is sent. Declared, because
	// the daemon cannot tell a terminal from a pipe on the far side of an SSH
	// channel — and a pty viewer that does not read its terminal would leave
	// the terminal's replies in the foreground shell as junk. Only the attach
	// socket reads it.
	DeclareInteractive bool

	// OnReady runs once, after the shell request is confirmed and before the
	// first byte of output is written to Stdout. Nil does nothing.
	OnReady func()

	// Status returns the lines ~? prints into this terminal, never into the
	// session: the session's status and the keys, each without its line
	// ending. It runs on a goroutine of its own, so the input is never held
	// up by it, and is given a context that ends with the attachment; it
	// should be bounded all the same, since lines that come late are lines
	// nobody is waiting for. nil leaves ~? as ordinary input, which is what
	// join wants. It is offered only when the terminal's modes are tracked
	// (Pty set): without them there is no telling whether text written now
	// would land inside the session's own escape sequence.
	Status func(ctx context.Context) []string

	Logger *slog.Logger
}

// Reason says how an attachment ended.
type Reason int

const (
	// Detached: the client ended it — the escape key, EOF on Stdin, or ctx.
	Detached Reason = iota
	// Exited: the session sent the command's exit status and closed.
	Exited
	// Disconnected: the session closed the connection without an exit status.
	// The daemon's log says why: a stalled or overflowed client, or a daemon
	// that went away.
	Disconnected
)

func (r Reason) String() string {
	switch r {
	case Detached:
		return "detached"
	case Exited:
		return "exited"
	case Disconnected:
		return "disconnected"
	}
	return fmt.Sprintf("reason(%d)", int(r))
}

// CauseKind is why the daemon ended a session, as it said so itself.
type CauseKind int

const (
	// CauseNone: the daemon said nothing, as one from before the session-end
	// request does. The status is then all there is to go on.
	CauseNone CauseKind = iota
	// CauseExited: the command ended on its own, and Status is its own.
	CauseExited
	// CauseStopped: the session was stopped (upterm session stop).
	CauseStopped
	// CauseSignaled: the daemon, or the command on its own, was killed by a
	// signal; Cause.Signal says which.
	CauseSignaled
	// CauseCanceled: the daemon's run was cancelled.
	CauseCanceled
	// CauseJoinTimeout: no guest joined within the join timeout. The status
	// is 0, which is why a cause is needed to tell this from an ordinary exit.
	CauseJoinTimeout
	// CauseUnknown: the daemon said why, but not in words this client knows:
	// a cause from a later daemon, or a payload this client can't decode. No
	// reason is guessed, and the status isn't taken for the command's either,
	// since the cause may be one that says it isn't.
	CauseUnknown
)

// Cause is why the daemon ended the session, when it said. Kind is CauseNone
// when it did not.
type Cause struct {
	Kind CauseKind
	// For CauseSignaled, the daemon's name for the signal: the SSH name
	// without "SIG" ("TERM"), or the number of one with no name ("40").
	Signal string
}

// Result is how an attachment ended. Status and Cause are meaningful only for
// Exited. Released and Unrestored are Terminal.Run's; Client.Run leaves them
// zero. Cause is Client.Run's, which reads it from the connection's global
// requests; Terminal.Run leaves it zero.
type Result struct {
	Reason Reason
	Status int
	// Cause is why the daemon ended the session, ahead of the status: the
	// status alone cannot say, and for 0 it says nothing at all.
	Cause Cause

	// Released closes once no write from this session to Stdout is in
	// flight: the output copy has returned, and so has every mode write and
	// every status write ~? made. It is already closed when Terminal.Run
	// returns, except after a drain or a mode write that timed out, or with
	// a status write still parked, whose write is still in flight.
	Released <-chan struct{}
	// Unrestored is the mode restore left unwritten because the output was
	// abandoned with the terminal in the session's modes: the drain timed
	// out, a suspend could not take the output from a write parked on the
	// terminal, the write that put the modes back after a suspend did not
	// finish, or the restore could not take the output from a status write
	// parked on the terminal. Empty otherwise: the restore was written or
	// attempted, the process came back without the terminal, or there is no
	// pty and so no modes.
	Unrestored []byte
}

// Run opens a session on client and runs it until it ends. setupBy bounds
// every request before the shell runs: a peer that answered the handshake
// and then stopped answering would otherwise hold NewSession, RequestPty or
// Shell forever, so past it the connection is closed. A zero setupBy has
// long passed, so the connection is closed at once. An error means shell
// startup was not confirmed, and Run has closed client before returning it,
// whatever the cause; once startup was confirmed, every ending is a Result,
// and Run closes the connection as the session ends.
//
// An error comes with the zero Result, whose Released is nil: there is no
// write to wait for, and a receive from it would never return.
func (t *Terminal) Run(ctx context.Context, client *ssh.Client, setupBy time.Time) (_ Result, err error) {
	// Registered first, so it runs last. Closing here, once, leaves no error
	// returning with the connection open. The closes armed below for ctx and
	// setupBy can't be relied on for that: the return stops them, and an
	// error that comes first leaves them unrun.
	defer func() {
		if err != nil {
			_ = client.Close()
		}
	}()
	if t.Stdout == nil {
		return Result{}, errors.New("stdout is required")
	}
	logger := t.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// parent is the caller's context; ctx is the one internal cleanup
	// cancels. Told apart deliberately: see record below.
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Local cancellation never waits on the peer. Closing the connection is
	// the one thing that fails a Wait on a session the daemon will never
	// close, an input write parked on an exhausted window, and a setup
	// request nobody answers: it ends mux.loop, which closes every channel
	// (x/crypto v0.57.0 ssh/mux.go:212-219). Bytes the channel has already
	// received stay readable after it, so the drain below loses nothing the
	// daemon actually sent.
	stopClosing := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClosing()
	// setupBy is enforced the same way, and called off only once the shell
	// is running.
	setup := time.AfterFunc(time.Until(setupBy), func() { _ = client.Close() })
	defer setup.Stop()

	sess, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("opening the session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	if t.Pty != nil {
		size := t.Pty.Size
		if !size.Valid() {
			size = termsize.Default
		}
		if err := sess.RequestPty(t.Pty.Term, size.Rows, size.Cols, ssh.TerminalModes{}); err != nil {
			return Result{}, fmt.Errorf("pty request: %w", err)
		}
	}
	if t.DeclareInteractive {
		if err := sess.Setenv(upterm.AttachInteractiveEnvVar, "1"); err != nil {
			return Result{}, fmt.Errorf("setenv %s: %w", upterm.AttachInteractiveEnvVar, err)
		}
	}
	// Always a pipe, even with no Stdin: leaving Session.Stdin nil makes
	// x/crypto copy from an empty reader and send EOF at once, which ends a
	// viewer's session the moment it starts. A pipe nobody writes to holds the
	// input open until the session ends.
	stdin, err := sess.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := sess.Shell(); err != nil {
		return Result{}, fmt.Errorf("starting the shell: %w", err)
	}
	if !setup.Stop() || time.Now().After(setupBy) {
		// The shell was confirmed just as setupBy passed. Whether the timer
		// has run is a matter of scheduling, and this fails either way: the
		// connection is closed on the way out, as for any error.
		return Result{}, errors.New("the shell started after the setup deadline")
	}
	if t.OnReady != nil {
		t.OnReady()
	}

	// The first cause recorded wins, and internal cleanup never records one.
	// run.Group interrupts every actor as soon as any one returns, so by the
	// time an interrupt runs "cancelled" says nothing about why: only the
	// actor that saw the cause may record it. And once the caller has left,
	// whatever is seen afterwards is a consequence of leaving: ctx is derived
	// from parent, so parent's end cancels ctx too, and Wait failing because
	// the connection was closed on the way out must read as the detach it is.
	var (
		mu     sync.Mutex
		result *Result
	)
	record := func(r Result) {
		if parent.Err() != nil {
			r = Result{Reason: Detached}
		}
		mu.Lock()
		defer mu.Unlock()
		if result == nil {
			result = &r
		}
	}

	// Output runs on its own goroutine, not as an actor: a Stdout that blocks
	// — a stopped terminal, a pipe nobody drains — must not keep Run from
	// returning once the session is gone. It owns Stdout only until
	// abandoned: a write already in flight cannot be interrupted without
	// owning the descriptor, but no later one is started. copyErr is a
	// failed write to Stdout; a read ending, however it ends, is nil, and
	// Wait says what it meant.
	var (
		o = &output{w: t.Stdout, turn: make(chan struct{}, 1), released: make(chan struct{}),
			statusClosing: make(chan struct{})}
		copied  = make(chan struct{})
		copyErr error
	)
	if t.Pty != nil {
		o.modes = uio.NewModeTracker()
		if testHookTracker != nil {
			testHookTracker(o.modes)
		}
	}
	o.writing()
	go func() {
		copyErr = copyOutput(stdout, o)
		// Counted out before copied says so: the tail goes from copied to
		// Released without waiting on this goroutine.
		o.wrote()
		close(copied)
	}()

	var g run.Group
	{
		// The session's end: an exit status, or a close without one. Cancel
		// first, then the courtesy close: run.Group runs interrupts one
		// after another, a channel close is a packet written to the socket,
		// and a daemon that has stopped reading its socket would park it —
		// before the interrupt that cancels, and so before the AfterFunc
		// that closes the connection and releases it. Cancelled first, the
		// close either completes or fails when the connection goes.
		g.Add(func() error {
			record(resultFromWait(sess.Wait()))
			return nil
		}, func(error) {
			cancel()
			_ = sess.Close()
		})
	}
	{
		// Stdout going away is this terminal detaching — EPIPE from a pipe
		// whose reader left, an error from a terminal that closed — and
		// nothing on the session's side would ever report it: with a quiet
		// command nothing else moves. On an ordinary EOF this parks; Wait
		// is what classifies the session's end.
		g.Add(func() error {
			select {
			case <-copied:
				if copyErr != nil {
					record(Result{Reason: Detached})
					return nil
				}
				<-ctx.Done()
			case <-ctx.Done():
			}
			return nil
		}, func(error) { cancel() })
	}
	if t.Stdin != nil {
		g.Add(func() error {
			if t.forwardInput(ctx, sess, stdin, o, logger) {
				record(Result{Reason: Detached})
			}
			return nil
		}, func(error) { cancel() })
	}
	if t.Resizes != nil {
		g.Add(func() error {
			for {
				select {
				case size, ok := <-t.Resizes:
					if !ok {
						<-ctx.Done()
						return nil
					}
					if size.Valid() {
						if err := sess.WindowChange(size.Rows, size.Cols); err != nil {
							// Bounded: this fails when the connection has
							// gone, which is when the group is unwinding,
							// and a handler blocked on a stopped terminal
							// would park the unwind right here.
							logging.LogWithin(logger, slog.LevelDebug, logging.LogBound, "window change not delivered", "error", err)
						}
					}
				case <-ctx.Done():
					return nil
				}
			}
		}, func(error) { cancel() })
	}
	{
		// The caller leaving is a detach. This actor only triggers the
		// unwinding; record itself notices parent's end, so it does not
		// matter which of ctx and parent this select happens to pick.
		g.Add(func() error {
			<-ctx.Done()
			if parent.Err() != nil {
				record(Result{Reason: Detached})
			}
			return nil
		}, func(error) { cancel() })
	}
	_ = g.Run()
	// Nothing more is shown for ~? from here: the attachment is over, and a
	// lookup still under way finds the slot closed. Before the tail, so that
	// the drain writes no status either, and so before Stdout is released.
	o.closeStatus()

	// The tail. The channel's remaining bytes are readable after its close,
	// and Wait can return before the copy has read them.
	//
	// One budget for the whole of it, the copy and the mode restore after it:
	// both write to the same terminal, and a terminal that has stopped stops
	// them both. Nothing here may hold Run — a stopped terminal is exactly
	// when the caller needs it to return.
	tail := time.NewTimer(outputDrainTimeout)
	defer tail.Stop()
	select {
	case <-copied:
		// Everything the session sent has been written, so the terminal is in
		// the modes the session left it in and this is the moment to take it
		// out of them: a full-screen program still running in the session
		// would otherwise leave this terminal's shell on the alternate
		// screen, cursor hidden, mouse reporting on. Restoring the termios
		// settings around this call says nothing about any of that.
		//
		// Here rather than in the copy goroutine because only this path has
		// seen it end, which leaves the tracker free: a suspend, its one
		// other writer, ended with the group. On the timeout below the copy
		// may still be inside a write to a terminal that is not taking
		// bytes, which is the one case where writing more is the wrong
		// answer anyway.
		//
		// On the turn, like every other write, within what is left of the
		// same budget: a status write may still own the output, parked on a
		// terminal that stopped, and a restore written beside it could land
		// in the middle of it once the terminal resumes. If the turn doesn't
		// come, the output is abandoned as on the drain's timeout, the
		// restore unwritten and handed back. The turn is not given back:
		// nothing writes after the restore.
		//
		// A turn that is free is taken first, whatever is left of the
		// budget: with copied and the timer both ready, one select between
		// the turn and the timer would pick either at random, and could give
		// up a restore nothing stood in the way of. Only a turn something
		// holds is waited for, within the budget.
		if !o.abandoned.Load() {
			if restore := o.restore(); len(restore) > 0 {
				taken := false
				select {
				case o.turn <- struct{}{}:
					taken = true
				default:
					select {
					case o.turn <- struct{}{}:
						taken = true
					case <-tail.C:
					}
				}
				if taken {
					o.writeWithin(tail.C, restore, logger)
				} else {
					o.abandon()
					logging.WarnWithin(logger, logging.LogBound, "abandoning the terminal's mode restore: a status write still holds the output", "timeout", outputDrainTimeout)
				}
			}
		}
	case <-tail.C:
		o.abandon()
		logging.WarnWithin(logger, logging.LogBound, "abandoning output still undelivered to the terminal", "timeout", outputDrainTimeout)
	}

	mu.Lock()
	defer mu.Unlock()
	if result == nil {
		// Every actor above records on its own ending; this is defensive.
		result = &Result{Reason: Disconnected}
	}
	result.Released = o.release()
	o.trackerMu.Lock()
	result.Unrestored = o.unrestored
	o.trackerMu.Unlock()
	return *result, nil
}

// output is one Run's hold on Stdout. Four things write to it — the copy of
// the session's output, a suspend's two mode writes, ~?'s status and the
// restore on the way out — and output keeps them in turn, and says when the
// last of them has returned.
type output struct {
	w io.Writer

	// What the session did to this terminal, watched on the way past so it
	// can be undone on the way out. Only for a terminal: a viewer redirected
	// into a pipe or a file is not left in any modes, and mode sequences
	// appended to a captured log are nothing but noise.
	modes *uio.ModeTracker
	// trackerMu is the tracker's own lock. uio.ModeTracker is not safe for
	// concurrent use, and abandon, giving up on a copy parked in a write,
	// reads the tracker without waiting for turn. Held only around the
	// tracker — in the copy, in abandon and in takeStatus, with the abandoned
	// check or set that goes with it — and never across a write to w.
	trackerMu sync.Mutex
	// Whose turn it is to write to w: the copy's for each chunk, a suspend's
	// for as long as the terminal is out of the session's modes, a status's
	// until its write has returned, and the restore's on the way out. A
	// channel rather than a mutex so that a writer can give up waiting for
	// it.
	turn chan struct{}
	// Once set, no write to w is started but the one for a chunk the copy
	// had already fed, which abandon's restore undoes, or for a status
	// already taken, which sets no mode; a write already in flight cannot be
	// interrupted without owning the descriptor. Released waits for them.
	abandoned atomic.Bool
	// unrestored is the restore abandon left unwritten, under trackerMu.
	unrestored []byte

	mu       sync.Mutex
	inFlight int           // goroutines writing to w, or about to
	sealed   bool          // release has been called
	released chan struct{} // closed once sealed with nothing in flight

	// The ~? status waiting to be written: one slot, served where the
	// terminal will read it as text, by whoever holds turn there — the copy
	// at a chunk's end, or showStatus while the output is idle. statusMu is
	// taken inside trackerMu, never the other way round, and never across a
	// write.
	statusMu      sync.Mutex
	status        *statusOffer // nil when nothing is waiting
	statusClosed  bool
	statusClosing chan struct{} // closed by closeStatus
}

// statusOffer is one ~?'s lines, as the one write they are made in, and what
// closes once they are gone from the slot: written, dropped, or discarded.
type statusOffer struct {
	p     []byte
	taken chan struct{}
}

// writing counts a goroutine about to write to w; wrote counts it out once
// its write has returned.
func (o *output) writing() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight++
}

func (o *output) wrote() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight--
	if o.sealed && o.inFlight == 0 {
		close(o.released)
	}
}

// release says that no further write will start, and returns what closes
// once the last one in flight has returned: at once, unless a write is still
// parked.
func (o *output) release() <-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sealed = true
	if o.inFlight == 0 {
		close(o.released)
	}
	return o.released
}

// restore and snapshot are the tracker's, taken under trackerMu; nil without
// a tracker.
func (o *output) restore() []byte {
	if o.modes == nil {
		return nil
	}
	o.trackerMu.Lock()
	defer o.trackerMu.Unlock()
	return o.modes.Restore()
}

func (o *output) snapshot() []byte {
	if o.modes == nil {
		return nil
	}
	o.trackerMu.Lock()
	defer o.trackerMu.Unlock()
	return o.modes.Snapshot()
}

// abandon gives up w while the terminal is, or is about to be, in the
// session's modes, and keeps the restore that leaves unwritten. The two are
// one hold of trackerMu: a chunk the copy has fed is in that restore, and one
// it has not is never written, so the restore undoes every chunk written or
// still being written.
//
// Only the call that gives the output up records a restore. One that finds it
// already given up leaves what is there: an earlier abandon's restore, which
// nothing fed since can have changed, or none, from a suspend that gave the
// output up having already taken the terminal out of the session's modes.
func (o *output) abandon() {
	o.trackerMu.Lock()
	defer o.trackerMu.Unlock()
	if o.abandoned.Swap(true) || o.modes == nil {
		return
	}
	o.unrestored = o.modes.Restore()
}

// offerStatus puts lines in the status slot, each \r\n-ended, as the one
// write they go out in, so that they arrive whole and are never split across
// the session's chunks. The write starts with \r\n too, as OpenSSH's ~? does,
// so the first line is a line of its own rather than the end of whatever the
// cursor was on, a shell's prompt as often as not. It returns false once the
// slot is closed — teardown has begun, and a lookup finishing now has nowhere
// to go — when an offer is already waiting in it, or when there is nothing to
// show. taken closes once the lines are gone from the slot.
//
// An offer already waiting is kept, not replaced: its taken is what its own
// showStatus waits on, and an offer put over it would leave that one waiting
// on a channel nothing closes.
//
// The lines are text alone, as uio.PlainText has it. They carry what others
// chose — a guest's SSH version is whatever its client sent — and the
// tracker never sees them, so a status that started a sequence or set a mode
// of its own would leave the terminal where the tracker doesn't know it is,
// and the session's next bytes inside whatever it opened.
func (o *output) offerStatus(lines []string) (taken <-chan struct{}, ok bool) {
	if len(lines) == 0 {
		return nil, false
	}
	p := []byte("\r\n")
	for _, l := range lines {
		p = append(p, uio.PlainText(l)...)
		p = append(p, '\r', '\n')
	}
	o.statusMu.Lock()
	defer o.statusMu.Unlock()
	if o.statusClosed || o.status != nil {
		return nil, false
	}
	offer := &statusOffer{p: p, taken: make(chan struct{})}
	o.status = offer
	return offer.taken, true
}

// takeStatus hands the waiting status to a caller holding turn, if the
// terminal would read it as text here: the output has not been abandoned, and
// the session's output has left the terminal outside every sequence, on
// InSequence's cautious reading, and in ASCII. The session's output can stop
// inside an OSC, a CSI, a DCS, a charset designation or a UTF-8 character at a
// chunk's end, and text written there would be read as part of it; and with
// DEC Special Graphics in G0, or after a shift-out, text is drawn as line
// pieces. Otherwise the status stays in the slot, for a later chunk's end or
// for its bound to drop it.
//
// The charset is waited out rather than switched: an ESC ( B or an SI written
// ahead of the status would leave the terminal in ASCII while the program,
// and the tracker, believe it is still in graphics.
//
// Nothing ever cancels the session's sequence to make room: no CAN, no ST.
// Terminals disagree on where a cancelled string ends (kitty keeps an OSC open
// at CAN), and cancelling ESC [ ? 1000 before its "l" would leave mouse
// reporting on with the tracker recording it off.
//
// counted says whether the caller is already counted in flight, as the copy
// is. One that is not is counted here, in the same hold of statusMu as the
// take: a take that closeStatus did not stop is then always a write Released
// waits for.
func (o *output) takeStatus(counted bool) []byte {
	if o.modes == nil {
		return nil
	}
	o.trackerMu.Lock()
	defer o.trackerMu.Unlock()
	if o.abandoned.Load() || o.modes.InSequence() || o.modes.NonASCIICharset() {
		return nil
	}
	o.statusMu.Lock()
	defer o.statusMu.Unlock()
	offer := o.status
	if offer == nil {
		return nil
	}
	o.status = nil
	close(offer.taken)
	if !counted {
		o.writing()
	}
	return offer.p
}

// dropStatus drops the offer taken belongs to, if it is still in the slot, and
// logs why. Bounded, like every diagnostic on a path a stopped terminal can
// reach.
func (o *output) dropStatus(taken <-chan struct{}, logger *slog.Logger, why string, bound time.Duration) {
	o.statusMu.Lock()
	offer := o.status
	dropped := offer != nil && offer.taken == taken
	if dropped {
		o.status = nil
		close(offer.taken)
	}
	o.statusMu.Unlock()
	if dropped {
		logging.WarnWithin(logger, logging.LogBound, "not showing the session's status: "+why, "timeout", bound)
	}
}

// closeStatus closes the slot, before Run releases Stdout: a status still in
// it is discarded, so is the result of a lookup that finishes later, and no
// status write starts from here on. One already taken is a write in flight,
// which Released waits for like any other; it may land later, on a terminal
// that resumes, as an abandoned copy's may.
func (o *output) closeStatus() {
	o.statusMu.Lock()
	defer o.statusMu.Unlock()
	if o.statusClosed {
		return
	}
	o.statusClosed = true
	if o.status != nil {
		close(o.status.taken)
		o.status = nil
	}
	close(o.statusClosing)
}

// showStatus is ~?: it asks Status for the lines and puts them on the
// terminal where they land as text, or drops them. It runs on a goroutine of
// its own, never the input's, so that neither a lookup nor a terminal that
// has stopped taking bytes ever holds up ~. or the session's end.
//
// The copy writes the lines at the end of a chunk, on the turn it already
// holds, once the session's output is outside every sequence and in ASCII, as
// takeStatus has it. With the output idle nothing would, so this takes the
// turn the way a suspend does, within turnWait (outputDrainTimeout) because
// the copy may be parked in a write to a terminal that has stopped, and
// writes them itself if the output is there. If it is not, the lines wait for
// the copy to come out of it, within safeWait (statusSafeTimeout) of being
// offered; past either bound they are dropped, and the input carries on. A
// dropped status shows nothing, the one case ~? does, and pressing it again
// works once the program has moved on.
//
// A write of its own owns the output until it returns, not until a deadline:
// a write cannot be interrupted, and a turn given back at a deadline would let
// the session's next chunk race the status bytes still parked on the
// terminal. The copy waits for the turn meanwhile, which costs nothing: it
// would be parked on the same stopped terminal. The write is counted in
// flight, so Released waits for it.
func (t *Terminal) showStatus(ctx context.Context, o *output, safeWait, turnWait time.Duration, logger *slog.Logger) {
	taken, ok := o.offerStatus(t.Status(ctx))
	if !ok {
		return
	}
	safe := time.NewTimer(safeWait)
	defer safe.Stop()
	wait := time.NewTimer(turnWait)
	defer wait.Stop()
	select {
	case o.turn <- struct{}{}:
	case <-taken:
		// Written at the end of a chunk while this waited.
		return
	case <-wait.C:
		o.dropStatus(taken, logger, "the terminal is not taking output", turnWait)
		return
	case <-o.statusClosing:
		return
	}
	if p := o.takeStatus(false); p != nil {
		err := writeAll(o.w, p)
		o.wrote()
		<-o.turn
		if err != nil {
			logging.WarnWithin(logger, logging.LogBound, "could not show the session's status", "error", err)
		}
		return
	}
	<-o.turn
	select {
	case <-taken:
	case <-safe.C:
		o.dropStatus(taken, logger, "the session's output stayed inside an escape sequence", safeWait)
	case <-o.statusClosing:
	}
}

// writeAll writes p to w, a short write being a failed one, as io.Copy has
// it.
func writeAll(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}

// suspend stops the process and puts the session back in step with the
// terminal that comes back.
//
// The terminal goes to the shell out of the session's modes, as a detach
// leaves it; otherwise the shell's prompt is drawn on the alternate screen,
// with no cursor and the mouse reporting clicks as input. It is put back into
// them only if it is this client's again, and before the WINCH below, so the
// program repaints onto the screen it believes it is drawing on. The way back
// is the tracker's Snapshot, the bytes a joiner is given, partial sequence
// included: a chunk that stopped mid-sequence before the suspend is followed
// by one that completes it rather than printing.
//
// The output is held from the one to the other: written in between, it would
// be drawn over the shell's screen, and a mode it set would make a liar of
// the restore. The hold is taken from the copy within outputDrainTimeout,
// because the copy may be parked in a write to a terminal that has stopped
// taking bytes, and nothing interrupts that.
//
// It reports whether the terminal is still this client's to draw on. It is
// not when the process came back without it — bg: the terminal is the
// foreground job's, and SIGTTOU, ignored, stops no write to it — or when the
// terminal stopped taking bytes within the bound, leaving a write parked
// that completes whenever it can, beside anything written after it. Then
// Stdout is abandoned before the hold is released, so nothing more is
// written, and the caller detaches. If the terminal stopped before the
// process did, the process is not stopped at all: the parked write would
// land on the foreground shell's screen once bg continued it.
//
// Then, if it is, two requests, both best-effort: the size, because the
// terminal may have been resized while this process was stopped, and a
// WINCH, because a full-screen program repaints on it and the scrollback
// this client stopped reading is already behind it.
//
// Both are bounded for the reason every other request on this path is: they
// fail when the connection has gone, which is when the group is unwinding,
// and a handler blocked on a stopped terminal would park the unwind here.
func (t *Terminal) suspend(sess *ssh.Session, o *output, logger *slog.Logger) (kept bool) {
	if o.modes != nil {
		leave := time.NewTimer(outputDrainTimeout)
		defer leave.Stop()
		select {
		case o.turn <- struct{}{}:
		case <-leave.C:
			// Still in the session's modes, with nothing written to take it
			// out of them.
			o.abandon()
			logging.WarnWithin(logger, logging.LogBound, "detaching instead of suspending: the terminal is not taking output", "timeout", outputDrainTimeout)
			return false
		}
		if restore := o.restore(); len(restore) > 0 && !o.writeWithin(leave.C, restore, logger) {
			o.abandoned.Store(true)
			<-o.turn
			return false
		}
	}
	size, kept := t.Suspend()
	if kept && o.modes != nil {
		back := time.NewTimer(outputDrainTimeout)
		defer back.Stop()
		if snapshot := o.snapshot(); len(snapshot) > 0 && !o.writeWithin(back.C, snapshot, logger) {
			// The session's modes are on their way back, in a write that
			// timed out and may yet land, or that failed having written some
			// of them, and nothing here will take the terminal out of them
			// again.
			o.abandon()
			<-o.turn
			return false
		}
	}
	if !kept {
		o.abandoned.Store(true)
	}
	if o.modes != nil {
		<-o.turn
	}
	if !kept {
		return false
	}
	if t.Pty != nil && size.Valid() {
		if err := sess.WindowChange(size.Rows, size.Cols); err != nil {
			logging.LogWithin(logger, slog.LevelDebug, logging.LogBound, "window change not delivered after resume", "error", err)
		}
	}
	// x/crypto has no SIGWINCH constant — RFC 4254 does not list it — and
	// ssh.Signal is a string, so the request is spelled out.
	if err := sess.Signal(ssh.Signal("WINCH")); err != nil {
		logging.LogWithin(logger, slog.LevelDebug, logging.LogBound, "redraw nudge not delivered after resume", "error", err)
	}
	return true
}

// writeWithin writes p to w, giving up on waiting for it when deadline
// fires, and reports whether the terminal took it. It exists for the mode
// writes: the restore Run makes after the session is gone, and the two a
// suspend makes around the stop.
//
// The write is on a goroutine because a write to a terminal cannot be
// interrupted: it is the descriptor's owner that would have to close it, and
// Run does not own Stdout. So the wait is what ends, not the write — the same
// bargain the abandoned output copy makes, and for the same reason. What is
// left behind is one goroutine holding a handful of bytes for a terminal that
// is not reading; if that terminal ever resumes, what lands on it is a reset
// to the defaults, which is the least harmful thing that could arrive late.
// Released waits for it.
//
// Its error is logged within a bound too: this is the path a stopped terminal
// takes, and a logger writing to that same terminal is the classic way to
// turn a bounded wait into an unbounded one.
func (o *output) writeWithin(deadline <-chan time.Time, p []byte, logger *slog.Logger) (written bool) {
	done := make(chan error, 1)
	o.writing()
	go func() {
		_, err := o.w.Write(p)
		// Counted out before done says so, so that a write waited for is
		// never still in flight when Run releases Stdout.
		o.wrote()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			logging.WarnWithin(logger, logging.LogBound, "could not restore the terminal's modes", "error", err)
		}
		return err == nil
	case <-deadline:
		logging.WarnWithin(logger, logging.LogBound, "the terminal did not take its mode restore", "timeout", outputDrainTimeout)
		return false
	}
}

// copyOutput copies the session's output into o's writer until the session's
// side ends or a write fails, checking abandoned before every write. It
// returns the write error — a short write is one, as io.Copy has it — and
// nil for every way the read can end.
//
// The tracker, when there is one, observes everything on its way to the
// terminal, so that the terminal can be put back afterwards. It is fed what
// was read rather than what was written: a write that fails has still reached
// the terminal as far as the modes in it are concerned, and the tracker is the
// record of what this terminal was asked to do, not of what arrived. Each
// chunk is fed and written on turn, which a suspend takes to keep the
// terminal to itself while it is out of the session's modes; the check and
// the feed are one hold of trackerMu, so an abandon, the tail's or a
// suspend's, reads the tracker either before a chunk or after all of it.
//
// A chunk's end is also where a waiting ~? status goes, on the same turn, if
// the chunk left the terminal outside every sequence and in ASCII: written
// whole, and never between two halves of the session's output. A failed
// status write is a failed write to Stdout like any other.
func copyOutput(r io.Reader, o *output) error {
	buf := make([]byte, 32<<10)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			o.turn <- struct{}{}
			o.trackerMu.Lock()
			abandoned := o.abandoned.Load()
			if !abandoned && o.modes != nil {
				if testHookFeeding != nil {
					testHookFeeding()
				}
				_, _ = o.modes.Write(buf[:n])
			}
			o.trackerMu.Unlock()
			if abandoned {
				<-o.turn
				return nil
			}
			werr := writeAll(o.w, buf[:n])
			if werr == nil {
				if p := o.takeStatus(true); p != nil {
					werr = writeAll(o.w, p)
				}
			}
			<-o.turn
			if werr != nil {
				return werr
			}
		}
		if rerr != nil {
			return nil
		}
	}
}

// forwardInput copies Stdin to the session through the escape filter. It
// reports true when the client is leaving of its own accord — the escape
// sequence completed, or Stdin ended, which from a terminal means the
// terminal went away — and false when it was unblocked by ctx, which is the
// session ending for some other reason that Wait will report.
//
// Reading and delivering are separate goroutines, because a session that has
// stopped taking input ends them differently. Its pty write is parked because
// the command is not reading, so the channel's window is exhausted, and the
// write that hits it returns only when the connection closes. Escape
// recognition lives in what has been read, so a client that read and wrote on
// one goroutine would stop reading exactly when the one escape that exists to
// get out of this is typed: the Enter before ~. parks, and the ~. is never
// seen. The reader therefore queues, and the writer parks.
//
// It does not close the session's input on the way out. That close is an
// EOF packet written to the socket, and a daemon that has stopped reading
// would park it here, before the caller has recorded the detach and before
// anything has cancelled: the attachment is ending either way, and the
// connection close that follows cancellation says so.
func (t *Terminal) forwardInput(ctx context.Context, sess *ssh.Session, stdin io.Writer, o *output, logger *slog.Logger) (detached bool) {
	var opts []EscapeOption
	if t.Status != nil && o.modes != nil {
		opts = append(opts, WithStatus())
	}
	filter := NewEscapeFilter(t.Escape, t.Suspend != nil, opts...)
	// One ~? at a time: one pressed while another is still being looked up
	// or written is dropped, so a terminal that has stopped taking bytes
	// collects no goroutines however often it is pressed. Its bounds are read
	// here, once: a showStatus can outlive Run, and a test that shortens one
	// puts it back once Run has returned.
	var showing atomic.Bool
	safeWait, turnWait := statusSafeTimeout, outputDrainTimeout
	buf := make([]byte, 4096)
	r := uio.NewContextReader(ctx, t.Stdin)

	q := newInputQueue()
	// Closed on every path, including the ones that do not wait: it is what
	// the writer ends on, and a queue left open leaks it.
	defer q.close()
	go q.drainTo(stdin)

	// flush waits for what the session is still owed — the Enter before ~., a
	// held escape byte at EOF — under the same bound a single delivery used
	// to get, now applied to the queue. Past it the writer is abandoned where
	// it is parked, and the connection close that follows cancellation
	// releases it.
	flush := func() {
		q.close()
		q.waitDrained(inputFlushTimeout)
	}

	dropped := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out, action := filter.Feed(buf[:n])
			if action == EscapeDetach {
				// The bytes before the escape are the session's — the Enter
				// that preceded ~. — but a detach that has been detected
				// must reach the cancellation machinery whether or not the
				// session is still taking input, so they are queued and
				// waited for rather than written here. With the backlog
				// already full they are dropped like any other byte: the
				// policy does not change for the last read, and a session
				// that has taken nothing for a megabyte will not take this.
				q.append(out)
				flush()
				return true
			}
			if !q.append(out) && !dropped {
				// Dropped rather than waited on, deliberately: a session that
				// is not reading will never see these bytes, and blocking for
				// it is the defect this queue exists to fix — OpenSSH stops
				// reading the terminal here, which is no better. Once per
				// attachment, and bounded: this runs on the goroutine that
				// has to stay responsive.
				dropped = true
				logging.WarnWithin(logger, logging.LogBound, "dropping input: the session is not taking it",
					"backlog-bytes", inputBacklogLimit)
			}
			if action == EscapeStatus && showing.CompareAndSwap(false, true) {
				// Off this goroutine, which has to stay free for ~. and for
				// the session's end, however long the lookup and the
				// terminal take.
				go func() {
					defer showing.Store(false)
					t.showStatus(ctx, o, safeWait, turnWait, logger)
				}()
			}
			if action == EscapeSuspend && !t.suspend(sess, o, logger) {
				flush()
				return true
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			// Stdin ended: the terminal is gone. An escape byte held back
			// was real input; it is delivered under the same bound, for
			// the same reason.
			q.append(filter.Flush())
			flush()
			return true
		}
		if q.stopped() {
			// The session went away under us; Wait says how.
			return false
		}
	}
}

// inputQueue hands keystrokes from forwardInput's reader to its writer. The
// reader never blocks on it, which is the point; the writer parks in the
// session's Write for as long as the session is not taking input.
type inputQueue struct {
	mu     sync.Mutex
	more   *sync.Cond
	buf    []byte
	closed bool

	// done is closed by drainTo on its way out, which is the one thing that
	// says what was queued has been delivered — or that it never will be.
	done chan struct{}
}

func newInputQueue() *inputQueue {
	q := &inputQueue{done: make(chan struct{})}
	q.more = sync.NewCond(&q.mu)
	return q
}

// append queues p and reports whether it was taken. Beyond inputBacklogLimit
// it is not: the session has stopped reading and nothing queued for it is
// going anywhere.
func (q *inputQueue) append(p []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf)+len(p) > inputBacklogLimit {
		return false
	}
	q.buf = append(q.buf, p...)
	q.more.Broadcast()
	return true
}

// next blocks until there is something to write, or until the queue is closed
// and empty. What it returns is the caller's.
func (q *inputQueue) next() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.buf) == 0 && !q.closed {
		q.more.Wait()
	}
	if len(q.buf) == 0 {
		return nil, false
	}
	p := q.buf
	q.buf = nil
	return p, true
}

// close says no more keystrokes are coming. Idempotent: every way out of
// forwardInput reaches it, and two of them reach it twice.
func (q *inputQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.more.Broadcast()
}

// stopped reports that the writer has gone: either everything queued has been
// delivered and the queue is closed, or a write failed and nothing more will
// be delivered.
func (q *inputQueue) stopped() bool {
	select {
	case <-q.done:
		return true
	default:
		return false
	}
}

// waitDrained waits at most timeout for the writer to finish.
func (q *inputQueue) waitDrained(timeout time.Duration) {
	select {
	case <-q.done:
	case <-time.After(timeout):
	}
}

// drainTo writes what the reader queues into w until the queue is closed and
// empty, or a write fails.
func (q *inputQueue) drainTo(w io.Writer) {
	defer close(q.done)
	for {
		p, ok := q.next()
		if !ok {
			return
		}
		if _, err := w.Write(p); err != nil {
			// The session went away under us; the reader notices through
			// stopped and Wait says how.
			return
		}
	}
}

func resultFromWait(err error) Result {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return Result{Reason: Exited, Status: 0}
	case errors.As(err, &exit):
		return Result{Reason: Exited, Status: exit.ExitStatus()}
	case errors.As(err, &missing):
		return Result{Reason: Disconnected}
	default:
		// The connection went away under the session: no close message, no
		// status. What the daemon knows about it is in its log.
		return Result{Reason: Disconnected}
	}
}
