//go:build !windows

package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gssh "charm.land/ssh"
	ptylib "github.com/creack/pty"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// The terminals the tests below join with, and the pty they make: a session
// takes the minimum over its terminals, per dimension.
var (
	desktop = termsize.Size{Cols: 80, Rows: 24}
	phone   = termsize.Size{Cols: 45, Rows: 30}
	// desktopAndPhone is the pty with both of those attached.
	desktopAndPhone = termsize.Size{Cols: 45, Rows: 24}
	// tablet is smaller than both in each dimension, so a pty it joins is at
	// exactly its size, whoever else is attached.
	tablet = termsize.Size{Cols: 40, Rows: 20}
)

// ringMark is what a session holds before anyone joins it. A join needs
// something in the ring to reach a replayer at all: with the ring empty it
// takes Append's path.
const ringMark = "RING-MARK"

// emulatedMark heads every render a doorReplayer's emulation makes, so that
// a joiner's bytes say whether it was handed a reconstruction or the raw
// ring.
const emulatedMark = "<emulated>"

// errNoReplay is what a doorReplayer's start hook returns to have the join
// fall back to the raw ring, which it is attached with.
var errNoReplay = errors.New("the test's replayer declines")

// printsTheRing is a session's command that prints ringMark and then says
// nothing more until the session ends.
var printsTheRing = []string{"sh", "-c", "printf '" + ringMark + "\\n'; exec sleep 600"}

// doorReplayer is a Replayer a test installs at the doors' seam
// (installReplayer) or on a rig's fan-out. Start records each join it is
// handed, then runs the start hook, if set: an error from it is Start's, and
// so is a panic. Otherwise the emulation consumes all it is offered, hands
// off at the end of it, and renders emulatedMark and the bytes it consumed.
type doorReplayer struct {
	// start runs in each Start, with the join's index among the replayer's
	// Starts and the join's ctx.
	start func(n int, ctx context.Context) error

	// started hears each join as its Start begins.
	started chan startedJoin

	mu    sync.Mutex
	joins []startedJoin
}

// startedJoin is what one Start was handed.
type startedJoin struct {
	size termsize.Size // the joiner's terminal
	// newest is the size of the capture's newest event: the pty's size, as
	// the capture found it.
	newest termsize.Size
	// left is how much of the join's budget was left as Start began.
	left time.Duration
}

func newDoorReplayer() *doorReplayer {
	return &doorReplayer{started: make(chan startedJoin, 16)}
}

func (r *doorReplayer) Start(ctx context.Context, deadline time.Time, c *uio.Capture, size termsize.Size) (uio.Emulation, error) {
	j := startedJoin{size: size, left: time.Until(deadline)}
	if len(c.Sizes) > 0 {
		j.newest = c.Sizes[len(c.Sizes)-1].Size
	}
	r.mu.Lock()
	n := len(r.joins)
	r.joins = append(r.joins, j)
	r.mu.Unlock()
	r.started <- j

	if r.start != nil {
		if err := r.start(n, ctx); err != nil {
			return nil, err
		}
	}
	e := &doorEmulation{end: c.Start}
	_ = e.Feed(c.Chunks, c.Sizes)
	return e, nil
}

// seen returns every join Start has been handed so far, in order.
func (r *doorReplayer) seen() []startedJoin {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]startedJoin(nil), r.joins...)
}

// next returns the next join to reach Start, failing the test if none does
// within harnessTimeout.
func (r *doorReplayer) next(t *testing.T) startedJoin {
	t.Helper()
	select {
	case j := <-r.started:
		return j
	case <-time.After(harnessTimeout):
		t.Fatal("no join reached the replayer")
		return startedJoin{}
	}
}

// doorEmulation is a doorReplayer's emulation when nothing stops it.
type doorEmulation struct {
	consumed     []byte
	end, lastSeq uint64
}

func (e *doorEmulation) Feed(chunks [][]byte, sizes []uio.SizeEvent) error {
	for _, c := range chunks {
		e.consumed = append(e.consumed, c...)
		e.end += uint64(len(c))
	}
	if len(sizes) > 0 {
		e.lastSeq = sizes[len(sizes)-1].Seq
	}
	return nil
}

func (e *doorEmulation) Handoff() (uint64, uint64) { return e.end, e.lastSeq }

func (e *doorEmulation) Render() ([]byte, error) {
	return append([]byte(emulatedMark), e.consumed...), nil
}

// installReplayer has every session ServeWithContext builds from here on
// use r. Called before startHost, as capturePacer is, for the same reason.
func installReplayer(t *testing.T, r uio.Replayer) {
	t.Helper()
	sessionReplayer = func() uio.Replayer { return r }
	t.Cleanup(func() { sessionReplayer = nil })
}

// The pty takes the minimum over the terminals attached, per dimension.
// (a) No other terminal (a viewer only, the session at its 80x24 start
// size): a 45x30 guest's capture sees 45x30 as the newest event.
// (b) An 80x24 terminal attached: the same guest's capture sees 45x24.
// A test Replayer records Capture.Sizes' last size.
//
// The sizes the capture sees are the ones the session's pty reported to the
// fan-out, so this is also what pins command.Start handing startPty the
// fan-out as its reporter: with no reporter, no size covers the ring, and
// every join falls back before the replayer.
func TestTheJoinerResizesThePtyBeforeTheCapture(t *testing.T) {
	const noReporter = "the join never reached the replayer: no size covered the ring, " +
		"so the session's pty reported none (command.Start passes startPty its fan-out)"

	t.Run("no other terminal", func(t *testing.T) {
		r := newDoorReplayer()
		installReplayer(t, r)
		h := startHost(t, &Server{Command: printsTheRing})
		// A viewer has no terminal and counts towards no size: the session
		// stays at the 80x24 it started at, and its ring now holds output.
		_, viewer, _ := h.connectHost(t, nil)
		readUntil(t, viewer, ringMark)

		_, out := h.connectGuest(t, withWindow(phone))
		readUntil(t, out, ringMark)

		joins := r.seen()
		require.Len(t, joins, 1, noReporter)
		require.Equal(t, phone, joins[0].size)
		require.Equal(t, phone, joins[0].newest, "the capture was taken before the pty had the joiner's size")
	})

	t.Run("an 80x24 terminal attached", func(t *testing.T) {
		r := newDoorReplayer()
		installReplayer(t, r)
		h := startHost(t, &Server{Command: printsTheRing})
		_, viewer, _ := h.connectHost(t, nil)
		readUntil(t, viewer, ringMark)
		_, desk := h.connectGuest(t, withWindow(desktop))
		readUntil(t, desk, ringMark)

		_, out := h.connectGuest(t, withWindow(phone))
		readUntil(t, out, ringMark)

		joins := r.seen()
		require.Len(t, joins, 2, noReporter)
		require.Equal(t, phone, joins[1].size)
		require.Equal(t, desktopAndPhone, joins[1].newest, "the capture was taken before the pty had the joiner's size")
	})
}

// For each outcome that attaches nothing after the resize (Shutdown first,
// ctx cancelled while a gated Replayer runs, ctx cancelled while the join
// waits for the fan-out's lock with nothing to emulate, a refusal at the
// pacer's gate, a sink whose Write fails): the pty is back at the size
// without the joiner. A Replayer that panics instead: the joiner gets the raw fallback,
// is attached, and the pty keeps its size.
//
// Every outcome on both doors but the pacer's gate, which only guests pass.
// An 80x24 terminal is attached throughout, so that the size without the
// joiner is one the pty can be put back to: with no terminal left, a pty
// keeps the size it has.
func TestAFailedJoinTakesItsTerminalOutAgain(t *testing.T) {
	// The pty's sizes on a failed join: counted before the capture, then
	// taken out again.
	countedThenTakenOut := []termsize.Size{desktop, desktopAndPhone, desktop}

	for _, tc := range []struct {
		name      string
		guestOnly bool
		run       func(t *testing.T, kind clientKind)
	}{
		{name: "Shutdown first", run: func(t *testing.T, kind clientKind) {
			r := newDoorReplayer()
			rig := newJoinRig(t, r, uio.DefaultReplayBytes, false)
			require.NoError(t, rig.writers.Shutdown(t.Context()))

			j := rig.join(t, kind, phone)
			j.awaitDone(t)
			require.Equal(t, []int{0}, j.exitCodes(), "a client that arrived as the session ended is told 0")
			require.Empty(t, r.seen(), "a join to a fan-out already shut down reached the replayer")
			require.Equal(t, countedThenTakenOut, rig.sizes.applied())
			require.Equal(t, desktop, rig.ptySize(t))
		}},
		{name: "the joiner leaves while its replay runs", run: func(t *testing.T, kind clientKind) {
			r := newDoorReplayer()
			r.start = func(_ int, ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}
			rig := newJoinRig(t, r, uio.DefaultReplayBytes, false)

			j := rig.join(t, kind, phone)
			require.Equal(t, phone, r.next(t).size)
			require.Equal(t, desktopAndPhone, rig.ptySize(t), "the joiner was not counted before the capture")
			j.leave()
			j.awaitDone(t)
			require.Empty(t, j.exitCodes(), "a client that left was sent a status")
			require.Equal(t, countedThenTakenOut, rig.sizes.applied())
			require.Equal(t, desktop, rig.ptySize(t))
		}},
		{name: "the joiner leaves while it waits for the fan-out, with nothing to emulate", run: func(t *testing.T, kind clientKind) {
			// No replayer: the join is attached by the raw ring, and has to
			// find out its client is gone from the hold of the fan-out's lock
			// that would attach it. Nothing before that hold asks.
			rig := newJoinRig(t, nil, uio.DefaultReplayBytes, false)
			logs := &recordingWriter{}
			rig.handler.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			var hostAttached atomic.Bool
			rig.handler.onHostClientAttached = func() { hostAttached.Store(true) }
			member := newParkingMember()
			require.NoError(t, rig.writers.Append(member))
			member.park(t, rig.writers)

			j := rig.join(t, kind, phone)
			// After the joiner's own cleanup is registered, so it runs before:
			// a failed test doesn't leave the join waiting on it.
			t.Cleanup(member.release)
			// Counted, so past its deadline and its resize, and on its way to
			// the lock the parked Write holds.
			rig.sizes.await(t, desktopAndPhone)
			j.leave()
			member.release()
			j.awaitDone(t)
			require.Empty(t, j.exitCodes(), "a client that left was sent a status")
			require.False(t, hostAttached.Load(), "a client that left was reported attached")
			require.Contains(t, string(logs.bytes()), "left before its output was attached",
				"a client that left was attached by the raw ring")
			require.Equal(t, countedThenTakenOut, rig.sizes.applied())
			require.Equal(t, desktop, rig.ptySize(t))
		}},
		{name: "a refusal at the pacer's gate", guestOnly: true, run: func(t *testing.T, kind clientKind) {
			r := newDoorReplayer()
			rig := newJoinRig(t, r, uio.DefaultReplayBytes, true)
			rig.holdTheGate(t)

			j := rig.join(t, kind, phone)
			// Counted, so past its deadline and its resize, and at the gate.
			rig.sizes.await(t, desktopAndPhone)
			j.leave()
			j.awaitDone(t)
			require.Empty(t, j.exitCodes(), "a client that left was sent a status")
			require.Empty(t, r.seen(), "a joiner refused at the pacer's gate reached the replayer")
			require.Equal(t, countedThenTakenOut, rig.sizes.applied())
			require.Equal(t, desktop, rig.ptySize(t))
		}},
		{name: "a sink whose Write fails", run: func(t *testing.T, kind clientKind) {
			r := newDoorReplayer()
			r.start = func(int, context.Context) error { return errNoReplay }
			rig := newJoinRig(t, r, 2*uio.DefaultGuestBufferSize, false)
			// More than a joiner's sink holds, in one chunk: the raw ring the
			// join falls back to overflows the sink as it is handed over.
			_, err := rig.writers.Write(bytes.Repeat([]byte("x"), uio.DefaultGuestBufferSize+1))
			require.NoError(t, err)

			j := rig.join(t, kind, phone)
			j.awaitDone(t)
			require.Equal(t, []int{1}, j.exitCodes(), "a client whose output couldn't be attached is told 1")
			require.Len(t, r.seen(), 1, "the join never reached the replayer")
			require.Equal(t, countedThenTakenOut, rig.sizes.applied())
			require.Equal(t, desktop, rig.ptySize(t))
		}},
		{name: "a replayer that panics", run: func(t *testing.T, kind clientKind) {
			r := newDoorReplayer()
			r.start = func(int, context.Context) error { panic("the test's replayer panics") }
			rig := newJoinRig(t, r, uio.DefaultReplayBytes, false)

			j := rig.join(t, kind, phone)
			attached := j.awaitSettled(t)
			require.Equal(t, []termsize.Size{desktop, desktopAndPhone}, rig.sizes.applied(),
				"a join attached by the raw fallback lost its size")
			require.Equal(t, desktopAndPhone, rig.ptySize(t))
			require.True(t, attached, "the joiner's handler returned rather than attaching it")
			got := j.out.await(t, ringMark)
			require.NotContains(t, got, emulatedMark, "a replay that panicked was handed over")

			// Its own leaving takes it out, as any attached terminal's does.
			j.leave()
			j.awaitDone(t)
			require.Equal(t, desktop, rig.ptySize(t))
		}},
	} {
		for _, door := range []struct {
			name string
			kind clientKind
		}{{"guest", kindGuest}, {"host", kindHost}} {
			if tc.guestOnly && door.kind != kindGuest {
				continue
			}
			t.Run(door.name+"/"+tc.name, func(t *testing.T) { tc.run(t, door.kind) })
		}
	}
}

// The fan-out's lock can be held indefinitely: a synchronous primary, the
// host's own terminal, parked in a write to a terminal that has stopped holds
// it for as long as the terminal stays stopped. A join that wants the lock
// waits for it, and the terminal it has counted constrains the pty meanwhile.
// When the joiner hangs up in that wait, the pty goes back to the size without
// it at once, not when the lock is released: the departure that takes a
// terminal out is an actor, and none has started for a join that has not
// attached. Once the lock is released the joiner's handler returns, finding
// its client gone, and nothing puts the terminal back.
//
// Both doors, as both count a terminal before they attach it. The parked
// member stands for the primary: what holds the lock is a Write parked in the
// fan-out, whoever's it is.
func TestAJoinerThatLeavesStopsConstrainingThePtyWhileTheFanOutIsHeld(t *testing.T) {
	for _, door := range []struct {
		name string
		kind clientKind
	}{{"guest", kindGuest}, {"host", kindHost}} {
		t.Run(door.name, func(t *testing.T) {
			rig := newJoinRig(t, nil, uio.DefaultReplayBytes, false)
			var hostAttached atomic.Bool
			rig.handler.onHostClientAttached = func() { hostAttached.Store(true) }
			member := newParkingMember()
			require.NoError(t, rig.writers.Append(member))
			member.park(t, rig.writers)

			j := rig.join(t, door.kind, phone)
			// After the joiner's own cleanup is registered, so it runs before:
			// a failed test doesn't leave the join waiting on it.
			t.Cleanup(member.release)
			// Counted, so past its resize and on its way to the lock the
			// parked Write holds.
			rig.sizes.await(t, desktopAndPhone)
			j.leave()

			// Taken out again with the lock still held: the pty is back at
			// the size without the joiner.
			rig.sizes.await(t, desktop)
			require.Equal(t, desktop, rig.ptySize(t))
			select {
			case <-j.done:
				t.Fatal("the joiner's handler returned with the fan-out's lock still held: the test never held the join up")
			default:
			}

			member.release()
			j.awaitDone(t)
			require.Empty(t, j.exitCodes(), "a client that left was sent a status")
			require.False(t, hostAttached.Load(), "a client that left was reported attached")
			require.Equal(t, []termsize.Size{desktop, desktopAndPhone, desktop}, rig.sizes.applied(),
				"the pty was resized again after the joiner was taken out")
			require.Equal(t, desktop, rig.ptySize(t))

			terminals := rig.handler.terminals
			terminals.mu.Lock()
			counted := make([]string, 0, 2)
			for id := range terminals.m[rig.handler.ptmx] {
				counted = append(counted, id)
			}
			terminals.mu.Unlock()
			require.Equal(t, []string{"desktop"}, counted, "a terminal that had left was counted again")
		})
	}
}

// With a pacer: a join gated inside its Replayer holds the gate; a second
// joiner disconnects while waiting; its handler returns within 50 ms, its
// AsyncWriter is Closed, and the goroutine count is back to its baseline
// within 1 s (its drain goroutine ended).
//
// The drain goroutine is the evidence of the Close: a sink that has been
// handed nothing waits for its first write, and only a Close ends that wait.
func TestThePacerGateHonoursTheJoinersContext(t *testing.T) {
	r := newDoorReplayer()
	r.start = func(n int, ctx context.Context) error {
		if n == 0 {
			<-ctx.Done()
		}
		return errNoReplay
	}
	rig := newJoinRig(t, r, uio.DefaultReplayBytes, true)

	rig.join(t, kindGuest, phone)
	require.Equal(t, phone, r.next(t).size, "the first join never reached its replay")
	baseline := runtime.NumGoroutine()

	second := rig.join(t, kindGuest, tablet)
	// Counted, so past its resize and at the gate the first one holds.
	rig.sizes.await(t, tablet)
	left := time.Now()
	second.leave()
	second.awaitDone(t)
	require.Less(t, time.Since(left), 50*time.Millisecond,
		"a joiner that left kept waiting for the join ahead of it")
	require.True(t, goroutinesBackTo(baseline, time.Second),
		"the refused joiner's sink was left open, its drain goroutine waiting on it")
	require.Len(t, r.seen(), 1, "the joiner that left reached the replayer")
}

// goroutinesBackTo reports whether the goroutine count came down to baseline
// within d. Counted on the caller's goroutine, not in require.Eventually,
// whose condition runs on a goroutine of its own and so is always one over.
// Polled: nothing announces a goroutine's end.
func goroutinesBackTo(baseline int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for runtime.NumGoroutine() > baseline {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// A second joiner that waited 300 ms at the pacer's gate reaches
// AppendSized with 700 ms of its 1 s budget left, not 1 s.
func TestTheDeadlineStartsBeforeThePacerGate(t *testing.T) {
	const waited = 300 * time.Millisecond
	release := make(chan struct{})
	r := newDoorReplayer()
	r.start = func(n int, ctx context.Context) error {
		if n == 0 {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return errNoReplay
	}
	rig := newJoinRig(t, r, uio.DefaultReplayBytes, true)

	rig.join(t, kindGuest, phone)
	require.Equal(t, phone, r.next(t).size, "the first join never reached its replay")
	rig.join(t, kindGuest, tablet)
	// Counted, so past its deadline and its resize, and at the gate.
	rig.sizes.await(t, tablet)
	// Not ordering anything: the wait is what the deadline must be charged.
	time.Sleep(waited)
	close(release)

	second := r.next(t)
	require.Equal(t, tablet, second.size)
	want := uio.ReplayBudget - waited
	require.LessOrEqual(t, second.left, want, "the join's budget started after it began")
	// Loose: how long the release takes to reach Start is the runner's, and
	// the bound only catches a budget charged for far more than the wait.
	require.GreaterOrEqual(t, second.left, want-250*time.Millisecond)
}

// A host-door viewer (no pty) still gets the raw ring.
//
// With a replayer at the seam, and a terminal on the same door handed its
// reconstruction of the same ring, so the viewer's raw ring is the viewer's
// and not a replayer that is never consulted.
func TestAViewerStillGetsTheRawRing(t *testing.T) {
	r := newDoorReplayer()
	installReplayer(t, r)
	h := startHost(t, &Server{Command: printsTheRing})
	_, first, _ := h.connectHost(t, nil)
	readUntil(t, first, ringMark)

	_, term, _ := h.connectHost(t, &hostPty{term: "xterm", cols: desktop.Cols, rows: desktop.Rows})
	require.Contains(t, readUntil(t, term, ringMark), emulatedMark, "a terminal was handed the raw ring")

	_, viewer, _ := h.connectHost(t, nil)
	require.NotContains(t, readUntil(t, viewer, ringMark), emulatedMark, "a viewer was handed a reconstruction")
	require.Len(t, r.seen(), 1, "a viewer's join reached the replayer")
}

// Host-door terminals that arrive before the command has started decide the
// size it opens at, and that is the minimum over them, as any resize is: a
// second terminal, larger than the first, must not open the command at its
// own size.
//
// At the handler rather than through ServeWithContext: there, the first
// terminal's attach opens the gate the command's start waits on, and nothing
// holds the start back until a second has arrived.
func TestTerminalsBeforeTheCommandOpenItAtTheirMinimum(t *testing.T) {
	shared := newSharedPTY()
	t.Cleanup(shared.abandon)
	attached := make(chan struct{}, 2)
	h := &sessionHandler{
		kind:              kindHost,
		ptmx:              shared,
		writers:           uio.NewMultiWriter(uio.DefaultReplayBytes),
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
		keepAliveDuration: time.Hour,
		ctx:               t.Context(),
		logger:            discardLogger(),
		// What the command's start waits on, and reads the size after.
		onHostClientAttached: func() { attached <- struct{}{} },
	}

	larger := termsize.Size{Cols: 100, Rows: 40}
	for i, size := range []termsize.Size{phone, larger} {
		startJoiner(t, h, fmt.Sprintf("%s/%d", t.Name(), i), size)
		select {
		case <-attached:
		case <-time.After(harnessTimeout):
			t.Fatalf("the %v terminal was never attached", size)
		}
	}
	require.Equal(t, phone, shared.initialSize(), "the command would open at a size larger than a terminal attached")
}

// A terminal counts its size before it attaches, and before the command has
// started that size is what the command will open at. When the terminal never
// attaches -- it leaves, or its join fails -- the size goes with it: a client
// that attaches afterwards and opens the gate, a pipe viewer with no terminal,
// starts the command at the default, not at the size of a terminal that is no
// longer there.
//
// At the handler, as TestTerminalsBeforeTheCommandOpenItAtTheirMinimum is,
// and for the same reason: through ServeWithContext the first client's attach
// opens the gate at once, so nothing can be staged between a terminal counting
// and the command starting. What the gate does -- start the command with the
// size the handle recorded, then publish its pty -- is done by hand, after the
// viewer's attach has reported what the gate waits for.
//
// Both ways out of the counted-not-attached state: the client leaving while
// the join waits for the fan-out's lock, which takes it out from the context's
// end, and the join failing outright, which takes it out as the handler
// returns.
func TestAJoinerThatLeavesBeforeTheCommandStartsDoesNotSizeIt(t *testing.T) {
	newHost := func(t *testing.T) (h *sessionHandler, shared *sharedPTY, writers *uio.MultiWriter, attached chan struct{}) {
		shared = newSharedPTY()
		t.Cleanup(shared.abandon)
		writers = uio.NewMultiWriter(uio.DefaultReplayBytes)
		attached = make(chan struct{}, 2)
		h = &sessionHandler{
			kind:              kindHost,
			ptmx:              shared,
			writers:           writers,
			eventEmmiter:      emitter.New(1),
			terminals:         newTerminalWindows(discardLogger()),
			keepAliveDuration: time.Hour,
			ctx:               t.Context(),
			logger:            discardLogger(),
			// What the command's start waits on, and reads the size after.
			onHostClientAttached: func() { attached <- struct{}{} },
		}
		return h, shared, writers, attached
	}

	// openCommand is the gate's start: the command opened with the size the
	// handle recorded, and the pty published. It reports the size the pty
	// opened at, as the kernel has it.
	openCommand := func(t *testing.T, shared *sharedPTY, writers *uio.MultiWriter) termsize.Size {
		t.Helper()
		cmd := newCommand("sleep", []string{"600"}, nil, termsize.Size{}, false, "", emitter.New(1), writers, discardLogger())
		p, err := cmd.Start(t.Context(), shared.initialSize())
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = p.Kill()
			_ = p.Close()
			_ = p.Wait()
		})
		shared.set(p)
		rows, cols, err := ptylib.Getsize(p.(*pty).File)
		require.NoError(t, err)
		return termsize.Size{Cols: cols, Rows: rows}
	}

	t.Run("the client leaves while its join waits for the fan-out", func(t *testing.T) {
		h, shared, writers, attached := newHost(t)
		member := newParkingMember()
		require.NoError(t, writers.Append(member))
		member.park(t, writers)

		j := startJoiner(t, h, t.Name()+"/terminal", phone)
		// After the joiner's own cleanup is registered, so it runs before:
		// a failed test doesn't leave the join waiting on it.
		t.Cleanup(member.release)
		require.Eventually(t, func() bool { return shared.initialSize() == phone },
			harnessTimeout, time.Millisecond, "the terminal was never counted")
		j.leave()
		// Out from the context's end, with the fan-out's lock still held.
		require.Eventually(t, func() bool { return shared.initialSize() == termsize.Size{} },
			harnessTimeout, time.Millisecond, "the command would open at the size of a terminal that has left")

		member.release()
		j.awaitDone(t)
		require.Empty(t, attached, "a client that left was reported attached")

		startViewer(t, h, t.Name()+"/viewer")
		select {
		case <-attached:
		case <-time.After(harnessTimeout):
			t.Fatal("the viewer was never attached")
		}
		require.Equal(t, termsize.Size{}, shared.initialSize())
		require.Equal(t, termsize.Default, openCommand(t, shared, writers),
			"the command opened at the size of a terminal that had left")
	})

	t.Run("the join fails", func(t *testing.T) {
		h, shared, writers, attached := newHost(t)
		// The fan-out is shut down, so the terminal's attach is refused and
		// its handler returns.
		require.NoError(t, writers.Shutdown(t.Context()))

		j := startJoiner(t, h, t.Name()+"/terminal", phone)
		j.awaitDone(t)
		require.Equal(t, []int{0}, j.exitCodes(), "a client that arrived as the session ended is told 0")
		require.Empty(t, attached, "a client whose join failed was reported attached")

		require.Equal(t, termsize.Size{}, shared.initialSize(), "the command would open at the size of a terminal that has left")
		require.Equal(t, termsize.Default, openCommand(t, shared, writers),
			"the command opened at the size of a terminal that had left")
	})
}

// joinRig is a session's doors with nothing in front of them, for outcomes a
// session served over SSH can't stage on demand: Shutdown before a join, a
// sink that can't take the ring. It has a real pty, which reports its
// resizes to a fan-out with the test's replayer installed, an 80x24 terminal
// attached throughout, the handler the doors share, and joiners the test
// drives.
//
// The replayer is installed on the rig's own fan-out directly: the seam is
// what ServeWithContext builds its fan-out with, and the rig builds its own.
type joinRig struct {
	handler sessionHandler
	writers *uio.MultiWriter
	pacer   *guestPacer
	ptmx    *pty
	sizes   *ptySizes
	joined  atomic.Int32
}

// newJoinRig builds a rig whose ring holds ringBytes and already holds
// ringMark. paced puts the pacer in front of the guest door.
func newJoinRig(t *testing.T, r uio.Replayer, ringBytes int, paced bool) *joinRig {
	t.Helper()
	writers := uio.NewMultiWriter(ringBytes)
	writers.SetReplayer(r, nil)
	sizes := &ptySizes{w: writers, begun: map[uint64]termsize.Size{}, changed: make(chan struct{})}
	p, err := startPty(exec.Command("sleep", "600"), desktop, false, sizes)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = p.Kill()
		_ = p.Close()
		_ = p.Wait()
	})
	_, err = writers.Write([]byte(ringMark + "\r\n"))
	require.NoError(t, err)

	rig := &joinRig{writers: writers, ptmx: p.(*pty), sizes: sizes}
	rig.handler = sessionHandler{
		ptmx:              p,
		writers:           writers,
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
		keepAliveDuration: time.Hour,
		ctx:               t.Context(),
		logger:            discardLogger(),
	}
	if paced {
		rig.pacer = newGuestPacer(t.Context(), writers)
		rig.handler.pacer = rig.pacer
	}
	rig.handler.terminals.changed(p, "desktop", desktop.Cols, desktop.Rows, nil)
	return rig
}

// join runs a joiner with a terminal of size through the door kind names, on
// a goroutine of its own. By the time the test ends it has left and its
// handler has returned.
func (r *joinRig) join(t *testing.T, kind clientKind, size termsize.Size) *joiner {
	t.Helper()
	h := r.handler
	h.kind = kind
	return startJoiner(t, &h, fmt.Sprintf("%s/%d", t.Name(), r.joined.Add(1)), size)
}

// startJoiner runs a joiner, id, with a terminal of size, through h, on a
// goroutine of its own. By the time the test ends it has left and its
// handler has returned.
func startJoiner(t *testing.T, h *sessionHandler, id string, size termsize.Size) *joiner {
	t.Helper()
	j := newJoiner(t, id, size)
	runJoiner(t, h, j, j)
	return j
}

// startViewer runs a client with no terminal, `upterm host` in a pipe or
// backgrounded, through h. It counts towards no size.
func startViewer(t *testing.T, h *sessionHandler, id string) *joiner {
	t.Helper()
	j := newJoiner(t, id, termsize.Size{})
	runJoiner(t, h, j, pipeViewer{j})
	return j
}

// pipeViewer is a joiner that asked for no pty.
type pipeViewer struct{ *joiner }

func (pipeViewer) Pty() (gssh.Pty, <-chan gssh.Window, bool) { return gssh.Pty{}, nil, false }

// runJoiner runs sess, which is j or stands in for it, through h on a
// goroutine of its own. By the time the test ends j has left and the handler
// has returned.
func runJoiner(t *testing.T, h *sessionHandler, j *joiner, sess gssh.Session) {
	t.Helper()
	go func() {
		defer close(j.done)
		h.HandleSession(sess)
	}()
	t.Cleanup(func() {
		j.leave()
		select {
		case <-j.done:
		case <-time.After(harnessTimeout):
			t.Errorf("the handler of joiner %s never returned", j.ctx.sessionID)
		}
	})
}

// parkingMember is a member of a fan-out whose Write, once it is told to
// park, parks until released: the Write that reaches it holds the fan-out's
// lock, so a join that wants the lock waits, outside anything a test can see,
// for the release.
type parkingMember struct {
	armed   atomic.Bool
	in      chan struct{} // closed as the first parked Write begins
	gate    chan struct{}
	inOnce  sync.Once
	outOnce sync.Once
}

// newParkingMember returns a member that takes writes until told to park.
func newParkingMember() *parkingMember {
	return &parkingMember{in: make(chan struct{}), gate: make(chan struct{})}
}

func (m *parkingMember) Write(p []byte) (int, error) {
	if m.armed.Load() {
		m.inOnce.Do(func() { close(m.in) })
		<-m.gate
	}
	return len(p), nil
}

// park has a Write to w park in the member, and returns once it has.
func (m *parkingMember) park(t *testing.T, w io.Writer) {
	t.Helper()
	m.armed.Store(true)
	go func() { _, _ = w.Write([]byte("x")) }()
	select {
	case <-m.in:
	case <-time.After(harnessTimeout):
		t.Fatal("no Write reached the parking member")
	}
}

func (m *parkingMember) release() { m.outOnce.Do(func() { close(m.gate) }) }

// holdTheGate has the pacer's gate held, by an attach that waits there until
// the test ends.
func (r *joinRig) holdTheGate(t *testing.T) {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	attached := make(chan error, 1)
	holder := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
	go func() {
		attached <- r.pacer.attach(t.Context(), holder, func() error {
			close(held)
			<-release
			return errNoReplay
		})
	}()
	t.Cleanup(func() {
		close(release)
		require.ErrorIs(t, <-attached, errNoReplay, "the attach ends with what its append returned")
		_ = holder.Close()
	})
	select {
	case <-held:
	case <-time.After(harnessTimeout):
		t.Fatal("the gate was never taken")
	}
}

// ptySize is the rig's pty's size, as the kernel has it.
func (r *joinRig) ptySize(t *testing.T) termsize.Size {
	t.Helper()
	rows, cols, err := ptylib.Getsize(r.ptmx.File)
	require.NoError(t, err)
	return termsize.Size{Cols: cols, Rows: rows}
}

// ptySizes passes a pty's reports on to the fan-out and keeps every size it
// applied, so a test can wait for a joiner to have been counted rather than
// guess when it has.
type ptySizes struct {
	w *uio.MultiWriter

	mu    sync.Mutex
	begun map[uint64]termsize.Size
	sizes []termsize.Size
	// changed is closed and replaced at each resize's end.
	changed chan struct{}
}

func (s *ptySizes) ResizeBegin(size termsize.Size) uint64 {
	seq := s.w.ResizeBegin(size)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begun[seq] = size
	return seq
}

func (s *ptySizes) ResizeEnd(seq uint64, applied bool) {
	s.w.ResizeEnd(seq, applied)
	s.mu.Lock()
	defer s.mu.Unlock()
	if applied {
		s.sizes = append(s.sizes, s.begun[seq])
	}
	delete(s.begun, seq)
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *ptySizes) Pinned(size termsize.Size) { s.w.Pinned(size) }

// applied is every size the pty has been resized to, starting with the size
// it opened at.
func (s *ptySizes) applied() []termsize.Size {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]termsize.Size(nil), s.sizes...)
}

// await waits for the pty's latest size to be size.
func (s *ptySizes) await(t *testing.T, size termsize.Size) {
	t.Helper()
	timeout := time.After(harnessTimeout)
	for {
		s.mu.Lock()
		latest, changed := termsize.Size{}, s.changed
		if n := len(s.sizes); n > 0 {
			latest = s.sizes[n-1]
		}
		s.mu.Unlock()
		if latest == size {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("the pty was never resized to %v; it is at %v", size, latest)
		}
	}
}

// joiner is the whole of gssh.Session a join touches on either door: a client
// with a terminal of a given size, which declares no interactivity, so the
// host door never makes it primary. It reads nothing until it leaves, so one
// that attached stays attached. Leaving is its connection going: its context
// ends and its window channel closes, as charm's do. Its Exit is answered at
// once, as a live client's close is.
type joiner struct {
	gssh.Session

	ctx    joinerContext
	cancel context.CancelFunc
	window gssh.Window
	winCh  chan gssh.Window
	key    gssh.PublicKey
	out    joinerOutput

	gone, reading, done chan struct{}
	leaveOnce, readOnce sync.Once

	mu    sync.Mutex
	exits []int // the codes Exit was called with
}

func newJoiner(t *testing.T, id string, size termsize.Size) *joiner {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	return &joiner{
		ctx:     joinerContext{ctx: ctx, sessionID: id},
		cancel:  cancel,
		window:  gssh.Window{Width: size.Cols, Height: size.Rows},
		winCh:   make(chan gssh.Window),
		key:     signer.PublicKey(),
		out:     joinerOutput{more: make(chan struct{})},
		gone:    make(chan struct{}),
		reading: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Read is the input actor's, which runs only once the joiner is attached.
func (j *joiner) Read([]byte) (int, error) {
	j.readOnce.Do(func() { close(j.reading) })
	<-j.gone
	return 0, io.EOF
}

func (j *joiner) Write(p []byte) (int, error) { return j.out.Write(p) }
func (j *joiner) Close() error                { return nil }
func (j *joiner) Exit(code int) error {
	j.mu.Lock()
	j.exits = append(j.exits, code)
	j.mu.Unlock()
	j.leave()
	return nil
}
func (j *joiner) Context() gssh.Context { return j.ctx }
func (j *joiner) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "xterm", Window: j.window}, j.winCh, true
}
func (j *joiner) Environ() []string                              { return nil }
func (j *joiner) PublicKey() gssh.PublicKey                      { return j.key }
func (j *joiner) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (j *joiner) Signals(chan<- gssh.Signal)                     {}

// exitCodes is every code the joiner's handler sent it, in order.
func (j *joiner) exitCodes() []int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]int(nil), j.exits...)
}

func (j *joiner) leave() {
	j.leaveOnce.Do(func() {
		j.cancel()
		close(j.winCh)
		close(j.gone)
	})
}

// awaitDone waits for the joiner's handler to return.
func (j *joiner) awaitDone(t *testing.T) {
	t.Helper()
	select {
	case <-j.done:
	case <-time.After(harnessTimeout):
		t.Fatal("the joiner's handler never returned")
	}
}

// awaitSettled waits for the joiner's handler either to start its actors,
// which it does only once the joiner is attached, or to return, and reports
// whether the joiner was attached.
func (j *joiner) awaitSettled(t *testing.T) (attached bool) {
	t.Helper()
	select {
	case <-j.reading:
		return true
	case <-j.done:
		return false
	case <-time.After(harnessTimeout):
		t.Fatal("the joiner's handler neither attached it nor returned")
		return false
	}
}

// joinerContext is what a join asks of a session's context: its ID, whether
// the client is still there, and its client version for the host door's
// join event. The rest is left nil, as fakeGuestContext's is.
type joinerContext struct {
	gssh.Context

	ctx       context.Context
	sessionID string
}

func (c joinerContext) Value(key any) any {
	if key == gssh.ContextKeySessionID {
		return c.sessionID
	}
	return nil
}
func (c joinerContext) Done() <-chan struct{}       { return c.ctx.Done() }
func (c joinerContext) Err() error                  { return c.ctx.Err() }
func (c joinerContext) Deadline() (time.Time, bool) { return c.ctx.Deadline() }
func (c joinerContext) ClientVersion() string       { return "test" }

// joinerOutput is what a joiner was sent.
type joinerOutput struct {
	mu  sync.Mutex
	buf []byte
	// more is closed and replaced at each write.
	more chan struct{}
}

func (o *joinerOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf = append(o.buf, p...)
	close(o.more)
	o.more = make(chan struct{})
	return len(p), nil
}

// await waits for marker in what the joiner was sent, and returns all of it.
func (o *joinerOutput) await(t *testing.T, marker string) string {
	t.Helper()
	timeout := time.After(harnessTimeout)
	for {
		o.mu.Lock()
		got, more := string(o.buf), o.more
		o.mu.Unlock()
		if strings.Contains(got, marker) {
			return got
		}
		select {
		case <-more:
		case <-timeout:
			t.Fatalf("the joiner was never sent %q; it was sent %s", marker, summarize(got))
		}
	}
}
