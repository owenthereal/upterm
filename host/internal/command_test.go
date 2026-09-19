package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommand_ContextCancellation verifies that context cancellation
// properly terminates the command and cleans up resources.
func TestCommand_ContextCancellation(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)

	// Use a long-running command that will only exit when interrupted
	var shellCmd string
	var shellArgs []string
	if runtime.GOOS == "windows" {
		// Windows: Use 'ping' with high count
		shellCmd = "ping"
		shellArgs = []string{"-n", "1000", "127.0.0.1"}
	} else {
		// Unix: Use 'sleep' for a long time
		shellCmd = "sleep"
		shellArgs = []string{"1000"}
	}

	cmd := newCommand(
		shellCmd,
		shellArgs,
		nil,
		termsize.Size{},
		false,
		"",
		ee,
		writers,
		discardLogger(),
	)

	// Create a context with cancel
	ctx, cancel := context.WithCancel(context.Background())

	_, err := cmd.Start(ctx, termsize.Size{})
	require.NoError(err, "failed to start command")

	// Run the command in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Give the command time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context - this should trigger cleanup
	cancel()

	// Command should terminate within reasonable time
	select {
	case err := <-errCh:
		// Context cancellation should cause command to exit
		// Error may be context.Canceled or exit status from kill
		if err != nil && err != context.Canceled {
			t.Logf("command exited with error (expected): %v", err)
		}
		// Command terminated successfully - reaching here proves it worked
	case <-time.After(2 * time.Second):
		assert.Fail("command did not terminate after context cancellation")
	}
}

// exitedPTY models a process that has already exited with output still
// buffered in the pty: Wait returns at once, while Read keeps returning the
// pending chunks before EOF. On Linux and Windows the real pty behaves this
// way; on macOS the slave write blocks until the master reads, so the race
// cannot be reproduced with a real process.
type exitedPTY struct {
	mu        sync.Mutex
	pending   [][]byte
	closed    bool
	readDelay time.Duration

	// sizeH, sizeW record the last Setsize call, so a test can assert what a
	// caller resized this fake to.
	sizeH, sizeW int

	// redraws counts Redraw calls, so a test can assert how many nudges a
	// door sent without needing a real process to receive SIGWINCH.
	redraws int
}

func (p *exitedPTY) Read(b []byte) (int, error) {
	time.Sleep(p.readDelay)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.pending[0])
	p.pending = p.pending[1:]
	return n, nil
}

func (p *exitedPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *exitedPTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
func (p *exitedPTY) Setsize(h, w int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sizeH, p.sizeW = h, w
	return nil
}

// lastSize returns the h, w of the most recent Setsize call.
func (p *exitedPTY) lastSize() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sizeH, p.sizeW
}

func (p *exitedPTY) Redraw() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redraws++
	return nil
}

// redrawCount returns how many times Redraw has been called.
func (p *exitedPTY) redrawCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redraws
}

func (p *exitedPTY) Wait() error                 { return nil }
func (p *exitedPTY) Kill() error                 { return nil }
func (p *exitedPTY) Signal(syscall.Signal) error { return nil }

// TestCommand_DrainsOutputAfterExit verifies that output the process wrote
// just before exiting is delivered rather than dropped when Run notices the
// exit.
func TestCommand_DrainsOutputAfterExit(t *testing.T) {
	require := require.New(t)

	const lastLine = "written just before exit"
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	var out recordingWriter
	require.NoError(writers.Append(&out))

	cmd := &command{
		logger:  discardLogger(),
		writers: writers,
		ctx:     context.Background(),
		ptmx: &exitedPTY{
			pending:   [][]byte{[]byte("first chunk\r\n"), []byte(lastLine + "\r\n")},
			readDelay: 20 * time.Millisecond,
		},
	}

	require.NoError(cmd.Run())

	require.Contains(string(out.bytes()), lastLine, "output buffered in the pty at exit was dropped")
}

// signalPTY records the signals it is sent and ends when told to. Read
// returns EOF at once, as if the command had closed every pty slave fd
// while staying alive itself -- the shape TestCommandRunEndsWhenOutputEnds
// -WithoutCancellation needs a command.Run to actually exercise the wait
// actor's interrupt with; Write, Close, Setsize and Redraw are no-ops, and
// Wait blocks until Kill or a matching Signal ends it, so it stands in
// fully for PTY rather than leaning on an embedded nil one.
type signalPTY struct {
	mu      sync.Mutex
	signals []syscall.Signal
	killed  bool
	// sequence records every Signal and Close, in order, as e.g. "hangup",
	// "close", "terminated" -- the shape a test needs to pin terminate's
	// step order, which the separate signals slice above cannot show.
	sequence []string
	// endOn ends the process when this signal arrives; zero never ends it.
	endOn       syscall.Signal
	exited      chan struct{}
	unsupported bool
	// signalErr, when set, is what Signal returns for signalErrOn, having
	// recorded the attempt: a send that failed for its own reasons, as
	// distinct from unsupported above, which is the platform saying it
	// cannot signal at all and never records anything.
	signalErr   error
	signalErrOn syscall.Signal
}

func newSignalPTY(endOn syscall.Signal) *signalPTY {
	return &signalPTY{endOn: endOn, exited: make(chan struct{})}
}

func (p *signalPTY) Signal(sig syscall.Signal) error {
	if p.unsupported {
		return errors.ErrUnsupported
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signals = append(p.signals, sig)
	p.sequence = append(p.sequence, sig.String())
	if p.signalErr != nil && sig == p.signalErrOn {
		// A signal that failed ends nothing, whatever endOn says.
		return p.signalErr
	}
	if sig == p.endOn {
		close(p.exited)
	}
	return nil
}

func (p *signalPTY) Kill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.killed = true
	select {
	case <-p.exited:
	default:
		close(p.exited)
	}
	return nil
}

func (p *signalPTY) Read([]byte) (int, error)    { return 0, io.EOF }
func (p *signalPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *signalPTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence = append(p.sequence, "close")
	return nil
}
func (p *signalPTY) Setsize(int, int) error { return nil }
func (p *signalPTY) Redraw() error          { return nil }

// Wait blocks until the command has ended: Kill was called, or Signal was
// sent endOn.
func (p *signalPTY) Wait() error {
	<-p.exited
	return nil
}

func TestTerminateHangsUpBeforeItKills(t *testing.T) {
	p := newSignalPTY(syscall.SIGHUP)
	terminate(p, p.exited, time.Second, discardLogger(), "test")
	require.Equal(t, []syscall.Signal{syscall.SIGHUP}, p.signals, "a command that hangs up is never sent anything else")
	require.False(t, p.killed)
}

func TestTerminateEscalatesThroughTermToKill(t *testing.T) {
	withHangupGrace(t, 20*time.Millisecond)

	p := newSignalPTY(0)
	start := time.Now()
	terminate(p, p.exited, 20*time.Millisecond, discardLogger(), "test")
	require.Equal(t, []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL}, p.signals,
		"the final step signals the group before killing the leader")
	require.True(t, p.killed, "a command that ignores both is killed")
	require.GreaterOrEqual(t, time.Since(start), 60*time.Millisecond,
		"a grace after the hangup, after the master closes, and after the term")
}

// withHangupGrace shrinks the package-level hangupGrace for the duration of
// t, restoring it after. Every terminate test that expects to run fast
// needs this: hangupGrace defaults to a full second, independent of
// whatever grace the test itself passes for the later steps.
func withHangupGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := hangupGrace
	hangupGrace = d
	t.Cleanup(func() { hangupGrace = orig })
}

// TestTerminateClosesTheMasterBetweenHangupAndTerm pins the design's own
// step order for a process that ignores every signal it is sent: SIGHUP,
// then -- once it stays past a grace -- the pty master closing, then
// SIGTERM after another grace, then SIGKILL to the group and the leader
// after a third. Dropping D11's omitted middle step is exactly what left a
// session leader with nothing that could ever free it: neither SIGHUP nor
// SIGTERM reaches a process stuck inside exit() waiting for its
// controlling terminal's output to drain, and only closing the master
// does.
func TestTerminateClosesTheMasterBetweenHangupAndTerm(t *testing.T) {
	withHangupGrace(t, 20*time.Millisecond)

	p := newSignalPTY(0)
	terminate(p, p.exited, 20*time.Millisecond, discardLogger(), "test")
	require.Equal(t, []string{syscall.SIGHUP.String(), "close", syscall.SIGTERM.String(), syscall.SIGKILL.String()}, p.sequence)
	require.True(t, p.killed, "a command that ignores everything, including the close, is still killed")
}

func TestTerminateKillsAtOnceWhereSignalsAreUnsupported(t *testing.T) {
	p := newSignalPTY(0)
	p.unsupported = true
	start := time.Now()
	terminate(p, p.exited, time.Second, discardLogger(), "test")
	require.Empty(t, p.signals)
	require.True(t, p.killed)
	require.Less(t, time.Since(start), 500*time.Millisecond, "no grace is spent on a step the platform cannot take")
}

// TestTerminateKeepsEscalatingWhenASignalFailsForItsOwnReasons pins the
// other half of that: only errors.ErrUnsupported -- the platform reporting
// it cannot signal -- skips to the kill. A send that failed for its own
// reasons, an ESRCH from a group that has just vanished being the likely
// one, says nothing about whether the next step can work, and jumping to
// SIGKILL on it skipped the hangup a job-control shell needs to collect its
// jobs and the close that frees a leader stuck in exit().
func TestTerminateKeepsEscalatingWhenASignalFailsForItsOwnReasons(t *testing.T) {
	withHangupGrace(t, 20*time.Millisecond)

	p := newSignalPTY(0)
	p.signalErr = syscall.ESRCH
	p.signalErrOn = syscall.SIGHUP
	terminate(p, p.exited, 20*time.Millisecond, discardLogger(), "test")
	require.Equal(t,
		[]string{syscall.SIGHUP.String(), "close", syscall.SIGTERM.String(), syscall.SIGKILL.String()},
		p.sequence,
		"a failed hangup is still followed by the close and the term, in order, not by an immediate kill")
	require.True(t, p.killed, "the escalation still ends in a kill when nothing else took")
}

// TestCommandRunEndsWhenOutputEndsWithoutCancellation pins that Run cannot
// block forever when the output actor returns on its own -- a command that
// has closed every pty slave fd but is still running elsewhere, so the
// master read ends in EOF before anyone has asked the session to stop.
// run.Group's contract is that an actor's execute returns once its own
// interrupt has run; the wait actor's interrupt has nothing else that would
// ever cancel its own ctx in this scenario, so it must do so itself, and do
// so before waiting on the gate that keeps Close behind terminate.
func TestCommandRunEndsWhenOutputEndsWithoutCancellation(t *testing.T) {
	p := newSignalPTY(syscall.SIGHUP)
	cmd := &command{
		logger:  discardLogger(),
		writers: uio.NewMultiWriter(uio.DefaultReplayBytes),
		// Live, not cancelled: nothing outside this actor's own interrupt
		// ever ends this context, which is the whole point of the scenario.
		ctx:       context.Background(),
		ptmx:      p,
		stopGrace: 20 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its output actor ended on its own")
	}

	require.Contains(t, p.signals, syscall.SIGHUP,
		"the wait actor's own cancel must still drive terminate's escalation")
}

// closeThenExitPTY models the real R20 bug: a session leader a platform
// will not let finish exiting while its controlling terminal still holds
// output nobody has drained. Signal and Kill do nothing to it -- the whole
// point is that neither can end this state -- and only Close, the way a
// terminal actually going away closes its slave, lets Wait return. Read
// returns EOF at once, so the output actor ends on its own and does not
// stand in the way of exercising the wait actor's escalation.
type closeThenExitPTY struct {
	mu     sync.Mutex
	closed bool
	done   chan struct{} // closed only by Close; Wait blocks on this

	// closeBeforeWait records, from inside Wait itself once it wakes, that
	// closed was already true -- true by construction, since done can only
	// close from Close, but recorded explicitly so the test does not have
	// to take the ordering on faith.
	closeBeforeWait bool
}

func newCloseThenExitPTY() *closeThenExitPTY {
	return &closeThenExitPTY{done: make(chan struct{})}
}

func (p *closeThenExitPTY) Signal(syscall.Signal) error { return nil }
func (p *closeThenExitPTY) Kill() error                 { return nil }
func (p *closeThenExitPTY) Read([]byte) (int, error)    { return 0, io.EOF }
func (p *closeThenExitPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *closeThenExitPTY) Setsize(int, int) error      { return nil }
func (p *closeThenExitPTY) Redraw() error               { return nil }

func (p *closeThenExitPTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	return nil
}

// Wait blocks until Close runs.
func (p *closeThenExitPTY) Wait() error {
	<-p.done
	p.mu.Lock()
	p.closeBeforeWait = p.closed
	p.mu.Unlock()
	return nil
}

// TestCommandRunClosesTheMasterBeforeTheProcessCanExit pins the bug R20
// fixes: a process that only finishes exiting once the pty master closes,
// which SIGHUP and SIGTERM alone can never cause.
//
// grace and hangupGrace are both deliberately large relative to the bound
// below, not small like the rest of this file's terminate tests: SIGHUP
// does nothing to this fake (Signal is a no-op), so even the fixed code
// spends the whole of hangupGrace on that first step before firing the
// close -- which this fake's Wait unblocks on within microseconds of being
// called, so the fixed run lands around hangupGrace, comfortably under the
// bound. Without terminate's own close, every remaining step (the close
// step's own wait, SIGTERM's, Kill's) also runs its full grace with
// nothing to end it early, several graces past the bound -- a real hang,
// not a race against the interrupt's own backup close, which still fires
// eventually but is not what this pins.
func TestCommandRunClosesTheMasterBeforeTheProcessCanExit(t *testing.T) {
	const grace = 200 * time.Millisecond
	const bound = 600 * time.Millisecond
	withHangupGrace(t, grace)

	p := newCloseThenExitPTY()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: terminate runs at once, no grace wasted waiting to start

	cmd := &command{
		logger:    discardLogger(),
		writers:   uio.NewMultiWriter(uio.DefaultReplayBytes),
		ctx:       ctx,
		ptmx:      p,
		stopGrace: grace,
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
	case <-time.After(bound):
		t.Fatal("Run did not return once the pty master was closed")
	}

	require.True(t, p.closeBeforeWait, "Wait must not have returned before Close ran")
}

// TestCommandRunSurvivesAParkedReaderDuringClose is the covering test for
// this task (R20-R24): a real pty, a genuinely parked reader, and a
// command that ignores signals terminate sends it. Neither fake above can
// express this -- neither couples Read and Close through a lock -- so this
// is what actually exercises the bugs the review found: sleep writes
// nothing, so the output actor's own Read is truly blocked, holding the
// pty's read lock for as long as that syscall stays parked, at the moment
// cancellation abandons it. Against a synchronous close inside terminate
// (R22) or a Kill that still took the pty lock (R23), the operation behind
// that Read queues behind its lock forever and the escalation never
// reaches SIGKILL -- terminate stays parked for the command's whole life.
func TestCommandRunSurvivesAParkedReaderDuringClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("trap and signal forwarding are POSIX shell behaviour")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not installed")
	}

	const grace = 200 * time.Millisecond

	t.Run("ignoresHangupOnly", func(t *testing.T) {
		// sh does not trap SIGTERM, so once terminate reaches that step the
		// command dies; what this pins is that it gets there at all.
		runCommandWithParkedReader(t, sh, "trap '' HUP; sleep 30", grace, 2*time.Second, nil)
	})

	t.Run("ignoresHangupAndTerm", func(t *testing.T) {
		// R23's own repro: only SIGKILL can end the leader. Before R23, the
		// pending close's write lock starved Kill's own read lock exactly
		// the way it once starved Signal, and terminate never reached
		// SIGKILL either -- parked for the command's whole life.
		//
		// R24: the final SIGKILL must also reach the shell's own child, not
		// just the leader. sleep runs backgrounded (sh -c does not give a
		// non-interactive script job control, so the child stays in the
		// leader's own process group rather than getting one of its own),
		// its pid recorded to a file the way the shell-jobs ftest records
		// its background job's pid, and wait keeps the leader parked on it
		// -- so a leader-only kill would leave sleep running exactly as the
		// reviewer observed.
		dir := t.TempDir()
		childPidFile := filepath.Join(dir, "child.pid")
		script := fmt.Sprintf("trap '' HUP TERM; sleep 20 & echo $! >%s; wait", childPidFile)
		runCommandWithParkedReader(t, sh, script, grace, 3*time.Second, func(t *testing.T) {
			t.Helper()
			b, err := os.ReadFile(childPidFile)
			require.NoError(t, err, "the shell never recorded its child's pid")
			childPid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			require.NoError(t, err)
			require.Eventually(t, func() bool { return processGone(childPid) }, time.Second, 20*time.Millisecond,
				"the group SIGKILL must reach the shell's own child too, not just the leader (child pid %d)", childPid)
		})
	})
}

// runCommandWithParkedReader starts sh -c script under a real pty, lets it
// settle, cancels, and requires Run to return within bound with the
// process reaped. after, when not nil, runs once Run has returned and the
// leader's reap has been confirmed -- the place a case checks anything
// beyond the leader itself, such as a child the escalation was also meant
// to reach.
func runCommandWithParkedReader(t *testing.T, sh, script string, grace, bound time.Duration, after func(t *testing.T)) {
	t.Helper()
	withHangupGrace(t, grace)

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	cmd := newCommand(sh, []string{"-c", script}, nil, termsize.Size{}, false, "", ee, writers, discardLogger())
	cmd.stopGrace = grace

	ctx, cancel := context.WithCancel(context.Background())
	_, err := cmd.Start(ctx, termsize.Size{})
	require.NoError(t, err, "failed to start command")

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	// Let the shell actually install its trap and reach the blocking sleep
	// -- and the output actor's Read genuinely park waiting for output
	// that will never come -- before cancelling.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(bound):
		t.Fatal("Run did not return: a parked reader must not block any teardown step")
	}

	require.NotNil(t, cmd.cmd.ProcessState, "the process must have been reaped once terminate finished")

	if after != nil {
		after(t)
	}
}

// processGone reports whether pid no longer names a running process,
// treating a zombie as gone on Linux: the same rule
// ftests/host_stop_unix_test.go's processGone uses (a container's PID 1
// may never reap an orphan, and what a test here asks is whether the
// escalation ended it, not whether something later collected it).
// Reproduced rather than shared across packages, since this file has no
// build tag and must also compile, unused, on platforms
// ftests/host_stop_unix_test.go's own build tag excludes.
func processGone(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	// Signal 0: the standard way to probe a pid's existence without
	// affecting it, the same thing unix.Kill(pid, 0) does in the ftest.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return true
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			// "pid (comm) state ..." -- the state follows the last ')'.
			s := string(b)
			if i := strings.LastIndex(s, ")"); i >= 0 && len(s) > i+2 {
				return s[i+2] == 'Z'
			}
		}
	}
	return false
}
