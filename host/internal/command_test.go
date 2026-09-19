package internal

import (
	"context"
	"errors"
	"io"
	"runtime"
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

func (p *exitedPTY) Redraw() error               { return nil }
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
	// endOn ends the process when this signal arrives; zero never ends it.
	endOn       syscall.Signal
	exited      chan struct{}
	unsupported bool
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
func (p *signalPTY) Close() error                { return nil }
func (p *signalPTY) Setsize(int, int) error      { return nil }
func (p *signalPTY) Redraw() error               { return nil }

// Wait blocks until the command has ended: Kill was called, or Signal was
// sent endOn.
func (p *signalPTY) Wait() error {
	<-p.exited
	return nil
}

func TestTerminateHangsUpBeforeItKills(t *testing.T) {
	p := newSignalPTY(syscall.SIGHUP)
	terminate(p, p.exited, time.Second)
	require.Equal(t, []syscall.Signal{syscall.SIGHUP}, p.signals, "a command that hangs up is never sent anything else")
	require.False(t, p.killed)
}

func TestTerminateEscalatesThroughTermToKill(t *testing.T) {
	p := newSignalPTY(0)
	start := time.Now()
	terminate(p, p.exited, 20*time.Millisecond)
	require.Equal(t, []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM}, p.signals)
	require.True(t, p.killed, "a command that ignores both is killed")
	require.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond, "one grace per step")
}

func TestTerminateKillsAtOnceWhereSignalsAreUnsupported(t *testing.T) {
	p := newSignalPTY(0)
	p.unsupported = true
	start := time.Now()
	terminate(p, p.exited, time.Second)
	require.Empty(t, p.signals)
	require.True(t, p.killed)
	require.Less(t, time.Since(start), 500*time.Millisecond, "no grace is spent on a step the platform cannot take")
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
