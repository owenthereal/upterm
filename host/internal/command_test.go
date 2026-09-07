package internal

import (
	"context"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// TestCommand_NonTTY_WithForceFlag verifies that stdin forwarding IS enabled
// when ForceForwardingInputForTesting is true, even with a non-TTY stdin.
func TestCommand_NonTTY_WithForceFlag(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Create a pipe (non-TTY)
	stdinr, stdinw, err := os.Pipe()
	require.NoError(err, "failed to create stdin pipe")
	defer func() { _ = stdinr.Close() }()
	defer func() { _ = stdinw.Close() }()

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	// Verify stdin is not a TTY
	assert.False(term.IsTerminal(int(stdinr.Fd())), "stdin should not be a TTY for this test")

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Create command WITH ForceForwardingInputForTesting
	// Use a command that reads from stdin and outputs it (cross-platform)
	var shellCmd string
	var shellArgs []string
	if runtime.GOOS == "windows" {
		// Windows: Use 'findstr' with regex that matches any line
		// This reads stdin line by line and outputs matching lines
		shellCmd = "findstr"
		shellArgs = []string{"/r", ".*"}
	} else {
		// Unix: Use 'head' which reads exactly one line then exits
		shellCmd = "head"
		shellArgs = []string{"-n", "1"}
	}

	cmd := newCommand(
		shellCmd,
		shellArgs,
		nil,
		stdinr,
		stdoutw,
		ee,
		writers,
		true, // Force stdin forwarding even though it's not a TTY
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = cmd.Start(ctx)
	require.NoError(err, "failed to start command")

	// Capture output in background
	outputCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 1024)
		var output []byte
		for {
			n, err := stdoutr.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		outputCh <- string(output)
	}()

	// Run the command in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Give it a moment to start and begin reading
	time.Sleep(100 * time.Millisecond)

	// Send input through the pipe
	testInput := "test input from pipe"
	_, err = stdinw.Write([]byte(testInput + "\n"))
	require.NoError(err, "failed to write to stdin")

	// Give a moment for data to be fully written and copied through the PTY
	time.Sleep(50 * time.Millisecond)

	// Close stdin so 'more' on Windows will exit after reading
	// On Unix, 'head -n 1' exits immediately after reading one line
	_ = stdinw.Close()

	// The command should complete after receiving input
	select {
	case err := <-errCh:
		// Expected: command completes after reading one line
		if err != nil {
			t.Logf("command completed with error (might be expected): %v", err)
		}

		// Verify the output shows our input was forwarded through stdin
		_ = stdoutw.Close()
		select {
		case output := <-outputCh:
			// head -n 1 should output exactly the line we sent
			assert.Contains(output, testInput, "should see our piped input in output, proving stdin was forwarded")
		case <-time.After(2 * time.Second):
			assert.Fail("stdout never reached EOF")
		}
	case <-time.After(1500 * time.Millisecond):
		cancel()
		assert.Fail("command did not complete after receiving input")
	}
}

// TestCommand_ContextCancellation verifies that context cancellation
// properly terminates the command and cleans up resources.
func TestCommand_ContextCancellation(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

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
		os.Stdin,
		stdoutw,
		ee,
		writers,
		false,
	)

	// Create a context with cancel
	ctx, cancel := context.WithCancel(context.Background())

	_, err = cmd.Start(ctx)
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
func (p *exitedPTY) Setsize(int, int) error { return nil }
func (p *exitedPTY) Wait() error            { return nil }
func (p *exitedPTY) Kill() error            { return nil }

// TestCommand_DrainsOutputAfterExit verifies that output the process wrote
// just before exiting is delivered rather than dropped when Run notices the
// exit.
func TestCommand_DrainsOutputAfterExit(t *testing.T) {
	require := require.New(t)

	stdinr, stdinw, err := os.Pipe()
	require.NoError(err)
	defer func() { _ = stdinr.Close() }()
	defer func() { _ = stdinw.Close() }()
	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err)
	defer func() { _ = stdoutr.Close() }()

	const lastLine = "written just before exit"
	cmd := &command{
		stdin:   stdinr,
		stdout:  stdoutw,
		writers: uio.NewMultiWriter(5),
		ctx:     context.Background(),
		ptmx: &exitedPTY{
			pending:   [][]byte{[]byte("first chunk\r\n"), []byte(lastLine + "\r\n")},
			readDelay: 20 * time.Millisecond,
		},
	}

	captured := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdoutr)
		captured <- string(b)
	}()

	require.NoError(cmd.Run())
	require.NoError(stdoutw.Close())

	select {
	case output := <-captured:
		require.Contains(output, lastLine, "output buffered in the pty at exit was dropped")
	case <-time.After(2 * time.Second):
		t.Fatal("stdout never reached EOF")
	}
}
