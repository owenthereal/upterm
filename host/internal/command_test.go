package internal

import (
	"context"
	"io"
	"runtime"
	"sync"
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

func (p *exitedPTY) Redraw() error { return nil }
func (p *exitedPTY) Wait() error   { return nil }
func (p *exitedPTY) Kill() error   { return nil }

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
