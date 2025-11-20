//go:build !windows
// +build !windows

package internal

import (
	"context"
	"os"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// TestCommand_Unix_PTY verifies Unix-specific PTY functionality.
// This test validates that a real PTY is properly detected as a TTY
// and stdin forwarding is enabled.
func TestCommand_Unix_PTY(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Create a real PTY
	ptmx, tty, err := ptylib.Open()
	require.NoError(err, "failed to create PTY")
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = tty.Close() }()

	// Set PTY size
	err = ptylib.Setsize(ptmx, &ptylib.Winsize{Rows: 24, Cols: 80})
	require.NoError(err, "failed to set PTY size")

	// Verify tty IS a terminal
	assert.True(term.IsTerminal(int(tty.Fd())), "tty should be recognized as a terminal")

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Create command with real PTY (ForceForwardingInputForTesting not needed)
	// Use 'head -n 1' which exits immediately after reading one line
	// This is more reliable than 'read' which has timing issues with bash initialization
	cmd := newCommand(
		"head",
		[]string{"-n", "1"},
		nil,
		tty,
		stdoutw,
		ee,
		writers,
		false, // Should not be needed for real TTY
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
		// Only send if we captured output (don't send empty string)
		if len(output) > 0 {
			outputCh <- string(output)
		}
	}()

	// Run the command in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Give head time to start
	time.Sleep(100 * time.Millisecond)

	// Send input through the PTY master
	// head -n 1 reads one line and exits immediately
	testInput := "hello from pty"
	_, err = ptmx.Write([]byte(testInput + "\n"))
	require.NoError(err, "failed to write to PTY")

	// Wait for command to complete (head exits after reading one line)
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("command completed with error (might be expected): %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		cancel()
		<-errCh
		assert.Fail("command did not complete - stdin may not be forwarded for PTY")
		return
	}

	// Command has exited, now close stdout writer to signal EOF to output reader
	_ = stdoutw.Close()

	// Wait for output (should be available now since command has finished)
	select {
	case output := <-outputCh:
		assert.Contains(output, testInput, "should see our input forwarded through PTY and output by head")
	case <-time.After(500 * time.Millisecond):
		assert.Fail("no output captured - PTY may not be forwarding data correctly")
	}
}
