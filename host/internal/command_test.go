package internal

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// TestCommand_TTY_DetectionWithRealPTY verifies that a real PTY is properly
// detected as a TTY and stdin forwarding is enabled.
func TestCommand_TTY_DetectionWithRealPTY(t *testing.T) {
	// Skip on Windows - ptylib.Open() uses Unix PTY which is not available
	// Windows uses ConPTY which is already tested through the main command implementation
	if runtime.GOOS == "windows" {
		t.Skip("Unix PTY test not applicable on Windows (uses ConPTY)")
	}

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
	// Use 'read' to verify stdin is actually being forwarded
	cmd := newCommand(
		"bash",
		[]string{"-c", "read input && echo \"received: $input\""},
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
		outputCh <- string(output)
	}()

	// Run the command in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Give it a moment to start and begin reading
	time.Sleep(100 * time.Millisecond)

	// Send input through the PTY master
	// Use \r (carriage return) for canonical mode compatibility on Linux
	// The outer PTY is in raw mode, so we need to send the line terminator
	// that bash's canonical mode expects
	_, err = ptmx.Write([]byte("hello from pty\r"))
	require.NoError(err, "failed to write to PTY")

	// Wait for command to complete
	select {
	case err := <-errCh:
		// Expected: command completes after receiving input
		if err != nil {
			t.Logf("command completed with error (might be expected): %v", err)
		}

		// Verify output was produced with our input
		_ = stdoutw.Close()
		output := <-outputCh
		assert.Contains(output, "received: hello from pty", "should see our input echoed back through PTY")
	case <-time.After(1500 * time.Millisecond):
		cancel()
		<-errCh // Wait for goroutine to finish
		assert.Fail("command did not complete - stdin may not be forwarded for PTY")
	}
}

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
	// Use 'head -n 1' which reads exactly one line then exits
	cmd := newCommand(
		"head",
		[]string{"-n", "1"},
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
	// Don't close stdinw yet - head will exit after reading one line

	// The command should complete after receiving input
	select {
	case err := <-errCh:
		// Expected: command completes after reading one line
		if err != nil {
			t.Logf("command completed with error (might be expected): %v", err)
		}

		// Verify the output shows our input was forwarded through stdin
		_ = stdoutw.Close()
		output := <-outputCh
		// head -n 1 should output exactly the line we sent
		assert.Contains(output, testInput, "should see our piped input in output, proving stdin was forwarded")
	case <-time.After(1500 * time.Millisecond):
		cancel()
		assert.Fail("command did not complete after receiving input")
	}
}
