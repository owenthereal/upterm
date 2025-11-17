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

// TestCommand_Unix_PTY verifies Unix-specific PTY functionality.
// This test validates that a real PTY is properly detected as a TTY
// and stdin forwarding is enabled.
func TestCommand_Unix_PTY(t *testing.T) {
	// Only run on Unix systems
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

// TestCommand_Windows_ConPTY verifies Windows-specific ConPTY functionality.
// This test validates that ConPTY can be created and used to run commands,
// and that command output is properly captured through the ConPTY.
func TestCommand_Windows_ConPTY(t *testing.T) {
	// Only run on Windows
	if runtime.GOOS != "windows" {
		t.Skip("ConPTY test only applicable on Windows")
	}

	require := require.New(t)
	assert := assert.New(t)

	// Create a pipe to capture stdout
	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Run a simple command through ConPTY
	// Use 'cmd /c echo' which is simple and reliable on Windows
	cmd := newCommand(
		"cmd",
		[]string{"/c", "echo", "ConPTY test successful"},
		nil,
		os.Stdin, // Pass stdin so startPty can attempt to get size
		stdoutw,
		ee,
		writers,
		false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start the command - this will create the ConPTY
	_, err = cmd.Start(ctx)
	require.NoError(err, "failed to start command with ConPTY")

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

	// Run the command
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Wait for command to complete
	select {
	case err := <-errCh:
		// Command should complete successfully
		assert.NoError(err, "command should complete successfully")

		// Verify we got output through ConPTY
		_ = stdoutw.Close()
		output := <-outputCh
		assert.Contains(output, "ConPTY test successful", "should see command output through ConPTY")
		t.Logf("ConPTY output: %q", output)
	case <-time.After(2500 * time.Millisecond):
		cancel()
		<-errCh // Wait for goroutine to finish
		assert.Fail("command did not complete within timeout")
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
	// Use a command that reads from stdin and outputs it (cross-platform)
	var shellCmd string
	var shellArgs []string
	if runtime.GOOS == "windows" {
		// Windows: Use 'more' which reads stdin and outputs
		// Will exit when stdin is closed
		shellCmd = "more"
		shellArgs = []string{}
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
		output := <-outputCh
		// head -n 1 should output exactly the line we sent
		assert.Contains(output, testInput, "should see our piped input in output, proving stdin was forwarded")
	case <-time.After(1500 * time.Millisecond):
		cancel()
		assert.Fail("command did not complete after receiving input")
	}
}
