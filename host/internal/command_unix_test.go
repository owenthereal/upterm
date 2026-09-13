//go:build !windows

package internal

import (
	"context"
	"os"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// TestCommand_Unix_PTY verifies Unix-specific PTY functionality.
// This test validates that a real PTY is properly detected as a TTY
// and that stdin read from one is forwarded to the command.
//
// It cannot also assert that being a TTY is on its own enough to turn
// forwarding on, because that is no longer the rule: Run forwards from a
// terminal it is in the foreground of, and a pty pair opened in-process is the
// controlling terminal of no session, so tcgetpgrp on it fails and ownsTerminal
// is false. Making it true would need setsid plus TIOCSCTTY, which would detach
// the test binary from its own terminal. Foreground ownership is observable
// only where there is a real session to be in the foreground of, which is what
// the tmux cases in internal/e2e are for.
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
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)

	// Create command with real PTY
	// Use 'head -n 1' which exits immediately after reading one line
	// This is more reliable than 'read' which has timing issues with bash initialization
	cmd := newCommand(
		"head",
		[]string{"-n", "1"},
		nil,
		termsize.Size{},
		false,
		"",
		tty,
		stdoutw,
		ee,
		writers,
		discardLogger(),
		true, // an in-process pty is nobody's foreground; see the doc comment
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

func Test_Command_StdinCloseDoesNotEndSession(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	out := &recordingWriter{}
	require.NoError(t, writers.Append(out))

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()

	cmd := newCommand(
		"sh", []string{"-c", "sleep 0.5; echo ALIVE"},
		nil, termsize.Default, false, "xterm-256color",
		r, devNull, emitter.New(1), writers, testLogger(t), true,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = cmd.Start(ctx)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	// Kill stdin while the command is still running. Only the write end is
	// closed here: Run reads c.stdin's descriptor, so closing the read end
	// concurrently is a data race on os.File, not a scenario. EOF is the
	// pointed case anyway — the copy returns a nil error, and returning nil
	// would end the session exactly as surely as returning one.
	require.NoError(t, w.Close())

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("command did not finish")
	}
	require.NoError(t, r.Close())

	require.Contains(t, string(out.bytes()), "ALIVE",
		"the command must run to completion after stdin dies")
}
