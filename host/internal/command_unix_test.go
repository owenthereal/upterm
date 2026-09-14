//go:build !windows

package internal

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
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

func Test_Command_UndrainedStdoutPipeDoesNotWedgeSession(t *testing.T) {
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = pr.Close() }() // deliberately never read

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	watcher := &recordingWriter{}
	require.NoError(t, writers.Append(watcher))

	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()

	cmd := newCommand(
		"sh", []string{"-c", "for i in $(seq 1 5000); do echo 0123456789012345678901234567890123456789; done; echo DONE"},
		nil, termsize.Default, false, "xterm-256color",
		devNull, pw, emitter.New(1), writers, testLogger(t), false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = cmd.Start(ctx)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("session wedged on an undrained stdout pipe")
	}

	require.Contains(t, string(watcher.bytes()), "DONE",
		"output must keep flowing to other writers while stdout is blocked")
}

func Test_Command_SlowStdoutPipeStillGetsItsTail(t *testing.T) {
	pr, pw, err := os.Pipe()
	require.NoError(t, err)

	// A reader that starts blocked, so backpressure is observable rather than
	// hoped for, then drains slowly but never stops.
	//
	// Review fix: the previous version emitted ~2 KB, which fits entirely in a
	// pipe buffer. Nothing was ever pending at shutdown, so the test passed
	// without exercising the flush path it is named for. The command now emits
	// well past any pipe buffer, and the reader is held until it has.
	//
	// The pace is not what creates the backpressure — holding the reader until
	// the fan-out has passed the threshold below is. What the pace has to do is
	// leave the flush room to finish inside guestFlushTimeout, which is one
	// second: at 1ms per 256-byte chunk the ~198 KB still to drain took ~0.94s,
	// so under -race with the whole suite loading the machine the flush expired,
	// Close discarded the tail, and the test blamed production code for a timing
	// budget. 100µs keeps the same slow-reader shape with an order of magnitude
	// of headroom.
	var (
		mu      sync.Mutex
		got     []byte
		read    = make(chan struct{})
		release = make(chan struct{})
	)
	go func() {
		defer close(read)
		<-release
		buf := make([]byte, 256)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				mu.Lock()
				got = append(got, buf[:n]...)
				mu.Unlock()
				time.Sleep(100 * time.Microsecond)
			}
			if err != nil {
				return
			}
		}
	}()

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)

	// Watch the fan-out so the test can tell when the command has produced
	// enough to have filled the pipe and backed up into the sink.
	progress := &recordingWriter{}
	require.NoError(t, writers.Append(progress))

	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()

	// 4000 lines of 64 bytes is ~256 KiB: far past a 64 KiB pipe buffer, and
	// still comfortably inside the 1 MiB sink, so this is the slow-reader case
	// and not the overflow case.
	cmd := newCommand(
		"sh", []string{"-c",
			"i=0; while [ $i -lt 4000 ]; do echo 0123456789012345678901234567890123456789012345678901234567890123; i=$((i+1)); done; echo TAIL-MARKER"},
		nil, termsize.Default, false, "xterm-256color",
		devNull, pw, emitter.New(1), writers, testLogger(t), false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = cmd.Start(ctx)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	// Wait until the fan-out has seen more than a pipe buffer's worth, which
	// means the sink is holding output the reader has not taken. Only then let
	// the reader start: now the tail genuinely has to survive shutdown.
	require.Eventually(t, func() bool {
		return len(progress.bytes()) > 128<<10
	}, 30*time.Second, 10*time.Millisecond, "command did not produce enough to create backpressure")
	close(release)

	require.NoError(t, <-done)

	_ = pw.Close()
	<-read

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, string(got), "TAIL-MARKER",
		"a slow but healthy stdout must still receive the command's last output")
}

// inheritedTerm is what the test's own environment carries, so that a case
// asserting the host's TERM won is asserting that it beat something.
const inheritedTerm = "upterm-inherited-term"

// Test_Command_TermIsAppendedSoItBeatsTheInheritedOne covers wiring that is
// load-bearing and was untested: --term reaches the command, and it does so by
// being appended to the environment rather than prepended. exec.Cmd keeps the
// last duplicate key, so a prepended TERM would be silently overridden by the
// inherited one and the flag would do nothing at all.
func Test_Command_TermIsAppendedSoItBeatsTheInheritedOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		term string
		want string
	}{
		{name: "the host names a term", term: "vt100", want: "TERM=vt100"},
		{name: "the host names none", term: "", want: "TERM=" + inheritedTerm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", inheritedTerm)

			// Never written to, and never a terminal, so Run does not forward
			// it and nothing here has to feed it.
			stdinr, stdinw, err := os.Pipe()
			require.NoError(t, err)
			defer func() { _ = stdinr.Close() }()
			defer func() { _ = stdinw.Close() }()

			writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
			out := &recordingWriter{}
			require.NoError(t, writers.Append(out))

			devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			require.NoError(t, err)
			defer func() { _ = devNull.Close() }()

			cmd := newCommand(
				"sh", []string{"-c", "echo TERM=$TERM"},
				nil, termsize.Default, false, tc.term,
				stdinr, devNull, emitter.New(1), writers, testLogger(t), false,
			)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err = cmd.Start(ctx)
			require.NoError(t, err)
			require.NoError(t, cmd.Run())

			require.Contains(t, string(out.bytes()), tc.want)
		})
	}
}

// Test_Command_SessionEnvBeatsTheInheritedOne pins the same rule for the
// variables that tell a script which session it is running in. A host started
// inside another upterm session -- or one whose variables were forwarded by
// the README's tmux tip -- inherits somebody else's UPTERM_SESSION_NAME and
// UPTERM_ADMIN_SOCKET, and `upterm session info` run inside the inner session
// would then report the outer one.
func Test_Command_SessionEnvBeatsTheInheritedOne(t *testing.T) {
	t.Setenv(upterm.HostSessionNameEnvVar, "outer-session")
	t.Setenv(upterm.HostAdminSocketEnvVar, "/outer/admin.sock")

	// Never written to, and never a terminal, so Run does not forward it and
	// nothing here has to feed it.
	stdinr, stdinw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = stdinr.Close() }()
	defer func() { _ = stdinw.Close() }()

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	out := &recordingWriter{}
	require.NoError(t, writers.Append(out))

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()

	cmd := newCommand(
		"sh", []string{"-c", fmt.Sprintf("echo NAME=$%s SOCKET=$%s",
			upterm.HostSessionNameEnvVar, upterm.HostAdminSocketEnvVar)},
		[]string{
			upterm.HostSessionNameEnvVar + "=inner-session",
			upterm.HostAdminSocketEnvVar + "=/inner/admin.sock",
		},
		termsize.Default, false, "",
		stdinr, devNull, emitter.New(1), writers, testLogger(t), false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = cmd.Start(ctx)
	require.NoError(t, err)
	require.NoError(t, cmd.Run())

	require.Contains(t, string(out.bytes()), "NAME=inner-session SOCKET=/inner/admin.sock",
		"the session's own environment must beat the one it inherited")
}
