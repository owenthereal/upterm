//go:build !windows

package internal

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// withForceCommandStopGrace sets forceCommandStopGrace for the duration of t.
func withForceCommandStopGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := forceCommandStopGrace
	forceCommandStopGrace = d
	t.Cleanup(func() { forceCommandStopGrace = orig })
}

// A forced command whose guest leaves is hung up, as a terminal going away
// would hang it up, not killed outright: a full-screen program -- Herdr, say,
// as a door -- gets to clean up after itself.
func TestAForcedCommandIsHungUpWhenItsGuestLeaves(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hup")
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap 'echo hup > "$0"; exit 0' HUP; printf READY; while :; do sleep 0.05; done`, marker},
	})
	_, out, sess := h.connectGuestSession(t)
	readUntil(t, out, "READY")

	require.NoError(t, sess.Close())

	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the forced command was never hung up")
}

// When the session ends, a forced command is hung up too, and what it writes
// on its way out -- a full-screen program putting the guest's terminal back
// -- reaches the guest, with its exit status. The session waits for that
// rather than ending under it: in production the tunnel closes behind the
// session, and the guest would be cut off first.
func TestSessionEndHangsUpAForcedCommandAndWaitsForIt(t *testing.T) {
	// Long enough that the hangup handler below finishes inside the first
	// step, so nothing escalates past it.
	withHangupGrace(t, 3*time.Second)
	withForceCommandStopGrace(t, 3*time.Second)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap 'sleep 1; printf HUNGUP; exit 3' HUP; printf READY; while :; do sleep 0.05; done`},
	})
	_, out, sess := h.connectGuestSession(t)
	readUntil(t, out, "READY")
	exited := make(chan error, 1)
	go func() { exited <- sess.Wait() }()

	h.stop(t)

	// Already sent by the time the session has ended, so it arrives at once
	// rather than a second later.
	start := time.Now()
	readUntil(t, out, "HUNGUP")
	assert.Less(t, time.Since(start), 500*time.Millisecond, "the session ended before its forced command had")
	select {
	case err := <-exited:
		var exitErr *ssh.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Equal(t, 3, exitErr.ExitStatus(), "the forced command's own status")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the guest was not sent its forced command's status before the session ended")
	}
}

// A forced command that ignores the hangup and SIGTERM is still gone once the
// teardown has run its course, and the session's end is bounded by it.
func TestAForcedCommandThatIgnoresTheHangupIsKilled(t *testing.T) {
	withHangupGrace(t, 100*time.Millisecond)
	withForceCommandStopGrace(t, 100*time.Millisecond)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap '' HUP TERM; printf 'PID=%s;' $$; while :; do sleep 0.05; done`},
	})
	_, out, _ := h.connectGuestSession(t)
	seen := readUntil(t, out, ";")
	pid, err := strconv.Atoi(strings.TrimSuffix(seen[strings.Index(seen, "PID=")+len("PID="):], ";"))
	require.NoError(t, err)

	took := h.stop(t)

	assert.Less(t, took, 3*time.Second)
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 2*time.Second, 20*time.Millisecond, "the forced command outlived its teardown")
}

// A guest's terminal is put back when its forced command ends: whatever modes
// the command left set are undone, behind its last output and before the
// guest's exit status. A plain ssh client restores termios on the way out and
// nothing more, so without this a guest whose door was killed, or a program
// that simply exits without cleaning up, is left on the alternate screen with
// the mouse reporting clicks as input.
func TestAForcedCommandsGuestIsPutBack(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		stop    bool
		want    string
	}{
		{
			name:    "the command exits leaving modes set",
			command: `printf '\033[?1049h\033[?2004hREADY'; exit 0`,
			want:    "\x1b[?1049h\x1b[?2004hREADY" + "\x1b[?1049l\x1b[?2004l",
		},
		{
			// sleep has no hangup handler, so nothing of the command's own
			// puts anything back.
			name:    "the session ends under it",
			command: `printf '\033[?1049h\033[?2004hREADY'; exec sleep 30`,
			stop:    true,
			want:    "\x1b[?1049h\x1b[?2004hREADY" + "\x1b[?1049l\x1b[?2004l",
		},
		{
			name:    "the command put everything back itself",
			command: `printf '\033[?2004hREADY\033[?2004l'; exit 0`,
			want:    "\x1b[?2004hREADY\x1b[?2004l",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startHost(t, &Server{
				Command:      []string{"sh", "-c", "sleep 30"},
				ForceCommand: []string{"sh", "-c", tc.command},
			})
			_, out, _ := h.connectGuestSession(t)
			seen := readUntil(t, out, "READY")
			if tc.stop {
				h.stop(t)
			}
			rest, err := io.ReadAll(out)
			require.NoError(t, err)
			assert.Equal(t, tc.want, seen+string(rest))
		})
	}
}

// The same for the guests of the shared command: when the session ends with
// the command still holding the terminal, each guest is put back.
func TestSessionEndPutsItsGuestsBack(t *testing.T) {
	h := startHost(t, &Server{
		Command: []string{"sh", "-c", `printf '\033[?1049h\033[?2004hREADY'; exec sleep 30`},
	})
	_, out, _ := h.connectGuestSession(t)
	seen := readUntil(t, out, "READY")

	h.stop(t)

	rest, err := io.ReadAll(out)
	require.NoError(t, err)
	assert.Equal(t, "\x1b[?1049h\x1b[?2004hREADY"+"\x1b[?1049l\x1b[?2004l", seen+string(rest))
}

// The wait at the session's end is bounded. A guest that has stopped reading
// holds its forced command's output in a write to the channel that nothing
// but the connection's end releases, so a wait for its handler is a wait for
// that; the session ends at the bound instead.
func TestSessionEndStopsWaitingForAGuestThatStoppedReading(t *testing.T) {
	withHangupGrace(t, 100*time.Millisecond)
	withForceCommandStopGrace(t, 100*time.Millisecond)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"yes"},
	})
	_, out, _ := h.connectGuestSession(t, withDialDeadline(time.Minute))
	readUntil(t, out, "y\r\ny")
	// And then nothing more is read: the channel's window fills, and the
	// handler's copy blocks writing to it.
	time.Sleep(500 * time.Millisecond)

	took := h.stop(t)

	assert.Less(t, took, forceCommandStopBound()+2*time.Second)
}
