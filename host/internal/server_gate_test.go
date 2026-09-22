//go:build !windows

package internal

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// markerCommand touches $UPTERM_TEST_MARK when it starts, so a test can tell
// "not started yet" from "started and quiet".
func markerCommand(t *testing.T, then string) (cmd []string, env []string, mark string) {
	t.Helper()
	mark = filepath.Join(t.TempDir(), "started")
	return []string{"sh", "-c", `: > "$UPTERM_TEST_MARK"; stty -echo -opost; ` + then},
		[]string{"UPTERM_TEST_MARK=" + mark}, mark
}

func TestGateDefersTheCommandUntilTheFirstHostClientIsSubscribed(t *testing.T) {
	cmd, env, mark := markerCommand(t, `printf 'hello\n'; exit 3`)
	h := startHost(t, &Server{Command: cmd, CommandEnv: env, AwaitInitialClient: true})

	time.Sleep(300 * time.Millisecond)
	_, err := os.Stat(mark)
	require.True(t, os.IsNotExist(err), "the command must not start before a host client is subscribed")

	// An immediate-exit command and a client that attaches afterwards: the
	// design's race. With the gate the client is subscribed before the first
	// byte exists, so it sees the output and the status every time.
	_, out, sess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, out, "hello")
	var exit *ssh.ExitError
	require.ErrorAs(t, sess.Wait(), &exit)
	require.Equal(t, 3, exit.ExitStatus())
	_, err = os.Stat(mark)
	require.NoError(t, err)
}

func TestGateTimesOutWithoutStartingTheCommand(t *testing.T) {
	cmd, env, mark := markerCommand(t, `IFS= read -r line`)
	h := startHost(t, &Server{Command: cmd, CommandEnv: env, AwaitInitialClient: true, InitialClientTimeout: 200 * time.Millisecond})

	select {
	case err := <-h.done:
		require.ErrorIs(t, err, ErrNoInitialClient)
	case <-time.After(harnessTimeout):
		t.Fatal("the server did not give up waiting for a client")
	}
	_, err := os.Stat(mark)
	require.True(t, os.IsNotExist(err), "a timed-out gate must never have started the command")
	require.Equal(t, CommandResult{}, h.srv.CommandResult())
}

func TestGateOpensThePtyAtTheInitialClientsSize(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c", `stty -echo -opost; stty size; IFS= read -r line`}, AwaitInitialClient: true})
	_, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 132, rows: 43})
	readUntil(t, out, "43 132")
}

func TestGatePinnedSizeBeatsTheInitialClient(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c", `stty -echo -opost; stty size; IFS= read -r line`},
		AwaitInitialClient: true, PtySize: termsize.Size{Cols: 100, Rows: 30}, PinPtySize: true})
	_, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 132, rows: 43})
	readUntil(t, out, "30 100")
}

func TestGateIsOpenedByAViewerAtTheDefaultSize(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c", `stty -echo -opost; stty size; IFS= read -r line`}, AwaitInitialClient: true})
	_, out, _ := h.connectHost(t, nil)
	readUntil(t, out, "24 80")
}

func TestGuestsAreNotServedBeforeTheCommandStarts(t *testing.T) {
	cmd, env, _ := markerCommand(t, `printf 'started\n'; IFS= read -r line`)
	h := startHost(t, &Server{Command: cmd, CommandEnv: env, AwaitInitialClient: true})

	type guest struct {
		out io.Reader
		err error
	}
	guestReady := make(chan guest, 1)
	go func() {
		_, out, _, err := h.dialGuest(t)
		guestReady <- guest{out, err}
	}()
	select {
	case <-guestReady:
		t.Fatal("a guest was served a session whose command has not started")
	case <-time.After(300 * time.Millisecond):
	}

	_, out, _ := h.connectHost(t, nil)
	readUntil(t, out, "started")
	select {
	case g := <-guestReady:
		require.NoError(t, g.err)
		readUntil(t, g.out, "started")
	case <-time.After(harnessTimeout):
		t.Fatal("the guest was not served once the command started")
	}
}

// clientReleaseTimeout bounds how long a client attached to a session that can
// never produce a pty may stay connected. Deliberately well inside
// harnessTimeout rather than equal to it: every host-door connection carries an
// absolute deadline of harnessTimeout, so a bound of harnessTimeout would be
// satisfied by that deadline tearing the connection down — the test would pass
// whether or not anything released the client. Release is immediate when it
// happens at all, so seconds of headroom cost nothing.
const clientReleaseTimeout = 2 * time.Second

// The gate opens on a command that then cannot start, so the pty the attached
// client is holding never arrives. Nothing else can release it: the client is
// parked inside the shared handle, not in the session, so only abandoning the
// handle ends its session — and a client that is never released is a host that
// never exits.
func TestAttachedClientIsReleasedWhenTheCommandFailsToStart(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"/nonexistent/upterm-no-such-binary"}, AwaitInitialClient: true})
	in, _, sess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	// Typed at once, so the input copy is parked in the shared handle's Write
	// by the time the start fails. Best-effort, and deliberately unasserted:
	// subscribing is what opens the gate, so the start this write is racing is
	// the one it provokes, and a start that loses no time failing tears the
	// session down first and fails the write with EOF. Either order parks or
	// releases the client, which is what the waits below are about, so the
	// write's own error says nothing about the release path.
	_, _ = io.WriteString(in, "x\n")

	waited := make(chan error, 1)
	go func() { waited <- sess.Wait() }()
	select {
	case <-waited:
		// Any status: that the session ended at all is the guarantee.
	case <-time.After(clientReleaseTimeout):
		t.Fatal("a client attached to a command that never started was not released")
	}

	select {
	case err := <-h.done:
		require.ErrorContains(t, err, "error starting command")
	case <-time.After(harnessTimeout):
		t.Fatal("the server did not return after its command failed to start")
	}
}

func TestInputTypedBeforeTheCommandStartsIsDelivered(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("GO", 0), AwaitInitialClient: true})
	in, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	// Written as early as the client can: this frequently lands before the
	// pty exists, and the shared handle has to hold it until it does.
	_, err := io.WriteString(in, "early\n")
	require.NoError(t, err)
	readUntil(t, out, "got:early")
}
