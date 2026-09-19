//go:build !windows

package internal

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Design item 5: with --force-command, the host door reaches the original
// command; a guest gets the forced one on its own pty with its queries
// unfiltered.
func TestHostDoorAttachesToTheOriginalCommandUnderForceCommand(t *testing.T) {
	h := startHost(t, &Server{
		Command:      readsALine("ORIGINAL", 0),
		ForceCommand: []string{"sh", "-c", `stty -echo -opost; printf 'FORCED\033[6n\n'; IFS= read -r line`},
	})

	in, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	got := readUntil(t, out, "ORIGINAL")
	require.NotContains(t, got, "FORCED")

	_, guestOut := h.connectGuest(t)
	guestGot := readUntil(t, guestOut, "FORCED")
	require.Contains(t, guestGot, "\x1b[6n", "a forced-command guest is the terminal for its own command; its queries must reach it")
	require.NotContains(t, guestGot, "ORIGINAL")

	_, err := io.WriteString(in, "from-host\n")
	require.NoError(t, err)
	readUntil(t, out, "got:from-host")
}

func TestHostDoorServesAViewerWithoutAPty(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("VIEW", 0)})
	in, out, _ := h.connectHost(t, nil)
	readUntil(t, out, "VIEW")
	// Input is still forwarded: a viewer is pty-less, not mute. This is what
	// the functional tests drive the host through.
	_, err := io.WriteString(in, "typed\n")
	require.NoError(t, err)
	readUntil(t, out, "got:typed")
}

func TestGuestDoorStillRequiresAPty(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("X", 0)})
	// connectGuest always requests a pty; open a bare session by hand.
	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)}, HostKeyCallback: ssh.FixedHostKey(h.hostKey)})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	sess, err := client.NewSession()
	require.NoError(t, err)
	out, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	readUntil(t, out, "PTY is required")
}

// D19: when the session ends because the command exited, every shared-pty
// client is closed with the command's status.
func TestSharedPtyClientsReceiveTheCommandsExitStatus(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 7)})
	in, out, hostSess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, out, "READY")
	_, guestOut, guestSess := h.connectGuestSession(t)
	readUntil(t, guestOut, "READY")

	_, err := io.WriteString(in, "go\n")
	require.NoError(t, err)

	var exit *ssh.ExitError
	require.ErrorAs(t, hostSess.Wait(), &exit)
	require.Equal(t, 7, exit.ExitStatus(), "the host client must learn the command's status")

	// Every shared-pty client, not just the one that typed: a guest watching
	// the same command ends for the same reason and with the same status.
	var guestExit *ssh.ExitError
	require.ErrorAs(t, guestSess.Wait(), &guestExit)
	require.Equal(t, 7, guestExit.ExitStatus(), "a guest on the shared pty must learn it too")
}

// A connection is not a client. The host door authenticates a local process
// that may never open a session, and a join announced for one of those would
// sit in the client repo forever: nothing else ever deletes it.
func TestHostDoorAnnouncesAClientOnlyWhenItOpensASession(t *testing.T) {
	srv := &Server{Command: readsALine("S", 0)}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	defer srv.EventEmitter.Off(upterm.EventClientJoined, joined)

	client := h.dialHost(t)
	time.Sleep(300 * time.Millisecond)
	select {
	case evt := <-joined:
		t.Fatalf("a connection that opened no session announced a client: %v", evt.Args[0])
	default:
	}

	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	require.NoError(t, sess.Shell())

	select {
	case evt := <-joined:
		c := evt.Args[0].(*api.Client)
		require.Equal(t, api.Client_HOST, c.Kind)
	case <-time.After(harnessTimeout):
		t.Fatal("no client-joined event once the connection opened a session")
	}
}

func TestHostDoorReportsHostKind(t *testing.T) {
	srv := &Server{Command: readsALine("K", 0)}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	defer srv.EventEmitter.Off(upterm.EventClientJoined, joined)

	_, out, _ := h.connectHost(t, nil)
	readUntil(t, out, "K")

	select {
	case evt := <-joined:
		c := evt.Args[0].(*api.Client)
		require.Equal(t, api.Client_HOST, c.Kind)
		require.Equal(t, "local", c.Addr)
		require.Equal(t, upterm.AttachSSHClientVersion, c.Version)
		require.NotEmpty(t, c.PublicKeyFingerprint)
	case <-time.After(harnessTimeout):
		t.Fatal("no client-joined event for the host client")
	}
}

func TestHostDoorIgnoresReadOnly(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("RO", 0), ReadOnly: true})
	in, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, out, "RO")
	_, guestOut := h.connectGuest(t)
	readUntil(t, guestOut, "read-only session")

	_, err := io.WriteString(in, "host-types\n")
	require.NoError(t, err)
	readUntil(t, out, "got:host-types")
}

// D17: the host door failing at runtime does not end the session.
func TestHostDoorFailureDoesNotEndTheSession(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("UP", 0)})
	_, out, _ := h.connectHost(t, nil)
	readUntil(t, out, "UP")

	require.NoError(t, h.hostListener.Close())
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-h.done:
		t.Fatalf("the session ended when the attach listener failed: %v", err)
	default:
	}
	_, guestOut := h.connectGuest(t)
	readUntil(t, guestOut, "UP")
}

// A host client leaving is not the session ending. The command keeps its pty
// and a guest keeps its output.
func TestHostClientLeavingDoesNotEndTheSession(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; IFS= read -r line; sleep 0.5; printf 'ALIVE\n'; IFS= read -r line`}})
	hostIn, hostOut, hostSess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, hostOut, "READY")
	_, guestOut := h.connectGuest(t)
	readUntil(t, guestOut, "READY")

	_, err := io.WriteString(hostIn, "go\n")
	require.NoError(t, err)
	require.NoError(t, hostSess.Close())

	readUntil(t, guestOut, "ALIVE")
	select {
	case err := <-h.done:
		t.Fatalf("the session ended when its host client left: %v", err)
	default:
	}
}

// An output-only viewer that never reads is dropped, and nothing else notices.
//
// 6 MB, because the drop has to be the host's doing rather than the harness's:
// 3 MB fits inside the client's SSH channel window (2 MiB) plus the secondary
// sink's buffer (1 MiB) and never overflows, so the viewer stayed connected
// and only the harness's own read deadline ended the wait.
func TestUndrainedViewerDoesNotWedgeTheSession(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; IFS= read -r line; yes | head -c 6000000; printf 'DONE\n'; IFS= read -r line`}})
	// Both connections outlive the harness's default deadline on purpose. Six
	// megabytes takes a loaded runner longer than ten seconds, and a deadline
	// firing here would not fail an assertion honestly: on the guest it ends
	// the stream this test is reading, and on the viewer it produces exactly
	// the error the test takes as proof that the host dropped it.
	_, viewerOut, viewerSess := h.connectHost(t, nil, withDialDeadline(60*time.Second))
	readUntil(t, viewerOut, "READY")
	// The viewer reads nothing more.
	guestIn, guestOut := h.connectGuest(t, withDialDeadline(60*time.Second))
	readUntil(t, guestOut, "READY")
	_, err := io.WriteString(guestIn, "go\n")
	require.NoError(t, err)
	readUntil(t, guestOut, "DONE")

	waited := make(chan error, 1)
	go func() { waited <- viewerSess.Wait() }()
	select {
	case err := <-waited:
		require.Error(t, err, "the undrained viewer is disconnected, not left holding the fan-out")
	case <-time.After(harnessTimeout):
		t.Fatal("the undrained viewer was neither dropped nor drained")
	}
}

// A terminal leaving restores the size for the terminals that remain, over a
// real door rather than through the event handler alone.
//
// This is the end-to-end shape its unit twin in event_test.go had to stand in
// for, and it is here because what made it unreliable is now fixed: charm
// closes a session's window-change channel when its request loop ends, and
// the handler's loop read that closed channel as an endless run of 0x0
// resizes. One landing after the departing client's own detach re-added a
// terminal nothing would ever remove, pinning the minimum to nothing for the
// rest of the session — the survivor read "0 0" instead of its own size,
// seven times in fifteen runs before the fix.
func TestASmallerTerminalLeavingRestoresTheSizeOverTheDoor(t *testing.T) {
	// SIGWINCH is the nudge that makes the command speak: every attach sends
	// one through Redraw, and so does every resize. A short sleep loop rather
	// than one long sleep, because a shell runs a trap between foreground
	// commands rather than interrupting one already running.
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty -echo -opost; trap 'stty size' WINCH; printf 'READY\n'; while :; do sleep 0.1; done`}})

	_, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 100, rows: 30})
	readUntil(t, aOut, "READY")

	// The smaller terminal takes the session down to its own size: the pty is
	// sized to the smallest terminal watching it.
	_, bOut, bSess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, bOut, "READY")
	readUntil(t, aOut, "24 80")

	// And leaving gives it back. B's output is drained from here on, so its
	// handler winds down instead of parking on a write nobody is reading.
	go func() { _, _ = io.Copy(io.Discard, bOut) }()
	require.NoError(t, bSess.Close())
	readUntil(t, aOut, "30 100")
}

// A guest counts towards the minimum from the size it arrives with, not from
// its first resize. The only geometry an SSH client sends is in its pty
// request, until somebody drags a window.
//
// Written to check a review's claim that it did not — and it does, from two
// places now: the registration in the handler, and charm seeding a session's
// window channel with the pty request's own window, which the window-change
// loop then reads. Kept because neither of those is this package's to
// guarantee: the first is one line in a handler that has been rearranged
// twice this month, and the second is a charm implementation detail that an
// upgrade could take away without saying so.
func TestAGuestsArrivingSizeConstrainsTheSession(t *testing.T) {
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty -echo -opost; trap 'stty size' WINCH; printf 'READY\n'; while :; do sleep 0.1; done`}})

	_, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 100, rows: 30})
	readUntil(t, aOut, "READY")

	// The harness's guest asks for 80x24 and never resizes.
	_, gOut := h.connectGuest(t)
	readUntil(t, gOut, "READY")
	readUntil(t, aOut, "24 80")
}
