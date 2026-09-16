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
