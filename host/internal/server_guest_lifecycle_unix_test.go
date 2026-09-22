//go:build !windows

package internal

import (
	"net"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func (h *hostHarness) guestClient(t *testing.T) *ssh.Client {
	t.Helper()
	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)}, HostKeyCallback: ssh.FixedHostKey(h.hostKey),
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func eventClient(t *testing.T, ch <-chan *api.Client) *api.Client {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(harnessTimeout):
		t.Fatal("guest did not join")
		return nil
	}
}

func TestGuestEventsFollowAcceptedSessionLifecycle(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0)}
	h := startHost(t, srv)
	joinedEvents := srv.EventEmitter.On(upterm.EventClientJoined)
	leftEvents := srv.EventEmitter.On(upterm.EventClientLeft)
	defer srv.EventEmitter.Off(upterm.EventClientJoined, joinedEvents)
	defer srv.EventEmitter.Off(upterm.EventClientLeft, leftEvents)
	joined := make(chan *api.Client, 2)
	go func() {
		for e := range joinedEvents {
			joined <- e.Args[0].(*api.Client)
		}
	}()

	client := h.guestClient(t)
	select {
	case c := <-joined:
		t.Fatalf("auth-only connection joined: %v", c)
	case <-time.After(100 * time.Millisecond):
	}
	empty, err := client.NewSession()
	require.NoError(t, err)
	_ = empty.Close()
	select {
	case c := <-joined:
		t.Fatalf("empty session channel joined: %v", c)
	case <-time.After(100 * time.Millisecond):
	}
	bare, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, bare.Shell())
	_ = bare.Close()
	select {
	case c := <-joined:
		t.Fatalf("rejected no-PTY session joined: %v", c)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case e := <-leftEvents:
		t.Fatalf("rejected session left without joining: %v", e.Args)
	default:
	}

	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	c := eventClient(t, joined)
	require.Equal(t, api.Client_GUEST, c.Kind)
	require.NotEmpty(t, c.PublicKeyFingerprint)
	require.NoError(t, sess.Close())
	select {
	case e := <-leftEvents:
		require.Equal(t, c.Id, e.Args[0])
	case <-time.After(harnessTimeout):
		t.Fatal("accepted guest did not leave")
	}
}

func TestGuestSessionsOnOneTransportHaveSeparateEventIDs(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0)}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	defer srv.EventEmitter.Off(upterm.EventClientJoined, joined)
	defer srv.EventEmitter.Off(upterm.EventClientLeft, left)
	client := h.guestClient(t)
	sessions := make([]*ssh.Session, 2)
	ids := make([]string, 2)
	for i := range sessions {
		var err error
		sessions[i], err = client.NewSession()
		require.NoError(t, err)
		require.NoError(t, sessions[i].RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		_, err = sessions[i].StdinPipe() // keep both channels live until explicitly closed
		require.NoError(t, err)
		require.NoError(t, sessions[i].Shell())
		select {
		case e := <-joined:
			ids[i] = e.Args[0].(*api.Client).Id
		case <-time.After(harnessTimeout):
			t.Fatal("guest did not join")
		}
	}
	require.NotEqual(t, ids[0], ids[1])
	for i := range sessions {
		_ = sessions[i].Close()
		select {
		case e := <-left:
			require.Equal(t, ids[i], e.Args[0])
		case <-time.After(harnessTimeout):
			t.Fatal("guest did not leave")
		}
	}
}

func TestAcceptedSFTPSessionEmitsPairedGuestEvents(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0)}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	client := h.guestClient(t)
	sftpClient, err := sftp.NewClient(client)
	require.NoError(t, err)
	var id string
	select {
	case e := <-joined:
		guest := e.Args[0].(*api.Client)
		require.Equal(t, api.Client_GUEST, guest.Kind)
		id = guest.Id
	case <-time.After(harnessTimeout):
		t.Fatal("accepted SFTP session did not join")
	}
	require.NoError(t, sftpClient.Close())
	select {
	case e := <-left:
		require.Equal(t, id, e.Args[0])
	case <-time.After(harnessTimeout):
		t.Fatal("SFTP session did not leave")
	}
}

func TestDisabledSFTPSessionDoesNotJoin(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0), SFTPDisabled: true}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	client := h.guestClient(t)
	_, err := sftp.NewClient(client)
	require.Error(t, err)
	select {
	case e := <-joined:
		t.Fatalf("disabled SFTP session joined: %v", e.Args)
	case e := <-left:
		t.Fatalf("disabled SFTP session left without joining: %v", e.Args)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestFailedForceCommandDoesNotJoin(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0), ForceCommand: []string{"/nonexistent-upterm-force-command"}}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	client := h.guestClient(t)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	_ = sess.Wait()
	select {
	case e := <-joined:
		t.Fatalf("failed force command joined: %v", e.Args)
	case e := <-left:
		t.Fatalf("failed force command left without joining: %v", e.Args)
	case <-time.After(100 * time.Millisecond):
	}
}
