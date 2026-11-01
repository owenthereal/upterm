//go:build !windows

package internal

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/consent"
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
	_, err = sess.StdinPipe() // keep the accepted session live until Close
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	c := eventClient(t, joined)
	require.Equal(t, api.Client_GUEST, c.Kind)
	require.NotEmpty(t, c.PublicKeyFingerprint)
	select {
	case e := <-leftEvents:
		t.Fatalf("accepted guest left before its channel closed: %v", e.Args)
	case <-time.After(50 * time.Millisecond):
	}
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

// A refused forward says what actually stopped it, in the guest's terms, and
// a remedy only where one applies.
func TestARefusedForwardPreservesConsentReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checker consent.PermissionChecker
		want    string
	}{
		{"unavailable", nil, forwardUnavailableRefusal},
		{"timeout", forwardPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			return consent.Deny, consent.ErrTimeout
		}), forwardTimeoutRefusal},
		{"denied", forwardPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			return consent.Deny, nil
		}), forwardDeniedRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startHost(t, &Server{Command: readsALine("READY", 0), PermissionChecker: tc.checker})
			_, err := h.guestClient(t).Dial("tcp", "127.0.0.1:1")
			var open *ssh.OpenChannelError
			require.ErrorAs(t, err, &open)
			require.Equal(t, ssh.Prohibited, open.Reason)
			require.Equal(t, tc.want, open.Message)
		})
	}
}

// A command that exits on its own ends the session with no stop: the
// session's context ends and the stop's never does. A forward still waiting
// for approval then ends with the session, as it would at a stop or with its
// transport, rather than waiting on until the tunnel closes: it is refused
// and audited as canceled, and nothing is dialed.
func TestAPendingForwardEndsWhenTheCommandExits(t *testing.T) {
	end := filepath.Join(t.TempDir(), "end")
	asked, ended := make(chan struct{}), make(chan struct{})
	output := &recordingWriter{}
	h := startHost(t, &Server{
		// Exits 0 once the test creates the file. Polled rather than a FIFO's
		// EOF, which a hosted command here has been seen to miss.
		Command: []string{"sh", "-c", `while [ ! -e "$0" ]; do sleep 0.01; done; exit 0`, end},
		Logger:  slog.New(slog.NewJSONHandler(output, nil)),
		PermissionChecker: forwardPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
			close(asked)
			<-ctx.Done()
			close(ended)
			return consent.Deny, consent.ErrCanceled
		}),
	})
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = target.Close() }()
	guest := h.guestClient(t)
	dialed := make(chan error, 1)
	go func() {
		conn, err := guest.Dial("tcp", target.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		dialed <- err
	}()
	select {
	case <-asked:
	case <-time.After(harnessTimeout):
		t.Fatal("the forward was not put to the checker")
	}
	require.NoError(t, os.WriteFile(end, nil, 0o600))
	select {
	case <-h.stopped:
	case <-time.After(harnessTimeout):
		t.Fatal("the session did not end with its command")
	}
	// Well before the guest's own connection deadline could end the wait.
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("forward still waiting for approval after the session ended")
	}
	var open *ssh.OpenChannelError
	require.ErrorAs(t, <-dialed, &open)
	require.Equal(t, ssh.Prohibited, open.Reason)
	require.Equal(t, forwardCanceledRefusal, open.Message)
	var policy []map[string]any
	for _, record := range forwardingAuditRecords(t, string(output.bytes())) {
		if record["msg"] == "forwarding permission policy" {
			policy = append(policy, record)
		}
	}
	require.Len(t, policy, 1)
	require.Equal(t, "canceled", policy[0]["outcome"])
	require.NoError(t, target.SetDeadline(time.Now().Add(20*time.Millisecond)))
	conn, err := target.Accept()
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "a forward the session's end canceled was dialed")
}

// A read-only session can't allow forwarding: the host would have to drop
// --read-only to pass the flag, so the refusal says what the session is
// instead of naming it.
func TestAReadOnlySessionsRefusedForwardSaysSo(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 0), ReadOnly: true})
	_, err := h.guestClient(t).Dial("tcp", "127.0.0.1:1")
	var open *ssh.OpenChannelError
	require.ErrorAs(t, err, &open)
	require.Equal(t, ssh.Prohibited, open.Reason)
	require.Equal(t, "upterm: this session is read-only, so it doesn't allow port forwarding", open.Message)
}

// A forward the session allows but the dial fails keeps the library's own
// connect-failure text: only the refusal for a session that doesn't allow
// forwarding is reworded.
func TestAForwardThatCantConnectKeepsTheLibrarysText(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := ln.Addr().String()
	require.NoError(t, ln.Close())

	h := startHost(t, &Server{Command: readsALine("READY", 0), AllowLocalTCPForwarding: true})
	_, err = h.guestClient(t).Dial("tcp", closed)
	var open *ssh.OpenChannelError
	require.ErrorAs(t, err, &open)
	require.Equal(t, ssh.ConnectionFailed, open.Reason)
	require.Contains(t, open.Message, "connection refused")
	require.NotContains(t, open.Message, "port forwarding")
}

// A guest whose command can't start is told so on its stderr: which command
// it was, the host's login or forced command or the one it asked for, what
// its status stands for, and the host's log, which has the error itself. None
// of the error is passed on. A start that found no such file is told which
// file the host finds missing: the directory the command starts in, gone since
// the session started, a file the program needs, such as the interpreter a
// script names, or else the program. The guest has a pty, and its terminal is
// raw, so the line ends with a carriage return as well.
func TestAGuestWhoseCommandCantStartIsToldWhichAndWhy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	notExecutable := filepath.Join(t.TempDir(), "not-executable")
	require.NoError(t, os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o644))
	// Unix only, as this file is: the kernel runs the interpreter a script
	// names, and finds none.
	scripts := t.TempDir()
	noInterpreter := filepath.Join(scripts, "door.sh")
	require.NoError(t, os.WriteFile(noInterpreter, []byte("#!/nonexistent/upterm-interpreter\necho ran\n"), 0o755))
	for _, tc := range []struct {
		name    string
		srv     *Server
		exec    bool
		shell   string
		dirGone bool // the directory guest commands start in is removed once the session is up
		status  int
		message string
	}{
		{
			name:    "forced command not found",
			srv:     &Server{ForceCommand: []string{"/nonexistent-upterm-force-command"}, LogPath: "/var/log/upterm.log"},
			status:  127,
			message: "upterm: the host's forced command couldn't start: /nonexistent-upterm-force-command was not found. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "login command not on PATH",
			srv:     &Server{LoginCommand: []string{"upterm-nonexistent-login-command", "--flag"}, LogPath: filepath.Join(home, ".local", "state", "upterm", "upterm.log")},
			status:  127,
			message: "upterm: the host's login command couldn't start: upterm-nonexistent-login-command was not found on the session's PATH. The host's log is ~/.local/state/upterm/upterm.log.\r\n",
		},
		{
			name:    "forced command not executable",
			srv:     &Server{ForceCommand: []string{notExecutable}, LogPath: "/var/log/upterm.log"},
			status:  126,
			message: "upterm: the host's forced command couldn't start: " + notExecutable + " couldn't be executed. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "forced exec not found",
			srv:     &Server{ForceCommand: []string{"/nonexistent-upterm-force-command"}, LogPath: "/var/log/upterm.log"},
			exec:    true,
			status:  127,
			message: "upterm: the host's forced command couldn't start: /nonexistent-upterm-force-command was not found. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "requested command's shell not found",
			srv:     &Server{AcceptExec: true, LogPath: "/var/log/upterm.log"},
			exec:    true,
			shell:   "/nonexistent/upterm-shell",
			status:  127,
			message: "upterm: your command couldn't start: the host's shell, /nonexistent/upterm-shell, was not found. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "no log to name",
			srv:     &Server{ForceCommand: []string{"/nonexistent-upterm-force-command"}},
			status:  127,
			message: "upterm: the host's forced command couldn't start: /nonexistent-upterm-force-command was not found.\r\n",
		},
		{
			name:    "a program's name is told plain",
			srv:     &Server{ForceCommand: []string{"/nonexistent\x1b]0;owned\a"}},
			status:  127,
			message: "upterm: the host's forced command couldn't start: /nonexistent?]0;owned? was not found.\r\n",
		},
		{
			name:    "login command whose directory is gone",
			srv:     &Server{LoginCommand: []string{"sh", "-c", "echo ran"}, LogPath: "/var/log/upterm.log"},
			dirGone: true,
			status:  127,
			message: "upterm: the host's login command couldn't start: the directory it starts in no longer exists. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "requested command whose directory is gone",
			srv:     &Server{AcceptExec: true, LogPath: "/var/log/upterm.log"},
			exec:    true,
			shell:   "/bin/sh",
			dirGone: true,
			status:  127,
			message: "upterm: your command couldn't start: the directory it starts in no longer exists. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			name:    "forced command whose interpreter is missing",
			srv:     &Server{ForceCommand: []string{noInterpreter}, LogPath: "/var/log/upterm.log"},
			status:  127,
			message: "upterm: the host's forced command couldn't start: " + noInterpreter + " needs a file that is missing, such as its interpreter. The host's log is /var/log/upterm.log.\r\n",
		},
		{
			// A relative program is looked for where the command starts,
			// not where the host runs.
			name:    "relative forced command whose interpreter is missing",
			srv:     &Server{ForceCommand: []string{"./door.sh"}, CommandDir: scripts, LogPath: "/var/log/upterm.log"},
			status:  127,
			message: "upterm: the host's forced command couldn't start: ./door.sh needs a file that is missing, such as its interpreter. The host's log is /var/log/upterm.log.\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shell != "" {
				t.Setenv("SHELL", tc.shell)
			}
			if tc.dirGone {
				tc.srv.CommandDir = filepath.Join(t.TempDir(), "launch")
				require.NoError(t, os.Mkdir(tc.srv.CommandDir, 0o700))
			}
			tc.srv.Command = readsALine("READY", 0)
			h := startHost(t, tc.srv)
			client := h.guestClient(t)
			if tc.dirGone {
				require.NoError(t, os.Remove(tc.srv.CommandDir))
			}
			sess, err := client.NewSession()
			require.NoError(t, err)
			var stdout, stderr bytes.Buffer
			sess.Stdout, sess.Stderr = &stdout, &stderr
			if tc.exec {
				err = sess.Run("true")
			} else {
				require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
				require.NoError(t, sess.Shell())
				err = sess.Wait()
			}
			requireExitStatus(t, err, tc.status)
			require.Equal(t, tc.message, stderr.String())
			require.Empty(t, stdout.String())
		})
	}
}

// A command that ran and exited with a status of its own is not one that
// couldn't start, whatever that status is.
func TestAGuestCommandThatExitsWith127IsNotToldItCouldntStart(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 0), ForceCommand: []string{"sh", "-c", "exit 127"}, LogPath: "/var/log/upterm.log"})
	sess, err := h.guestClient(t).NewSession()
	require.NoError(t, err)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	requireExitStatus(t, sess.Run("ignored"), 127)
	require.Empty(t, stderr.String())
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

// Exec presence is per channel. Natural completion and cancellation must each
// remove exactly the channel that joined, leaving its sibling present.
func TestGuestExecChannelsLeaveWithTheirJoinedIDs(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 0), AcceptExec: true}
	h := startHost(t, srv)
	joined := srv.EventEmitter.On(upterm.EventClientJoined)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	defer srv.EventEmitter.Off(upterm.EventClientJoined, joined)
	defer srv.EventEmitter.Off(upterm.EventClientLeft, left)
	client := h.guestClient(t)
	sessions := make([]*ssh.Session, 2)
	inputs := make([]io.WriteCloser, 2)
	ids := make([]string, 2)
	for i := range sessions {
		s, err := client.NewSession()
		require.NoError(t, err)
		sessions[i] = s
		t.Cleanup(func() { _ = s.Close() })
		inputs[i], err = s.StdinPipe()
		require.NoError(t, err)
		require.NoError(t, s.Start("cat >/dev/null"))
		select {
		case e := <-joined:
			ids[i] = e.Args[0].(*api.Client).Id
		case <-time.After(harnessTimeout):
			t.Fatal("exec channel did not join")
		}
	}
	require.NotEqual(t, ids[0], ids[1])
	require.NoError(t, inputs[0].Close())
	require.NoError(t, sessions[0].Wait())
	select {
	case e := <-left:
		require.Equal(t, ids[0], e.Args[0])
	case <-time.After(harnessTimeout):
		t.Fatal("completed exec channel did not leave")
	}
	select {
	case e := <-left:
		t.Fatalf("live sibling left: %v", e.Args)
	default:
	}
	require.NoError(t, sessions[1].Close())
	select {
	case e := <-left:
		require.Equal(t, ids[1], e.Args[0])
	case <-time.After(harnessTimeout):
		t.Fatal("cancelled exec channel did not leave")
	}
}
