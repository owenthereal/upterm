//go:build !windows

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// guestEnd keeps what a guest's session ran over, so a test whose read of the
// session's output fails can say what ended it. dialGuest fills it (see
// withGuestEnd).
//
// A guest that reads nothing and then EOF can't tell from the read alone which
// of four things happened. Its own connection may have reached its deadline.
// The host may have closed the connection, or closed the session's channel
// with or without a status, or ended the output and kept the channel open.
// Each needs a different fix.
type guestEnd struct {
	conn   net.Conn // the guest's own socket, so a test can end its transport
	client *ssh.Client
	sess   *ssh.Session
}

// guestEndSettle is how long cause waits for a session whose output has ended
// to say how it ended. A channel's close travels right behind the end of its
// output, so it is already on its way when the read sees the end.
const guestEndSettle = time.Second

// cause says what ended the guest's session. Call it only once a read of the
// session's output has failed: on a live session it waits guestEndSettle for
// an end that isn't coming. It must run before the test's cleanup closes the
// client.
//
// It asks the connection first, with a request that wants a reply. A
// connection that answers is still up, so the host ended the session on it.
// One that can't answer is gone, and its own error says whether the guest's
// deadline or the host ended it.
func (e *guestEnd) cause() string {
	probe := make(chan error, 1)
	go func() {
		// The reply is what makes this a probe. x/crypto wakes the guest's
		// read with the end of its channels before it fails writes on a
		// connection whose read side has ended, and the first write it fails
		// it reports as sent. A request that wants no reply can land in
		// between and come back fine from a connection that is gone; one that
		// wants a reply waits for the connection's end instead.
		_, _, err := e.client.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		probe <- err
	}()
	var probeErr error
	select {
	case probeErr = <-probe:
	case <-time.After(harnessTimeout):
		return fmt.Sprintf("the connection neither answered nor ended within %s", harnessTimeout)
	}

	if probeErr == nil {
		waited := make(chan error, 1)
		go func() { waited <- e.sess.Wait() }()
		select {
		case err := <-waited:
			if err == nil {
				return "the connection is up; the host closed the session with exit status 0"
			}
			return "the connection is up; the host closed the session: " + err.Error()
		case <-time.After(guestEndSettle):
			return fmt.Sprintf("the connection is up; the host ended the session's output, and its channel was still open %s later", guestEndSettle)
		}
	}

	ended := make(chan error, 1)
	go func() { ended <- e.client.Wait() }()
	select {
	case err := <-ended:
		// The guest's socket is closed only by its own connection's end, or by
		// the test's cleanup after this, so a read that ended without the
		// guest's deadline was ended by the host: closed between packets, in
		// the middle of one, or reset.
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			return "the guest's connection reached its deadline"
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return "the host closed the connection"
		case errors.Is(err, syscall.ECONNRESET):
			return "the host reset the connection"
		default:
			return fmt.Sprintf("the connection ended: %v", err)
		}
	case <-time.After(harnessTimeout):
		return fmt.Sprintf("the probe failed (%v), and the guest's connection hadn't ended %s later", probeErr, harnessTimeout)
	}
}

// endingServer is an SSH server that takes one guest's session and ends it
// however the test says, so each way a guest's output can end happens on
// purpose rather than by chance. It answers the guest's pty and shell
// requests, and its global requests with a refusal, which is still an
// answer.
type endingServer struct {
	addr    string
	hostKey ssh.PublicKey
	// end is how the test says how to end the session, once its shell has
	// been answered. It is given the session's channel and the TCP
	// connection under it.
	end chan<- func(*net.TCPConn, ssh.Channel)
}

func startEndingServer(t *testing.T) *endingServer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	end := make(chan func(*net.TCPConn, ssh.Channel))
	stop := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- raw
		_, chans, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		wg.Go(func() { ssh.DiscardRequests(reqs) })
		newChan, ok := <-chans
		if !ok {
			return
		}
		wg.Go(func() {
			for c := range chans {
				_ = c.Reject(ssh.Prohibited, "one session per connection")
			}
		})
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return
		}
		wg.Go(func() {
			for req := range chReqs {
				_ = req.Reply(req.Type == "pty-req" || req.Type == "shell", nil)
			}
		})
		select {
		case how := <-end:
			how(raw.(*net.TCPConn), ch)
		case <-stop:
		}
	})
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
		select {
		case raw := <-accepted:
			_ = raw.Close()
		default:
		}
		wg.Wait()
	})
	return &endingServer{addr: ln.Addr().String(), hostKey: signer.PublicKey(), end: end}
}

// exitStatus is the body of an SSH exit-status request.
func exitStatus(code uint32) []byte { return ssh.Marshal(struct{ Status uint32 }{code}) }

// Each way a guest's output can end, made to happen, reads as nothing then
// EOF, and cause names which one it was.
func TestAGuestsEndIsNamed(t *testing.T) {
	for _, tc := range []struct {
		name string
		// end is how the host ends the session; nil leaves it to the guest's
		// own deadline, which the test brings forward to now.
		end  func(*net.TCPConn, ssh.Channel)
		want string
	}{
		{
			name: "status",
			end: func(_ *net.TCPConn, ch ssh.Channel) {
				_, _ = ch.SendRequest("exit-status", false, exitStatus(3))
				_ = ch.Close()
			},
			want: "the connection is up; the host closed the session: Process exited with status 3",
		},
		{
			name: "zero status",
			end: func(_ *net.TCPConn, ch ssh.Channel) {
				_, _ = ch.SendRequest("exit-status", false, exitStatus(0))
				_ = ch.Close()
			},
			want: "the connection is up; the host closed the session with exit status 0",
		},
		{
			name: "no status",
			end:  func(_ *net.TCPConn, ch ssh.Channel) { _ = ch.Close() },
			want: "the connection is up; the host closed the session: wait: remote command exited without exit status or exit signal",
		},
		{
			name: "output only",
			end:  func(_ *net.TCPConn, ch ssh.Channel) { _ = ch.CloseWrite() },
			want: "the connection is up; the host ended the session's output, and its channel was still open 1s later",
		},
		{
			name: "host closed the connection",
			end:  func(raw *net.TCPConn, _ ssh.Channel) { _ = raw.Close() },
			want: "the host closed the connection",
		},
		{
			name: "host reset the connection",
			end: func(raw *net.TCPConn, _ ssh.Channel) {
				_ = raw.SetLinger(0) // a close that sends RST rather than FIN
				_ = raw.Close()
			},
			want: "the host reset the connection",
		},
		{
			name: "deadline",
			want: "the guest's connection reached its deadline",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := startEndingServer(t)
			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			signer, err := ssh.NewSignerFromKey(key)
			require.NoError(t, err)
			h := &hostHarness{addr: s.addr, hostKey: s.hostKey, guestSigner: signer}

			// dialGuest returns once the shell has been answered: the session
			// is up before it is ended.
			var end guestEnd
			_, out, _, err := h.dialGuest(t, withGuestEnd(&end))
			require.NoError(t, err)
			if tc.end != nil {
				s.end <- tc.end
			} else {
				require.NoError(t, end.conn.SetDeadline(time.Now()))
			}

			n, err := io.ReadFull(out, make([]byte, 1))
			require.Zero(t, n)
			require.ErrorIs(t, err, io.EOF)
			requireCause(t, &end, tc.want)
		})
	}
}

// A guest of the real host whose connection reaches its deadline is named as
// such: on the real door too, dialGuest fills the guestEnd that withGuestEnd
// passes it.
func TestAGuestsDeadlineOnTheRealDoorIsNamed(t *testing.T) {
	h := startHost(t, &Server{Command: printsTheRing})
	var end guestEnd
	_, out := h.connectGuest(t, withWindow(phone), withGuestEnd(&end))
	readUntil(t, out, ringMark)

	require.NoError(t, end.conn.SetDeadline(time.Now()))
	_, err := io.Copy(io.Discard, out)
	require.NoError(t, err, "the guest's output ended with something other than EOF")
	requireCause(t, &end, "the guest's connection reached its deadline")
}

// requireCause requires end's cause to be want, reported within the longest
// a correct cause waits on an ended session.
func requireCause(t *testing.T, end *guestEnd, want string) {
	t.Helper()

	got := make(chan string, 1)
	go func() { got <- end.cause() }()
	select {
	case cause := <-got:
		require.Equal(t, want, cause)
	case <-time.After(guestEndSettle + 2*time.Second):
		t.Fatal("cause did not report within its bound")
	}
}
