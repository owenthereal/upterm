package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRawSessionOutput(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		Handler: func(sess gssh.Session) {
			_, _ = io.Copy(sess, sess)
		},
		ChannelHandlers: map[string]gssh.ChannelHandler{"session": rawSessionHandler},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		require.ErrorIs(t, <-done, gssh.ErrServerClosed)
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{
		User: "guest", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()

	var inputs []io.WriteCloser
	var outputs []io.Reader
	// Keep both sessions open on one connection. A raw channel stored on the
	// connection context would send the first session's output to the second.
	for range 2 {
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer func() { _ = sess.Close() }()
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		input, err := sess.StdinPipe()
		require.NoError(t, err)
		output, err := sess.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Shell())
		inputs = append(inputs, input)
		outputs = append(outputs, output)
	}

	// Reading each write before sending the next forces CR and LF to cross
	// separate SSH writes, where stateless newline normalization also corrupts
	// an otherwise ordinary CRLF. No native PTY is needed, so this covers Windows.
	for _, chunk := range []string{"HELLO   ", "\n", "HELLO", "\r", "\n", "\r\r\n", "\x1b[12;9Hpane\nnext", "\x00\t☃"} {
		for i := range inputs {
			_, err := io.WriteString(inputs[i], chunk)
			require.NoError(t, err)
			got := make([]byte, len(chunk))
			_, err = io.ReadFull(outputs[i], got)
			require.NoError(t, err)
			require.Equal(t, chunk, string(got))
		}
	}
}

func TestRawSessionAdmissionKeepsSelectedTracker(t *testing.T) {
	for _, kind := range []clientKind{kindGuest, kindHost} {
		t.Run(map[clientKind]string{kindGuest: "guest", kindHost: "host"}[kind], func(t *testing.T) {
			original, replacement := &guestHandlers{}, &guestHandlers{}
			h := &sessionHandler{kind: kind, sharedGuests: original, hostHandlers: original, forceCommands: replacement}
			underlying := &fakeGuestSession{}
			raw := &rawSession{Session: underlying}
			require.True(t, h.admitGuest(raw, "shell"))
			original.mu.Lock()
			_, keyedByUnderlying := original.admitted[underlying]
			original.mu.Unlock()
			require.True(t, keyedByUnderlying, "admission must preserve Charm's underlying session key")
			h.forceCommand = []string{"changed-after-admission"}
			h.hostHandlers = replacement
			finish := h.takeAdmission(raw)
			require.NotNil(t, finish, "handler must take the tracker selected at admission")
			finish()
			require.True(t, original.wait(time.Second))
			require.Empty(t, original.admitted)
		})
	}
}

// A denied request may be followed by a PTY and a different request on the
// same channel; the initial no-PTY observation must not prevent consuming it.
func TestRawSessionWindowsAfterRejectedRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		underlying := &fakeGuestSession{}
		raw := &rawSession{Session: underlying}
		raw.startWindowChanges()
		underlying.winCh = make(chan gssh.Window, 256)
		raw.startWindowChanges()
		_, changes, _ := raw.Pty()
		require.NotNil(t, changes)
		for i := range 256 {
			underlying.winCh <- gssh.Window{Width: 90 + i, Height: 30 + i}
		}
		synctest.Wait()
		pty, _, _ := raw.Pty()
		require.Equal(t, gssh.Window{Width: 345, Height: 285}, pty.Window)
		require.Equal(t, gssh.Window{Width: 345, Height: 285}, <-changes)
		select {
		case <-changes:
			t.Fatal("mailbox retained an obsolete window")
		default:
		}
		close(underlying.winCh)
		synctest.Wait()
		_, ok := <-changes
		require.False(t, ok, "mailbox must close with its channel")
	})
}

func TestRawSessionOperationContext(t *testing.T) {
	for _, source := range []string{"host", "transport", "channel", "cleanup", "already closed channel", "already closed transport"} {
		t.Run(source, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, stopHost := context.WithCancel(context.Background())
				defer stopHost()
				transport, stopTransport := context.WithCancel(context.Background())
				defer stopTransport()
				closed := make(chan struct{})
				sess := &rawSession{Session: &fakeGuestSession{ctx: &operationTransport{operationCtx: transport}}, closed: closed}
				if source == "already closed channel" {
					close(closed)
				}
				if source == "already closed transport" {
					stopTransport()
				}
				ctx, cleanup := sessionOperationContext(parent, sess)
				defer cleanup()
				if source == "already closed channel" || source == "already closed transport" {
					require.ErrorIs(t, ctx.Err(), context.Canceled)
				} else {
					require.NoError(t, ctx.Err())
					switch source {
					case "host":
						stopHost()
					case "transport":
						stopTransport()
					case "channel":
						close(closed)
					case "cleanup":
						cleanup()
					}
				}
				synctest.Wait()
				require.ErrorIs(t, ctx.Err(), context.Canceled)
			})
		})
	}
}

type operationTransport struct {
	gssh.Context
	operationCtx context.Context
}

func (c *operationTransport) Deadline() (time.Time, bool) { return c.operationCtx.Deadline() }
func (c *operationTransport) Done() <-chan struct{}       { return c.operationCtx.Done() }
func (c *operationTransport) Err() error                  { return c.operationCtx.Err() }
func (c *operationTransport) Value(key any) any           { return c.operationCtx.Value(key) }
