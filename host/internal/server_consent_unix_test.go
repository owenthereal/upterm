//go:build !windows

package internal

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// permissionServer uses the harness's bounded SSH transport setup without
// starting a command: permission waiting itself is the admitted handler.
func permissionServer(t *testing.T, srv *gssh.Server) *ssh.Client {
	t.Helper()
	srv.HostSigners = []gssh.Signer{testSigner(t)}
	srv.ChannelHandlers = map[string]gssh.ChannelHandler{"session": rawSessionHandler}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); require.ErrorIs(t, <-done, gssh.ErrServerClosed) })
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{User: "guest", HostKeyCallback: ssh.FixedHostKey(srv.HostSigners[0].PublicKey())})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSessionPermissionCancellation(t *testing.T) {
	for _, kind := range []string{"shell", "empty exec", "exec", "sftp"} {
		t.Run(kind, func(t *testing.T) { testPermissionCancellation(t, kind, false) })
	}
}

func TestSessionPermissionWindowFlood(t *testing.T) {
	for _, kind := range []string{"shell", "empty exec", "exec", "sftp"} {
		t.Run(kind, func(t *testing.T) { testPermissionCancellation(t, kind, true) })
	}
}

func testPermissionCancellation(t *testing.T, kind string, flood bool) {
	t.Helper()
	h := &sessionHandler{kind: kindGuest, sharedGuests: &guestHandlers{}, forceCommands: &guestHandlers{}}
	var callbackSession gssh.Session
	var callbackClosed bool
	var effects atomic.Int32
	started := make(chan context.Context, 1)
	inputEnded := make(chan struct{})
	finished := make(chan struct{})
	latePermission := make(chan struct{})
	t.Cleanup(func() { close(latePermission) })
	handler := func(sess gssh.Session) {
		if finish := h.takeAdmission(sess); finish != nil {
			defer finish()
		}
		if sess.RawCommand() == "probe" {
			_, _ = io.Copy(sess, sess)
			return
		}
		defer close(finished)
		go func() { _, _ = io.Copy(io.Discard, sess); close(inputEnded) }()
		ctx, cancel := sessionOperationContext(t.Context(), sess)
		defer cancel()
		started <- ctx
		<-latePermission
		if ctx.Err() == nil {
			effects.Add(1)
		}
	}
	sftp := h.startAdmitted(handler)
	h.subsystems = map[string]gssh.SubsystemHandler{"sftp": sftp}
	srv := &gssh.Server{Handler: handler, SubsystemHandlers: h.subsystems,
		SessionRequestCallback: func(sess gssh.Session, requestType string) bool {
			if sess.RawCommand() != "probe" {
				callbackSession = sess
				callbackClosed = channelClosed(sess) != nil
			}
			return h.admitGuest(sess, requestType)
		},
	}
	client := permissionServer(t, srv)
	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	if flood {
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	}
	input, err := sess.StdinPipe()
	require.NoError(t, err)
	switch kind {
	case "shell":
		err = sess.Shell()
	case "empty exec":
		err = sess.Start("")
	case "exec":
		err = sess.Start("printf requested")
	case "sftp":
		err = sess.RequestSubsystem("sftp")
	}
	require.NoError(t, err)
	var operationCtx context.Context
	select {
	case operationCtx = <-started:
	case <-time.After(harnessTimeout):
		t.Fatal("handler did not start")
	}
	require.True(t, callbackClosed, "request callback must receive channel-owned close observation")
	require.IsType(t, &rawSession{}, callbackSession)
	wantType := "exec"
	if kind == "shell" {
		wantType = "shell"
	}
	if kind == "sftp" {
		wantType = "subsystem"
	}
	require.Equal(t, wantType, sessionRequestType(callbackSession))
	require.WithinDuration(t, time.Now(), sessionRequestReceivedAt(callbackSession), time.Second)
	require.NoError(t, input.Close())
	select {
	case <-inputEnded:
	case <-time.After(harnessTimeout):
		t.Fatal("server did not observe stdin EOF")
	}
	require.NoError(t, operationCtx.Err(), "stdin EOF must not cancel a permission request")
	if flood {
		pty, _, ok := callbackSession.Pty()
		require.True(t, ok)
		require.Equal(t, 80, pty.Window.Width)
		require.Equal(t, 24, pty.Window.Height)
		// The ACK is behind every window-change in the channel request loop.
		// More than Charm's one-slot buffer must progress while consent waits.
		for i := range 256 {
			require.NoError(t, sess.WindowChange(30+i, 90+i))
		}
		ok, err := sess.SendRequest("window-change", true, ssh.Marshal(struct{ Width, Height, PixelWidth, PixelHeight uint32 }{777, 333, 0, 0}))
		require.NoError(t, err)
		require.True(t, ok)
		require.Eventually(t, func() bool {
			pty, _, _ := callbackSession.Pty()
			return pty.Window.Width == 777 && pty.Window.Height == 333
		}, time.Second, time.Millisecond)
	}
	probe, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })
	probeInput, err := probe.StdinPipe()
	require.NoError(t, err)
	probeOutput, err := probe.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, probe.Start("probe"))
	siblingChannelProbe := func() {
		_, err := io.WriteString(probeInput, "alive")
		require.NoError(t, err)
		got := make([]byte, 5)
		_, err = io.ReadFull(probeOutput, got)
		require.NoError(t, err)
		require.Equal(t, "alive", string(got))
	}
	siblingChannelProbe()
	require.NoError(t, sess.Close())
	require.Eventually(t, func() bool { return operationCtx.Err() != nil }, time.Second, time.Millisecond)
	siblingChannelProbe()
	require.NoError(t, probeInput.Close())
	require.NoError(t, probe.Wait())
	// Deliver a late answer only after cancellation and proving the sibling lives.
	latePermission <- struct{}{}
	select {
	case <-finished:
	case <-time.After(harnessTimeout):
		t.Fatal("permission handler did not finish")
	}
	require.Zero(t, effects.Load())
	require.True(t, h.sharedGuests.wait(time.Second))
}

// Hold callbacks after registration to put shutdown exactly between
// admission and handler startup, including for startup-only SFTP ownership.
func TestSessionAdmissionShutdownRace(t *testing.T) {
	for _, kind := range []string{"shell", "empty exec", "exec", "sftp"} {
		t.Run(kind, func(t *testing.T) {
			h := &sessionHandler{kind: kindGuest, sharedGuests: &guestHandlers{}, forceCommands: &guestHandlers{}}
			var admitted, completed atomic.Int32
			registered := make(chan struct{}, 32)
			release := make(chan struct{})
			var releaseOnce, waitOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			waiting := make(chan struct{})
			h.sharedGuests.onWait = func() { waitOnce.Do(func() { close(waiting) }) }
			handle := func(sess gssh.Session) {
				if finish := h.takeAdmission(sess); finish != nil {
					defer finish()
				}
				completed.Add(1)
			}
			h.subsystems = map[string]gssh.SubsystemHandler{"sftp": h.startAdmitted(handle)}
			srv := &gssh.Server{Handler: handle, SubsystemHandlers: h.subsystems, SessionRequestCallback: func(sess gssh.Session, typ string) bool {
				ok := h.admitGuest(sess, typ)
				if ok {
					admitted.Add(1)
					registered <- struct{}{}
					<-release
				}
				return ok
			}}
			client := permissionServer(t, srv)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for range 32 {
				sess, err := client.NewSession()
				require.NoError(t, err)
				wg.Go(func() {
					defer func() { _ = sess.Close() }()
					<-start
					switch kind {
					case "shell":
						_ = sess.Shell()
					case "empty exec":
						_ = sess.Start("")
					case "exec":
						_ = sess.Start("true")
					case "sftp":
						_ = sess.RequestSubsystem("sftp")
					}
				})
			}
			close(start)
			for range 16 {
				select {
				case <-registered:
				case <-time.After(harnessTimeout):
					t.Fatal("concurrent requests were not admitted")
				}
			}
			waited := make(chan bool, 1)
			go func() { waited <- h.sharedGuests.wait(harnessTimeout) }()
			select {
			case <-waiting:
			case <-time.After(harnessTimeout):
				t.Fatal("shutdown did not wait for admitted requests")
			}
			releaseOnce.Do(func() { close(release) })
			wg.Wait()
			require.True(t, <-waited)
			require.Eventually(t, func() bool { return admitted.Load() == completed.Load() }, time.Second, time.Millisecond)
			require.GreaterOrEqual(t, admitted.Load(), int32(16))
			require.Equal(t, admitted.Load(), completed.Load())
		})
	}
}
