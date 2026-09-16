//go:build !windows

package command

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gssh "charm.land/ssh"
	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// testDoor is a charm ssh server on a unix socket whose handler is the
// test's. It accepts any public key, as the host door does.
//
// A copy of attach/client_test.go's fakeDoor: Go test helpers do not cross
// packages, and what is under test here — the signal contract of `upterm
// attach` — needs the same kind of door the attach client's own tests use.
type testDoor struct {
	socket string
}

func serveTestDoor(t *testing.T, handler func(gssh.Session)) *testDoor {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	// A short root, for the reason setupSessionRoots uses one: a socket path
	// is bounded at 103 bytes and macOS hands out long temp directories.
	dir, err := os.MkdirTemp("/tmp", "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)

	srv := &gssh.Server{
		HostSigners:      []gssh.Signer{signer},
		Handler:          handler,
		PublicKeyHandler: func(gssh.Context, gssh.PublicKey) bool { return true },
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &testDoor{socket: socket}
}

// SIGTERM to upterm attach is a detach: the terminal comes back the way it
// was found, and the exit status is 0. Nothing in this process installs the
// host's signal actor, so the attach command has to do this itself.
func TestAttachDetachesOnSIGTERMAndRestoresTheTerminal(t *testing.T) {
	// attached is a cheap first barrier: it confirms the door's handler
	// started at all, with its own failure message below if the session was
	// never established. It does not prove the client is past Shell():
	// charm replies to the shell request before it starts the handler
	// goroutine (charm.land/ssh@v0.4.3/session.go, around line 272:
	// sess.handled = true; req.Reply(true, nil); go func() {…}), so the
	// handler can run — and even finish writing its marker — before the
	// client has read that reply and returned from Shell(). macOS happened
	// to order it the other way; Linux does not. The barrier the kill
	// actually waits on is the READY marker read back from ptmx below.
	attached := make(chan struct{})
	sessionStarted := sync.OnceFunc(func() { close(attached) })
	door := serveTestDoor(t, func(s gssh.Session) {
		sessionStarted()
		// The client's output copy starts only once Shell() has returned
		// (attach/client.go, after line 215), and its stdout in this test is
		// tty, whose master ptmx the test holds: writing this marker before
		// the discard copy puts it on ptmx only once Shell() has returned
		// and the terminal is in raw mode.
		_, _ = io.WriteString(s, "READY")
		_, _ = io.Copy(io.Discard, s)
	})

	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	fd := int(tty.Fd())
	original, err := term.GetState(fd)
	require.NoError(t, err)

	ctx, cancel := notifyDetachSignals(context.Background())
	defer cancel()
	lt := localTerminal{stdin: tty, rawMode: true, pty: &attach.Pty{Term: "xterm", Size: termsize.Default}}
	done := make(chan attach.Result, 1)
	go func() {
		// owned is injected as always-true: a pty pair is nobody's
		// foreground, and what is under test is the signal, not ownership.
		res, err := attachLocalTerminalWith(ctx, door.socket, lt, '~', tty, tty, func(*os.File) bool { return true }, discardLogger())
		require.NoError(t, err)
		done <- res
	}()
	select {
	case <-attached:
	case <-time.After(5 * time.Second):
		t.Fatal("the door never saw the attachment")
	}

	// Wait for the marker on ptmx: that is the proof the client is past
	// Shell() and the terminal is in raw mode. Sending SIGTERM any earlier
	// races the client's own teardown against its read of the shell
	// request's reply, a race the signal's context cancellation can win.
	// Through a context reader, not bare: the test holds the slave open, so
	// a master read waiting for a marker that never arrives would wait past
	// the package's own timeout rather than fail here, and a pty master
	// takes no deadline of its own on macOS.
	markerCtx, markerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer markerCancel()
	marker := uio.NewContextReader(markerCtx, ptmx)
	var seen strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(seen.String(), "READY") {
		n, err := marker.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			t.Fatalf("no READY on the pty master: %v (saw %q)", err, seen.String())
		}
	}

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))

	select {
	case res := <-done:
		require.Equal(t, attach.Result{Reason: attach.Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not detach")
	}
	got, err := term.GetState(fd)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(original, got), "the terminal must be restored on the way out")
}
