package internal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// hostView gives a test the host door to hand a Server, and a way to wait for
// a marker on what a local client attached to it receives.
//
// The host's own view of a session is a client of that door now, so this is
// where a test that used to read the host's stdout reads from. The client is
// dialled on its own goroutine because the listener has to exist before
// ServeWithContext is called: a connection to a bound socket is queued until
// something accepts it, so the dial can run before the server does.
func hostView(t *testing.T) (net.Listener, func(marker string)) {
	t.Helper()

	ln, err := net.Listen("unix", filepath.Join(shortTempDir(t), "a.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	lines := make(chan string, 64)
	failed := make(chan error, 1)
	go func() {
		out, err := dialHostView(ln.Addr().String())
		if err != nil {
			failed <- err
			return
		}
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	awaitLine := func(marker string) {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case err := <-failed:
				t.Fatalf("could not attach a local client: %v", err)
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("the local client's output ended before %q", marker)
				}
				if strings.Contains(line, marker) {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for %q", marker)
			}
		}
	}

	return ln, awaitLine
}

// dialHostView attaches an output-only client to the host door, the way
// attach.Client does: a throwaway key, and the socket itself as the trust
// boundary. The returned reader holds the channel, which holds the
// connection, so nothing here has to be kept alive by the caller.
func dialHostView(socket string) (io.Reader, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	raw, err := net.DialTimeout("unix", socket, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, socket, &ssh.ClientConfig{
		User:            "host",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   upterm.AttachSSHClientVersion,
		Timeout:         20 * time.Second,
	})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	sess, err := ssh.NewClient(conn, chans, reqs).NewSession()
	if err != nil {
		return nil, err
	}
	// A pipe nobody writes to, so the session's input stays open: with
	// Session.Stdin nil, x/crypto sends EOF at once.
	if _, err := sess.StdinPipe(); err != nil {
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		return nil, err
	}
	return out, nil
}

func Test_Server_TunnelLossDoesNotKillCommand(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	hostLn, awaitLine := hostView(t)

	stopped := make(chan error, 1)
	s := &Server{
		// READY is an observed event, not a sleep: the tunnel must be closed
		// while the command is provably running.
		Command:           []string{"sh", "-c", "echo READY; sleep 2; echo SURVIVED"},
		HostKey:           testSigners(t)[0],
		EventEmitter:      emitter.New(1),
		KeepAliveDuration: time.Minute,
		Logger:            testLogger(t),
		PtySize:           termsize.Default,
		Term:              "xterm-256color",
		// The local client is what the markers are read through, so the
		// command must not run before it is attached.
		AwaitInitialClient: true,
		OnGuestServerStopped: func(err error) {
			select {
			case stopped <- err:
			default:
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ServeWithContext(ctx, ln, hostLn) }()

	awaitLine("READY")
	require.NoError(t, ln.Close())

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("guest server stop was not reported")
	}

	awaitLine("SURVIVED")

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server did not finish")
	}
}

// The other half of that guarantee. The callback means the guests were lost, so
// an ordinary command-led exit must not fire it.
//
// Our own interrupt calls server.Shutdown, and Shutdown is what makes Serve
// return: the actor sees a stop on every exit, not only on a lost tunnel.
// Reporting that one would put a "reverse tunnel stopped serving guests"
// warning on every clean exit, and write disconnected over a record that is
// merely ending.
func Test_Server_CommandExitDoesNotReportTunnelLoss(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	hostLn, awaitLine := hostView(t)

	stopped := make(chan error, 1)
	s := &Server{
		// No sleep and no close: nothing touches the listener, so the only
		// thing that ends this session is the command exiting.
		Command:            []string{"sh", "-c", "echo READY; exit 0"},
		HostKey:            testSigners(t)[0],
		EventEmitter:       emitter.New(1),
		KeepAliveDuration:  time.Minute,
		Logger:             testLogger(t),
		PtySize:            termsize.Default,
		Term:               "xterm-256color",
		AwaitInitialClient: true,
		OnGuestServerStopped: func(err error) {
			select {
			case stopped <- err:
			default:
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ServeWithContext(ctx, ln, hostLn) }()

	awaitLine("READY")

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server did not finish")
	}

	// After the server has returned, so there is nothing left to report: the
	// callback runs on the guest actor's goroutine, which run.Group drains
	// before Run returns.
	select {
	case err := <-stopped:
		t.Fatalf("a clean exit was reported as a lost tunnel: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
}
