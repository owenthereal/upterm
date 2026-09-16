package internal

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

// hostOutput gives a test the Stdout to hand a Server, and a way to wait for a
// marker to appear on it.
//
// The server writes host output to Stdout, so that is where the test must
// read from. A pipe, not a recording writer: Stdout is an *os.File.
func hostOutput(t *testing.T) (*os.File, func(marker string)) {
	t.Helper()

	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = pr.Close() })
	t.Cleanup(func() { _ = pw.Close() })

	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(pr)
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
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("stdout closed before %q", marker)
				}
				if strings.Contains(line, marker) {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for %q", marker)
			}
		}
	}

	return pw, awaitLine
}

func devNullStdin(t *testing.T) *os.File {
	t.Helper()

	stdin, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close() })

	return stdin
}

func Test_Server_TunnelLossDoesNotKillCommand(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	pw, awaitLine := hostOutput(t)

	stopped := make(chan error, 1)
	s := &Server{
		// READY is an observed event, not a sleep: the tunnel must be closed
		// while the command is provably running.
		Command:           []string{"sh", "-c", "echo READY; sleep 2; echo SURVIVED"},
		Signers:           testSigners(t),
		EventEmitter:      emitter.New(1),
		KeepAliveDuration: time.Minute,
		Stdin:             devNullStdin(t),
		Stdout:            pw,
		Logger:            testLogger(t),
		PtySize:           termsize.Default,
		Term:              "xterm-256color",
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
	go func() { done <- s.ServeWithContext(ctx, ln, nil) }()

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
		// Nothing writes to the pipe once the server has returned, so closing
		// the write end lets the scanner goroutine see EOF and exit.
		_ = pw.Close()
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

	pw, awaitLine := hostOutput(t)

	stopped := make(chan error, 1)
	s := &Server{
		// No sleep and no close: nothing touches the listener, so the only
		// thing that ends this session is the command exiting.
		Command:           []string{"sh", "-c", "echo READY; exit 0"},
		Signers:           testSigners(t),
		EventEmitter:      emitter.New(1),
		KeepAliveDuration: time.Minute,
		Stdin:             devNullStdin(t),
		Stdout:            pw,
		Logger:            testLogger(t),
		PtySize:           termsize.Default,
		Term:              "xterm-256color",
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
	go func() { done <- s.ServeWithContext(ctx, ln, nil) }()

	awaitLine("READY")

	select {
	case <-done:
		_ = pw.Close()
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
