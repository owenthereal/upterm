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

func Test_Server_TunnelLossDoesNotKillCommand(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// The server writes host output to Stdout, so that is where the test must
	// read from. A pipe, not a recording writer: Stdout is an *os.File.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = pr.Close() }()

	stdin, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()

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

	stopped := make(chan error, 1)
	s := &Server{
		// READY is an observed event, not a sleep: the tunnel must be closed
		// while the command is provably running.
		Command:           []string{"sh", "-c", "echo READY; sleep 2; echo SURVIVED"},
		Signers:           testSigners(t),
		EventEmitter:      emitter.New(1),
		KeepAliveDuration: time.Minute,
		Stdin:             stdin,
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
	go func() { done <- s.ServeWithContext(ctx, ln) }()

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
