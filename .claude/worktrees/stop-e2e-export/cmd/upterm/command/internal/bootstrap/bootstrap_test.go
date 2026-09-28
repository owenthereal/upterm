package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// pair returns the two ends of an in-process channel with the semantics the
// real one has: closing one end gives the other io.EOF.
func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func print(text string) *api.Startup {
	return &api.Startup{Msg: &api.Startup_Print{Print: &api.Print{Text: text}}}
}

func TestConnFramesMessagesBothWays(t *testing.T) {
	a, b := pair(t)
	ca, cb := NewConn(a), NewConn(b)
	go func() { _ = ca.Send(print("one")); _ = ca.Send(print("two")) }()
	m, err := cb.Recv()
	require.NoError(t, err)
	require.Equal(t, "one", m.GetPrint().GetText())
	m, err = cb.Recv()
	require.NoError(t, err)
	require.Equal(t, "two", m.GetPrint().GetText())

	require.NoError(t, ca.Close())
	_, err = cb.Recv()
	require.ErrorIs(t, err, io.EOF, "a closed peer is EOF, which is what the child watches for")
}

// TestExchangeInOrder runs the whole protocol between a real Child and a real
// Parent: every child message reaches the right handler, every reply comes
// back, and the parent returns on started.
func TestExchangeInOrder(t *testing.T) {
	a, b := pair(t)
	gone := make(chan struct{})
	child := NewChild(a, func() { close(gone) })
	parent := NewParent(b, strings.NewReader("yes\n"), io.Discard, func(prompt string) ([]byte, error) {
		return []byte("s3cret"), nil
	})

	var events []string
	var gotHostKeys []string
	childErr := make(chan error, 1)
	go func() {
		childErr <- func() error {
			child.Print("hello ")
			pass, err := child.ReadSecret("Enter passphrase: ")
			if err != nil {
				return err
			}
			if string(pass) != "s3cret" {
				return errors.New("wrong passphrase: " + string(pass))
			}
			r := bufio.NewReader(child.Reader())
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if string(line) != "yes\n" {
				return errors.New("wrong line: " + string(line))
			}
			if err := child.Claimed(&api.Claimed{Name: "n", LaunchId: "l", Pid: 7}); err != nil {
				return err
			}
			dec, err := child.SessionCreated(&api.GetSessionResponse{SessionId: "sid"})
			if err != nil {
				return err
			}
			if dec != api.Accept_ACCEPTED {
				return errors.New("expected accepted")
			}
			if err := child.Listening("/tmp/a.sock", []string{"ssh-ed25519 AAAA"}); err != nil {
				return err
			}
			child.Disarm()
			return child.Started("sid", "ready")
		}()
	}()

	out, err := parent.Run(context.Background(), Handlers{
		Claimed: func(c *api.Claimed) { events = append(events, "claimed:"+c.Name) },
		SessionCreated: func(s *api.GetSessionResponse) api.Accept_Decision {
			events = append(events, "created:"+s.SessionId)
			return api.Accept_ACCEPTED
		},
		Listening: func(l *api.Listening) {
			events = append(events, "listening:"+l.AttachSocket)
			gotHostKeys = l.HostKeys
		},
	})
	require.NoError(t, err)
	require.NoError(t, <-childErr)
	require.NotNil(t, out.Started)
	require.Equal(t, "sid", out.Started.SessionId)
	require.Equal(t, "ready", out.Started.Status,
		"the status the child published travels to the parent, which prints it")
	require.Equal(t, []string{"claimed:n", "created:sid", "listening:/tmp/a.sock"}, events)
	require.Equal(t, []string{"ssh-ed25519 AAAA"}, gotHostKeys, "the attach client (Task 5) pins exactly these host keys")

	// The parent is done and closes; the child has disarmed, so its watcher
	// says nothing.
	require.NoError(t, parent.Close())
	select {
	case <-gone:
		t.Fatal("a parent leaving after the command started is not abandonment")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestReadFailures(t *testing.T) {
	t.Run("a secret with no terminal", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, nil)
		parent := NewParent(b, strings.NewReader(""), io.Discard, nil)
		go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
		_, err := child.ReadSecret("Enter passphrase: ")
		var na *NoAnswerError
		require.ErrorAs(t, err, &na)
		require.Contains(t, na.Reason, "no terminal")
	})
	t.Run("a line from an exhausted stdin", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, nil)
		parent := NewParent(b, strings.NewReader(""), io.Discard, nil)
		go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
		_, err := bufio.NewReader(child.Reader()).ReadString('\n')
		var na *NoAnswerError
		require.ErrorAs(t, err, &na, "the host-key callback wraps this error in its own message, so it must carry the reason")
		require.Contains(t, na.Reason, "EOF")
	})
	t.Run("a line takes only one line", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, nil)
		stdin := strings.NewReader("yes\nrest")
		parent := NewParent(b, stdin, io.Discard, nil)
		go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
		line, err := bufio.NewReader(child.Reader()).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "yes\n", line)
		require.Equal(t, 4, stdin.Len(), "bytes past the newline belong to whoever reads stdin next")
	})
	t.Run("a line with no stdin", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, nil)
		parent := NewParent(b, nil, io.Discard, nil)
		go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
		_, err := bufio.NewReader(child.Reader()).ReadString('\n')
		var na *NoAnswerError
		require.ErrorAs(t, err, &na)
		require.Contains(t, na.Reason, "no input")
	})
	t.Run("a secret whose readSecret errors", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, nil)
		parent := NewParent(b, nil, io.Discard, func(prompt string) ([]byte, error) {
			return nil, errors.New("boom")
		})
		go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
		_, err := child.ReadSecret("Enter passphrase: ")
		var na *NoAnswerError
		require.ErrorAs(t, err, &na)
		require.Contains(t, na.Reason, "boom")
	})
}

func TestPromptsReachStderr(t *testing.T) {
	a, b := pair(t)
	child := NewChild(a, nil)
	var stderr strings.Builder
	parent := NewParent(b, strings.NewReader("no\n"), &stderr, nil)
	go func() { _, _ = parent.Run(context.Background(), Handlers{}) }()
	child.Print("The authenticity of host cannot be established.\n")
	_, _ = bufio.NewReader(child.Reader()).ReadString('\n')
	require.Eventually(t, func() bool { return strings.Contains(stderr.String(), "authenticity") }, time.Second, 10*time.Millisecond)
}

func TestSessionCreatedDecisions(t *testing.T) {
	for _, dec := range []api.Accept_Decision{api.Accept_ACCEPTED, api.Accept_DECLINED, api.Accept_INTERRUPTED} {
		t.Run(dec.String(), func(t *testing.T) {
			a, b := pair(t)
			child := NewChild(a, nil)
			parent := NewParent(b, nil, io.Discard, nil)
			go func() {
				_, _ = parent.Run(context.Background(), Handlers{SessionCreated: func(*api.GetSessionResponse) api.Accept_Decision { return dec }})
			}()
			got, err := child.SessionCreated(&api.GetSessionResponse{})
			require.NoError(t, err)
			require.Equal(t, dec, got)
		})
	}
}

// TestParentRunEndsOnContextCancelledDuringAccept pins that an operator
// hitting Ctrl-C at the accept prompt is reported as a cancellation, not as
// a daemon that vanished. In production this is context.AfterFunc's job:
// ctx ending calls Parent.Close, racing the in-flight accept Send. That race
// is real but not useful in a test — the accept message can win it (the
// child's read loop is already parked waiting, so a Send landing before the
// async Close goroutine even gets scheduled is common, not rare: 30 runs of
// this test with only `cancel()` and no explicit Close showed both outcomes,
// close to evenly split). So the handler closes the connection itself right
// after cancelling, making deterministic exactly the ordering AfterFunc is
// meant to produce (cancel, then closed, then the pending Send fails) without
// depending on which goroutine the scheduler runs first. What's under test —
// Run returning context.Canceled rather than ErrDaemonGone once ctx is
// already done — is the same either way.
func TestParentRunEndsOnContextCancelledDuringAccept(t *testing.T) {
	a, b := pair(t)
	child := NewChild(a, nil)
	parent := NewParent(b, nil, io.Discard, nil)
	ctx, cancel := context.WithCancel(context.Background())

	childErr := make(chan error, 1)
	go func() {
		_, err := child.SessionCreated(&api.GetSessionResponse{})
		childErr <- err
	}()

	_, err := parent.Run(ctx, Handlers{
		SessionCreated: func(*api.GetSessionResponse) api.Accept_Decision {
			cancel()
			_ = parent.Close()
			return api.Accept_INTERRUPTED
		},
	})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, <-childErr, ErrParentGone)
}

func TestFailedReachesTheParent(t *testing.T) {
	a, b := pair(t)
	child := NewChild(a, nil)
	parent := NewParent(b, nil, io.Discard, nil)
	go child.Failed("name in use: x", true, false)
	out, err := parent.Run(context.Background(), Handlers{})
	require.NoError(t, err)
	require.NotNil(t, out.Failed)
	require.True(t, out.Failed.NameInUse)
	require.Equal(t, "name in use: x", out.Failed.Error)
}

func TestFailedAfterStartedIsNotSent(t *testing.T) {
	a, b := pair(t)
	child := NewChild(a, nil)
	child.Disarm()
	cb := NewConn(b)
	// Reads run on their own goroutine: net.Pipe is unbuffered, so a send
	// completes only when the peer reads.
	got := make(chan *api.Startup, 2)
	errs := make(chan error, 1)
	go func() {
		for {
			m, err := cb.Recv()
			if err != nil {
				errs <- err
				return
			}
			got <- m
		}
	}()
	require.NoError(t, child.Started("sid", "ready"))
	m := <-got
	require.NotNil(t, m.GetStarted())
	child.Failed("late", false, false)
	require.NoError(t, child.Close())
	require.ErrorIs(t, <-errs, io.EOF)
	select {
	case m := <-got:
		t.Fatalf("after started the parent must never be told the session failed; got %T", m.Msg)
	default:
	}
}

// TestParentGoneIsAbandonmentOnlyWhileArmed pins the arm/disarm contract: a
// parent that leaves before the command starts abandons the session; one
// that leaves after does not.
func TestParentGoneIsAbandonmentOnlyWhileArmed(t *testing.T) {
	t.Run("armed", func(t *testing.T) {
		a, b := pair(t)
		gone := make(chan struct{})
		child := NewChild(a, func() { close(gone) })
		defer func() { _ = child.Close() }()
		require.NoError(t, b.Close())
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
			t.Fatal("the child never noticed the parent leaving")
		}
	})
	t.Run("a waiter is released too", func(t *testing.T) {
		a, b := pair(t)
		child := NewChild(a, func() {})
		defer func() { _ = child.Close() }()
		go func() { time.Sleep(50 * time.Millisecond); _ = b.Close() }()
		_, err := child.SessionCreated(&api.GetSessionResponse{})
		require.ErrorIs(t, err, ErrParentGone)
	})
	t.Run("disarmed", func(t *testing.T) {
		a, b := pair(t)
		gone := make(chan struct{})
		child := NewChild(a, func() { close(gone) })
		defer func() { _ = child.Close() }()
		child.Disarm()
		require.NoError(t, b.Close())
		select {
		case <-gone:
			t.Fatal("a parent leaving after disarm is expected and means nothing")
		case <-time.After(200 * time.Millisecond):
		}
	})
}

func TestParentRunEndsOnDaemonEOF(t *testing.T) {
	a, b := pair(t)
	parent := NewParent(b, nil, io.Discard, nil)
	require.NoError(t, a.Close())
	_, err := parent.Run(context.Background(), Handlers{})
	require.ErrorIs(t, err, ErrDaemonGone)
}

func TestParentRunEndsOnContext(t *testing.T) {
	_, b := pair(t)
	parent := NewParent(b, nil, io.Discard, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := parent.Run(ctx, Handlers{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
