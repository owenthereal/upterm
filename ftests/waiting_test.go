package ftests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	// waitingText and waitingExpiredText stand in for what an authority shows
	// a key it is waiting to see approved, and once that wait has expired.
	waitingText        = "Approve this SSH key\nOpen the authority's page and enter:\n\n    Q7MN-4K6P\n\nThis code expires at %s.\nNo terminal access is granted on this connection.\n"
	waitingExpiredText = "This code has expired. Ask for another.\n"
	waitingApproved    = "This key was approved. Connect again.\n"
	waitingOfferID     = "88888888-8888-4888-8888-888888888888"
	waitingAttemptID   = "99999999-9999-4999-8999-999999999999"
)

// waitingUser is the claimed user a key waiting to be approved connects as.
const waitingUser = claimPrefix + "add-ABC234"

// waitingApproval is the client key's approval as a fake authority holds it:
// an attempt that outlives every wait on it, until it is approved or it
// expires.
type waitingApproval struct {
	expires time.Time
	// waits receives each wait's context as it starts, and left each one's
	// error as it ends without a decision.
	waits chan context.Context
	left  chan error

	mu       sync.Mutex
	approved bool
	// changed is closed when the attempt is approved.
	changed chan struct{}
}

func newWaitingApproval(expires time.Time) *waitingApproval {
	return &waitingApproval{expires: expires, waits: make(chan context.Context, 4), left: make(chan error, 4), changed: make(chan struct{})}
}

func (w *waitingApproval) text() string {
	return fmt.Sprintf(waitingText, w.expires.UTC().Format("2006-01-02 15:04:05 UTC"))
}

// admission is the screen the client key is shown while it waits.
func (w *waitingApproval) admission(t *testing.T) server.Admission {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	return server.Admission{Verdict: server.VerdictWaiting, Message: []byte(w.text()), Waiting: &server.WaitingScreen{
		OfferID: waitingOfferID, AttemptID: waitingAttemptID, Address: waitingUser, KeyFingerprint: utils.FingerprintSHA256(key),
		ExpiredMessage: []byte(waitingExpiredText), ApprovedMessage: []byte(waitingApproved), Expires: w.expires, Await: w.await,
	}}
}

func (w *waitingApproval) await(ctx context.Context) (server.Target, error) {
	w.waits <- ctx
	w.mu.Lock()
	changed := w.changed
	w.mu.Unlock()
	select {
	case <-changed:
		return server.Target{}, nil
	case <-ctx.Done():
		w.left <- ctx.Err()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return server.Target{}, &server.WaitingEnded{Text: []byte(waitingExpiredText)}
		}
		return server.Target{}, ctx.Err()
	}
}

// approve approves the attempt, and reports whether it was still there to
// approve.
func (w *waitingApproval) approve() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.approved || !time.Now().Before(w.expires) {
		return false
	}
	w.approved = true
	close(w.changed)
	return true
}

func (w *waitingApproval) waiting(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-w.waits:
		return ctx
	case <-time.After(outcomeTimeout):
		t.Fatal("nothing waited on the approval")
		return nil
	}
}

func (w *waitingApproval) ended(t *testing.T) error {
	t.Helper()
	select {
	case err := <-w.left:
		return err
	case <-time.After(outcomeTimeout):
		t.Fatal("a wait on the approval went on")
		return nil
	}
}

// guestShell is a guest's shell, with a terminal, over the relay.
type guestShell struct {
	session *ssh.Session
	out     *guestOutput
}

func startGuestShell(t *testing.T, guest *ssh.Client) *guestShell {
	t.Helper()
	sess, err := guest.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	_, err = sess.StdinPipe()
	require.NoError(t, err)
	out := &guestOutput{}
	sess.Stdout = out
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	return &guestShell{session: sess, out: out}
}

func (s *guestShell) requireShows(t *testing.T, text, why string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(s.out.String(), text) }, outcomeTimeout, 10*time.Millisecond, why)
}

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// A key the authority doesn't know yet is shown how to have it approved, and
// waits, over a relay with an authority and a real delegated host. Not
// approved in time, it is shown that the code expired and exits 1. Approved
// after it has disconnected, its next connection is admitted. Approved while
// it waits, it is shown the authority's approved text and exits 0, and must
// connect again. It reaches the command only once approved, on a connection
// of its own.
func TestDelegatedWaitingScreen(t *testing.T) {
	r := newDelegatedRun(t, printing("DELEGATED-TICK"))
	r.authority.ClaimPrefix(claimPrefix)
	r.start(t)
	r.awaitReady(t)
	r.requireStarted(t)
	target := r.target(t)

	t.Run("expired", func(t *testing.T) {
		w := newWaitingApproval(time.Now().Add(2 * time.Second))
		r.authority.ScriptAdmit(w.admission(t))
		guest, err := r.dialGuestAs(t, waitingUser)
		require.NoError(t, err, "a key waiting to be approved was refused")
		shell := startGuestShell(t, guest)
		shell.requireShows(t, crlf(w.text()), "the guest was not shown how to have its key approved")
		w.waiting(t)
		var exit *ssh.ExitError
		require.ErrorAs(t, shell.session.Wait(), &exit)
		require.Equal(t, 1, exit.ExitStatus())
		require.Equal(t, crlf(w.text()+waitingExpiredText), shell.out.String())
		require.ErrorIs(t, w.ended(t), context.DeadlineExceeded)
		require.False(t, w.approve(), "an expired attempt was approved")
	})

	t.Run("approved after disconnecting", func(t *testing.T) {
		w := newWaitingApproval(time.Now().Add(10 * time.Minute))
		r.authority.ScriptAdmit(w.admission(t))
		guest, err := r.dialGuestAs(t, waitingUser)
		require.NoError(t, err)
		shell := startGuestShell(t, guest)
		shell.requireShows(t, "Q7MN-4K6P", "the guest was not shown how to have its key approved")
		w.waiting(t)
		require.NoError(t, guest.Close())
		require.ErrorIs(t, w.ended(t), context.Canceled, "disconnecting did not end the wait")

		require.True(t, w.approve(), "the attempt did not outlive the connection that waited on it")
		r.authority.ScriptAdmit(allow(target))
		next, err := r.dialGuestAs(t, claimPrefix+"work")
		require.NoError(t, err, "the approved key's next connection was refused")
		shell = startGuestShell(t, next)
		shell.requireShows(t, "DELEGATED-TICK", "the approved key never reached the command")
		require.NotContains(t, shell.out.String(), "Q7MN-4K6P")
		require.Empty(t, w.waits, "the approved key waited again")
	})

	t.Run("approved while waiting", func(t *testing.T) {
		w := newWaitingApproval(time.Now().Add(10 * time.Minute))
		r.authority.ScriptAdmit(w.admission(t))
		guest, err := r.dialGuestAs(t, waitingUser)
		require.NoError(t, err)
		shell := startGuestShell(t, guest)
		shell.requireShows(t, crlf(w.text()), "the guest was not shown how to have its key approved")
		w.waiting(t)
		require.NotContains(t, shell.out.String(), "DELEGATED-TICK", "a waiting guest saw the command")

		require.True(t, w.approve())
		require.NoError(t, shell.session.Wait())
		require.Equal(t, crlf(w.text()+waitingApproved), shell.out.String())
		require.NotContains(t, shell.out.String(), "DELEGATED-TICK")

		// The host and its command go on once the guest leaves.
		require.NoError(t, guest.Close())
		select {
		case err := <-r.done:
			t.Fatalf("the guest leaving ended the host: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
	})
}
