package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A daemon that binds at once and ends after `lives`.
func stubDaemon(lives time.Duration) daemonFunc {
	return func(ctx context.Context, onAttachSocket func(string)) error {
		onAttachSocket("/tmp/attach.sock")
		select {
		case <-time.After(lives):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Delivery into SSH is not delivery into stdout: with an immediate-exit
// command the daemon returns while the client is still copying the tail
// into the terminal (and still in raw mode). upterm host must not return —
// and so exit — until the client is done.
func TestRunLocalSessionWaitsForTheClientToDrain(t *testing.T) {
	var clientFinished atomic.Bool
	client := func(ctx context.Context, socket string) (attach.Result, error) {
		require.Equal(t, "/tmp/attach.sock", socket)
		time.Sleep(300 * time.Millisecond) // a slow terminal taking the tail
		clientFinished.Store(true)
		return attach.Result{Reason: attach.Exited}, nil
	}
	err := runLocalSession(context.Background(), "s", io.Discard, discardLogger(), stubDaemon(20*time.Millisecond), client)
	require.NoError(t, err)
	require.True(t, clientFinished.Load(), "returned before the local terminal had finished")
}

// A stdout nobody drains must not hold the exit: the wait is bounded, the
// client is cancelled when the bound expires — and then still waited for,
// because it restores the terminal on its way out and returning before that
// is exiting before that.
func TestRunLocalSessionCancelsThenWaitsForTheTerminalToBeRestored(t *testing.T) {
	orig := localClientDrainTimeout
	localClientDrainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { localClientDrainTimeout = orig })

	var restored atomic.Bool
	client := func(ctx context.Context, socket string) (attach.Result, error) {
		<-ctx.Done()
		time.Sleep(200 * time.Millisecond) // the drain bound and the restore on the way out
		restored.Store(true)
		return attach.Result{Reason: attach.Detached}, nil
	}
	start := time.Now()
	err := runLocalSession(context.Background(), "s", io.Discard, discardLogger(), stubDaemon(20*time.Millisecond), client)
	require.NoError(t, err)
	require.True(t, restored.Load(), "returned before the client had restored the terminal")
	require.Less(t, time.Since(start), 2*time.Second)
}

// The daemon's outcome is the session's, whatever the client reported, and a
// daemon that fails before binding the socket reports that failure.
func TestRunLocalSessionReturnsTheDaemonsError(t *testing.T) {
	boom := errors.New("relay unreachable")
	daemon := func(ctx context.Context, onAttachSocket func(string)) error { return boom }
	// Recorded rather than failed here: this runs on runLocalSession's own
	// goroutine, and t.Fatal from one that is not the test's stops only that
	// goroutine — a tripped guard would hang to the package timeout instead
	// of failing.
	var attached atomic.Bool
	client := func(ctx context.Context, socket string) (attach.Result, error) {
		attached.Store(true)
		return attach.Result{}, nil
	}
	err := runLocalSession(context.Background(), "s", io.Discard, discardLogger(), daemon, client)
	require.ErrorIs(t, err, boom)
	require.False(t, attached.Load(), "the client must not be attached when the daemon never bound its socket")
}

// A client the daemon disconnected does not end anything: the message names
// the log and the way back, and the session runs on.
func TestRunLocalSessionReportsADisconnectAndKeepsRunning(t *testing.T) {
	var stderr bytes.Buffer
	client := func(ctx context.Context, socket string) (attach.Result, error) {
		return attach.Result{Reason: attach.Disconnected}, nil
	}
	err := runLocalSession(context.Background(), "build-shell", &stderr, discardLogger(), stubDaemon(300*time.Millisecond), client)
	require.NoError(t, err)
	require.Contains(t, stderr.String(), "upterm attach build-shell")
	require.Contains(t, stderr.String(), "the session continues")
}

// blockingHandler is a slog.Handler whose Handle never returns until
// released: a log file on a wedged filesystem, or a console that stopped.
type blockingHandler struct{ release chan struct{} }

func (h blockingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (h blockingHandler) Handle(context.Context, slog.Record) error { <-h.release; return nil }
func (h blockingHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h blockingHandler) WithGroup(string) slog.Handler             { return h }

// blockingWriter never completes a write until released: stderr on a
// stopped terminal.
type blockingWriter struct{ release chan struct{} }

func (w blockingWriter) Write(p []byte) (int, error) { <-w.release; return len(p), nil }

// The diagnostics on the way out must not defeat the bound on the way out:
// a blocked logger after an attach failure, and a blocked stderr for the
// disconnect message, both on the same stopped terminal.
func TestRunLocalSessionBoundsItsDiagnostics(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	logger := slog.New(blockingHandler{release})
	stderr := blockingWriter{release}

	t.Run("attach failure with a blocked logger", func(t *testing.T) {
		var stderr bytes.Buffer
		client := func(ctx context.Context, socket string) (attach.Result, error) {
			return attach.Result{}, errors.New("refused")
		}
		start := time.Now()
		require.NoError(t, runLocalSession(context.Background(), "s", &stderr, logger, stubDaemon(50*time.Millisecond), client))
		require.Less(t, time.Since(start), 3*time.Second)
		require.Contains(t, stderr.String(), "could not attach")
		require.NotContains(t, stderr.String(), "was disconnected")
	})
	t.Run("disconnect report on a blocked stderr", func(t *testing.T) {
		client := func(ctx context.Context, socket string) (attach.Result, error) {
			return attach.Result{Reason: attach.Disconnected}, nil
		}
		start := time.Now()
		require.NoError(t, runLocalSession(context.Background(), "s", stderr, logger, stubDaemon(50*time.Millisecond), client))
		require.Less(t, time.Since(start), 3*time.Second)
	})
}

func TestLocalDisconnectMessageNamesTheLogAndTheReattachCommand(t *testing.T) {
	msg := localDisconnectMessage("build-shell", "/var/log/upterm.log", attach.Result{Reason: attach.Disconnected})
	require.Contains(t, msg, "build-shell")
	require.Contains(t, msg, "/var/log/upterm.log")
	require.Contains(t, msg, "upterm attach build-shell")
	require.Empty(t, localDisconnectMessage("x", "/l", attach.Result{Reason: attach.Exited}), "nothing to say when the command simply ended")
	require.Empty(t, localDisconnectMessage("x", "/l", attach.Result{Reason: attach.Detached}), "nothing to say when the terminal went away")
}

// Both notification sites, because filtering only the join would announce a
// departure with no arrival: the host's own terminal leaving, and — once
// upterm attach exists — every detach of it.
//
// The callbacks are driven, not only the predicate, so that a site which
// stopped asking is caught. Swapping notify is also what keeps this from
// raising real desktop notifications on whoever is running the suite.
func TestClientNotificationSkipsHostClients(t *testing.T) {
	require.False(t, shouldNotifyClient(&api.Client{Kind: api.Client_HOST}))
	require.True(t, shouldNotifyClient(&api.Client{Kind: api.Client_GUEST}))

	var sent []string
	orig := notify
	notify = func(title, message string, appIcon any) error {
		sent = append(sent, title)
		return nil
	}
	t.Cleanup(func() { notify = orig })

	clientJoinedCallback(&api.Client{Kind: api.Client_HOST})
	clientLeftCallback(&api.Client{Kind: api.Client_HOST})
	require.Empty(t, sent, "the host's own terminal is not a client to announce")

	clientJoinedCallback(&api.Client{Kind: api.Client_GUEST})
	clientLeftCallback(&api.Client{Kind: api.Client_GUEST})
	require.Equal(t, []string{"Upterm Client Joined", "Upterm Client Left"}, sent,
		"a guest is still announced both ways")
}
