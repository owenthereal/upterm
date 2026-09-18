package command

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/ci"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a CI system that reports nothing, so the lifecycle can be
// tested without a runner.
type fakeProvider struct {
	actor     string
	workspace string
	sessions  []ci.Session
	err       error
}

func (f *fakeProvider) Name() string      { return "Fake CI" }
func (f *fakeProvider) Actor() string     { return f.actor }
func (f *fakeProvider) Workspace() string { return f.workspace }
func (f *fakeProvider) Ready(s ci.Session) error {
	f.sessions = append(f.sessions, s)
	return f.err
}

func TestSplitUserList(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"comma separated, as pflag already split it", []string{"alice", "bob"}, []string{"alice", "bob"}},
		{"a YAML block scalar arrives as one element", []string{"alice\nbob\ncarol"}, []string{"alice", "bob", "carol"}},
		{"spaces and commas mixed", []string{"alice, bob  carol"}, []string{"alice", "bob", "carol"}},
		{"blank entries are not usernames", []string{"", "  ", "alice"}, []string{"alice"}},
		{"nothing", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, splitUserList(tc.in))
		})
	}
}

func TestCIAuthorizedUsers(t *testing.T) {
	t.Run("the actor is authorized through the code host", func(t *testing.T) {
		got, err := ciAuthorizedUsers(&fakeProvider{actor: "alice"}, true, nil)
		require.NoError(t, err)
		require.Equal(t, []string{"github:alice"}, got)
	})

	t.Run("named users are authorized", func(t *testing.T) {
		got, err := ciAuthorizedUsers(nil, false, []string{"alice,bob"})
		require.NoError(t, err)
		require.Equal(t, []string{"github:alice", "github:bob"}, got)
	})

	t.Run("the actor is not authorized twice", func(t *testing.T) {
		got, err := ciAuthorizedUsers(&fakeProvider{actor: "alice"}, true, []string{"alice", "bob"})
		require.NoError(t, err)
		require.Equal(t, []string{"github:alice", "github:bob"}, got)
	})

	// The two below are the fail-closed cases. Resolving to an empty list
	// would start a session that accepts anyone holding a connect string that
	// is sitting in a build log.
	t.Run("an actor nobody named is an error", func(t *testing.T) {
		_, err := ciAuthorizedUsers(&fakeProvider{actor: ""}, true, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did not say who triggered this job")
	})

	t.Run("no CI system at all is an error", func(t *testing.T) {
		_, err := ciAuthorizedUsers(nil, true, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no CI system detected")
	})

	t.Run("no restriction requested resolves to none", func(t *testing.T) {
		got, err := ciAuthorizedUsers(nil, false, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestCIContinueFiles(t *testing.T) {
	t.Run("an explicit path is the only one watched", func(t *testing.T) {
		require.Equal(t,
			[]string{"/tmp/done"},
			ciContinueFiles("/tmp/done", &fakeProvider{workspace: "/w"}),
		)
	})

	t.Run("the workspace copy is for a runner with no writable root", func(t *testing.T) {
		require.Equal(t,
			[]string{ciRootContinueFile, filepath.Join("/w", "continue")},
			ciContinueFiles("", &fakeProvider{workspace: "/w"}),
		)
	})

	t.Run("no provider, no workspace", func(t *testing.T) {
		require.Equal(t, []string{ciRootContinueFile}, ciContinueFiles("", nil))
	})
}

// newTestCISession returns a session whose watcher can be driven quickly, and
// the context it watches.
func newTestCISession(t *testing.T, waitTimeout time.Duration, continueFiles []string) (*ciSession, context.Context, *bytes.Buffer) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var out bytes.Buffer
	return &ciSession{
		logger:        slog.New(slog.DiscardHandler),
		out:           &out,
		waitTimeout:   waitTimeout,
		continueFiles: continueFiles,
		pollInterval:  5 * time.Millisecond,
		cancel:        cancel,
	}, ctx, &out
}

// waitForStop waits for the watcher to end the session, and returns the reason.
func waitForStop(t *testing.T, ctx context.Context, s *ciSession) string {
	t.Helper()

	select {
	case <-ctx.Done():
		return s.stopReason()
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher never ended the session")
		return ""
	}
}

func TestCISessionEndsWhenTheContinueFileAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "continue")
	s, ctx, _ := newTestCISession(t, 0, []string{path})

	go s.watch(ctx)

	require.NoError(t, os.WriteFile(path, nil, 0644))

	require.Contains(t, waitForStop(t, ctx, s), "was created")
}

func TestCISessionEndsWhenNobodyConnects(t *testing.T) {
	s, ctx, _ := newTestCISession(t, 10*time.Millisecond, nil)

	go s.watch(ctx)

	require.Contains(t, waitForStop(t, ctx, s), "no client connected within")
}

func TestCISessionStaysUpOnceAClientConnects(t *testing.T) {
	s, ctx, out := newTestCISession(t, 10*time.Millisecond, nil)

	// The question --wait-timeout asks is whether anyone ever arrived. A guest
	// who joins, fixes the build and disconnects has answered it; re-arming
	// the deadline behind them would shut down a session they are about to
	// reconnect to.
	s.clientJoined(&api.Client{Addr: "10.0.0.1:2222", Version: "test"})
	s.clientLeft(&api.Client{Addr: "10.0.0.1:2222", Version: "test"})

	go s.watch(ctx)

	select {
	case <-ctx.Done():
		t.Fatalf("the session was ended after a client had connected: %s", s.stopReason())
	case <-time.After(100 * time.Millisecond):
	}

	require.Contains(t, out.String(), "client joined")
	require.Contains(t, out.String(), "client left")
}

func TestCISessionWaitsForeverOnZeroTimeout(t *testing.T) {
	s, ctx, _ := newTestCISession(t, 0, nil)

	go s.watch(ctx)

	select {
	case <-ctx.Done():
		t.Fatalf("a session with no wait timeout was ended: %s", s.stopReason())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCISessionStopIsRecordedOnce(t *testing.T) {
	s, ctx, _ := newTestCISession(t, 0, nil)

	require.Empty(t, s.stopReason(), "a session nobody stopped has no reason")

	s.stop("first")
	s.stop("second")

	<-ctx.Done()
	// The reason ciRunE reports has to be the one that actually ended the
	// session, not whichever watcher noticed the cancellation afterwards.
	require.Equal(t, "first", s.stopReason())
}

func TestCISessionIgnoresAnUnstatableContinueFile(t *testing.T) {
	// A path under a file rather than a directory: Stat fails with something
	// other than "not there". Ending the session on that would make a
	// misconfigured --continue-file look like a guest's decision.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0644))

	s, ctx, _ := newTestCISession(t, 0, []string{filepath.Join(notADir, "continue")})

	go s.watch(ctx)

	select {
	case <-ctx.Done():
		t.Fatalf("the session was ended by a path that cannot be read: %s", s.stopReason())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCIReportFailureDoesNotEndTheSession(t *testing.T) {
	// report runs from SessionCreatedCallback, where an error abandons the
	// session. A session that is up and joinable is worth more than the
	// annotation that failed to describe it.
	p := &fakeProvider{err: fmt.Errorf("the runner's file is not writable")}
	s, _, out := newTestCISession(t, 0, nil)
	s.provider = p

	s.report(&api.GetSessionResponse{
		SessionId: "session-id",
		Host:      "ssh://uptermd.upterm.dev:22",
		SshUser:   "TOKEN",
	}, "bash-1a2b")

	require.Contains(t, out.String(), "could not report the session to Fake CI")
	require.Equal(t, []ci.Session{{SSHCommand: "ssh TOKEN@uptermd.upterm.dev", Name: "bash-1a2b"}}, p.sessions)
}
