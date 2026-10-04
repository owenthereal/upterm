//go:build !windows

package host

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// registryLockFile is sessiondir's own lock name, repeated here because it is
// unexported there and this test has to take the lock from outside.
const registryLockFile = ".registry.lock"

// holdSessionsRegistry takes the lock Claim waits on first, as a host that is
// stopped rather than slow would hold it, and returns the func that gives it
// back. It is also given back when the test ends.
func holdSessionsRegistry(t *testing.T) (release func()) {
	t.Helper()
	runtimeDir, err := utils.CreateUptermRuntimeDir()
	require.NoError(t, err)
	sessRoot := sessiondir.SessionsRoot(runtimeDir)
	require.NoError(t, os.MkdirAll(sessRoot, 0700))
	lock, err := os.OpenFile(filepath.Join(sessRoot, registryLockFile), os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err)
	// Non-blocking, so a lock this test somehow cannot take fails here rather
	// than hanging the setup.
	require.NoError(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
		})
	}
	t.Cleanup(release)

	// The file locked is the registry sessiondir waits on, not one that merely
	// looks like it: a Reap that cannot take the lock says so.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.ErrorContains(t, sessiondir.Reap(ctx, runtimeDir), "registry lock",
		"the lock held is not the one sessiondir waits on")
	return release
}

// Status is "" only when Run isn't running: a caller polling for that to learn
// Run has ended must not mistake the name claim for the end. So it is
// "starting" while Run waits to claim the name, as well as once it has.
//
// Unix-only: holding the registry from outside sessiondir means calling flock
// directly.
func TestStatusIsStartingFromTheNameClaimUntilRunReturns(t *testing.T) {
	f := newJoinTimeoutHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.Empty(t, f.h.Status(), "before Run")
	release := holdSessionsRegistry(t)

	var claimed string
	claimedSignal := make(chan struct{})
	f.h.SessionClaimedCallback = func(*sessiondir.Dir) {
		claimed = f.h.Status()
		close(claimedSignal)
		cancel()
	}
	done := make(chan error, 1)
	go func() { done <- f.h.Run(ctx) }()

	// The claim can't return while the registry is held, so a status read
	// before release is a status read during the claim.
	require.Eventually(t, func() bool { return f.h.Status() != "" }, 5*time.Second, 5*time.Millisecond,
		"Run reports no status while it waits for the name")
	require.Equal(t, sessiondir.StatusStarting, f.h.Status(), "while the claim waits")
	select {
	case err := <-done:
		t.Fatalf("Run returned while the registry was held: %v", err)
	default:
	}
	select {
	case <-claimedSignal:
		t.Fatal("the name was claimed while the registry was held")
	default:
	}

	release()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the claim")
	}
	require.Equal(t, sessiondir.StatusStarting, claimed, "once the name is claimed")
	require.Empty(t, f.h.Status(), "after Run")
}
