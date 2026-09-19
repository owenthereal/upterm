//go:build !windows

package ftests

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// registryLockFile is sessiondir's own lock name, repeated here because it is
// unexported there and this test has to take the lock from outside.
const registryLockFile = ".registry.lock"

// Test_Host_StartupClaimIsBounded pins that nothing can park a host at startup
// for as long as it likes.
//
// Claim waits on the sessions registry, and the CLI hands Run a
// context.Background(): a holder that is stopped rather than slow never gives
// the lock back, so an unbounded wait here is `upterm host` hanging before it
// prints anything, on a machine where `upterm session list` still answers.
//
// Unix-only: holding the lock from outside sessiondir means calling flock
// directly.
func Test_Host_StartupClaimIsBounded(t *testing.T) {
	// Far shorter than the assertion's budget below, so the gap between the
	// two is what proves the claim gave up rather than got lucky. Restored so
	// no later test inherits it.
	origClaimTimeout := host.ClaimTimeout
	host.ClaimTimeout = 200 * time.Millisecond
	t.Cleanup(func() { host.ClaimTimeout = origClaimTimeout })

	run := newOutcomeRun(t, []string{"sh", "-c", "exit 0"})

	// The first of the two locks Claim takes, held for the whole test by
	// something that will never answer — which is what a stopped host is.
	sessRoot := sessiondir.SessionsRoot(utils.UptermRuntimeDir())
	require.NoError(t, os.MkdirAll(sessRoot, 0700))
	lock, err := os.OpenFile(filepath.Join(sessRoot, registryLockFile), os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	})
	// Non-blocking, so a lock this test somehow cannot take is a failure here
	// rather than a hang in the setup of a test about hangs.
	require.NoError(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	select {
	case err := <-done:
		require.ErrorContains(t, err, "registry lock",
			"a host that gave up waiting must name what it was waiting for")
	case <-time.After(2 * time.Second):
		t.Fatal("Run waited on the registry lock instead of its own deadline")
	}

	// The claim never completed, so this run owns nothing and may have said
	// nothing: a record here would be an outcome published for a name the run
	// never held.
	_, readErr := sessiondir.ReadRecord(run.stateRoot, run.name)
	require.True(t, os.IsNotExist(readErr),
		"a claim that timed out must leave no record behind, got %v", readErr)
}
