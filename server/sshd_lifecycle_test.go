package server

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestSSHSessionWorkSealAndHandoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newSSHSessionWork()
		parent, ok := owner.enter()
		require.True(t, ok)
		owner.seal()
		_, ok = owner.enter()
		require.False(t, ok, "admitted a new producer after sealing")
		child := parent.child()
		parent.done()
		synctest.Wait() // The live child's handoff has settled without completing it.
		require.False(t, ownershipDone(owner.drained), "drained before admitted child returned")
		child.done()
		require.NoError(t, owner.wait(context.Background()))
		_, ok = owner.enter()
		require.False(t, ok, "reopened terminal admission")
	})
}

// Direct private callers retain a root until their fixture's normal cleanup
// has ended registrations and released holds. Sealing then cancels keepers and
// joins their descendants before earlier store cleanup runs.
func newTestSSHWork(t *testing.T, rescue ...func()) *sshWorkRef {
	t.Helper()
	owner := newSSHSessionWork()
	work, _ := owner.enter()
	t.Cleanup(func() {
		// Earlier-acquired holds must open before this later cleanup drains.
		for _, release := range rescue {
			release()
		}
		work.done()
		owner.seal()
		ctx, cancel := context.WithTimeout(context.Background(), serverShutDownDeadline)
		defer cancel()
		if err := owner.wait(ctx); err != nil {
			t.Errorf("direct SSH fixture drain: %v", err)
		}
	})
	return work
}

// testSSHWork admits a direct test invocation under its fixture's owner.
// Its cleanup runs before the fixture root seals and drains that owner.
func testSSHWork(t *testing.T, owner *sshSessionWork) *sshWorkRef {
	t.Helper()
	work, ok := owner.enter()
	require.True(t, ok, "direct caller started after fixture shutdown")
	t.Cleanup(work.done)
	return work
}
