//go:build !windows

package command

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// A registry lock held by a process that is stopped rather than slow would
// hang the shell on <TAB>. The lock is let go after six seconds, so a
// completion with no bound of its own answers late, and the test fails on the
// time instead of hanging.
func TestSessionNamesGiveUpOnAHeldRegistry(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")

	results := sessiondir.ResultsRoot(utils.UptermStateDir())
	require.NoError(t, os.MkdirAll(results, 0o700))
	lock, err := os.OpenFile(filepath.Join(results, ".registry.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	require.NoError(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	release := time.AfterFunc(6*time.Second, func() { _ = lock.Close() })
	t.Cleanup(func() { release.Stop(); _ = lock.Close() })

	start := time.Now()
	got, directive := complete(t, "attach", "")
	require.Less(t, time.Since(start), 4*time.Second)
	require.Empty(t, got)
	require.Equal(t, noFileComp, directive)
}
