//go:build !windows

package command

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// A delegated session's banner whose record can't be read in time, behind a
// registry another process holds for as long as the banner waits, is the
// fallback, and the session starts: a slow registry costs the banner its
// delegation, never the start.
func TestBannerOfAnUnreadRecordIsTheFallback(t *testing.T) {
	setupSessionRoots(t)
	prevAccept, prevTimeout := flagAccept, bannerReadTimeout
	t.Cleanup(func() { flagAccept, bannerReadTimeout = prevAccept, prevTimeout })
	flagAccept, bannerReadTimeout = true, 50*time.Millisecond
	d := testDelegation("Example Authority", "relay.example.com:22")
	heldDelegated(t, "work", d, sessiondir.StatusReady, nil)

	results := sessiondir.ResultsRoot(utils.UptermStateDir())
	lock, err := os.OpenFile(filepath.Join(results, ".registry.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lock.Close() })
	require.NoError(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))

	banner := captureStdout(t, func() {
		require.NoError(t, displaySession(context.Background(), delegatedAnswer("work"), "work"))
	})
	require.Equal(t, fallbackBanner, banner)
}
