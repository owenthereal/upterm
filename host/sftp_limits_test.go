package host

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostRejectsInvalidSFTPWriteLimitsBeforeStartup(t *testing.T) {
	require.ErrorContains(t, (&Host{SFTPWriteLimits: &SFTPWriteLimits{}}).Run(t.Context()), "requires SFTPRoot")
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	h := &Host{SFTPRoot: root, SFTPWriteLimits: &SFTPWriteLimits{Files: map[string]int64{"../outside": 1}, TotalBytes: 1}}
	require.ErrorContains(t, h.Run(t.Context()), "SFTPWriteLimits")
	require.NoError(t, h.WaitSFTP(t.Context()))
	_, err = root.Stat(".")
	require.NoError(t, err, "invalid policy must not take ownership of the root")
}
