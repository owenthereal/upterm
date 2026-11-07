package host

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootedHostWaitContract(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	h := &Host{SFTPRoot: root, LoginCommand: []string{"a"}, ForceCommand: []string{"b"}}
	require.Error(t, h.WaitSFTP(t.Context()), "pre-Run wait cannot certify a future server")
	require.Error(t, h.Run(t.Context()), "invalid startup must fail before serving")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- h.WaitSFTP(t.Context()) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	_, err = root.Stat(".")
	require.NoError(t, err, "host closed the caller's root")
	require.ErrorContains(t, h.Run(t.Context()), "cannot be reused")
	require.NoError(t, (&Host{}).WaitSFTP(context.Background()))
}
