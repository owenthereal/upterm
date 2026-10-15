package logging

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Discard is the fallback for a log file that can't be opened: the log goes
// nowhere, not to stderr as New with no output would send it.
func TestDiscardWritesNothing(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })

	logger, err := New(Discard())
	require.NoError(t, err)
	logger.Error("nobody reads this")
	require.NoError(t, logger.Close())

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, string(out))
}
