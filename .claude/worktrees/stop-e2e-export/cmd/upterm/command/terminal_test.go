package command

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()
	never := func(*os.File) bool { return false }
	always := func(*os.File) bool { return true }

	t.Run("no terminal at all is a pipe viewer", func(t *testing.T) {
		lt := classifyTerminal(r, w, never, "xterm")
		require.Nil(t, lt.pty)
		require.Nil(t, lt.stdin)
		require.False(t, lt.rawMode)
		require.Nil(t, lt.sizeOf)
	})

	t.Run("an owned stdin forwards input in raw mode even when stdout is a pipe", func(t *testing.T) {
		// `upterm host | tee log` from a terminal: keystrokes go to the
		// command, the output goes to the pipe, and nothing is a pty.
		lt := classifyTerminal(r, w, always, "xterm")
		require.Nil(t, lt.pty)
		require.NotNil(t, lt.stdin)
		require.True(t, lt.rawMode)
		require.Nil(t, lt.sizeOf)
	})
}
