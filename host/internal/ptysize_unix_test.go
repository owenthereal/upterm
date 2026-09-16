//go:build !windows

package internal

import (
	"os/exec"
	"testing"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

func Test_StartPty_AppliesInitialSize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	f, ok := p.(*pty)
	require.True(t, ok)

	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_PinnedIgnoresResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, true)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	// A pinned pty reports success and changes nothing: a caller that cannot
	// resize is not an error, it is the promise --pty-size makes.
	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_UnpinnedHonoursResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 24, rows)
	require.Equal(t, 80, cols)
}
