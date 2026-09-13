package internal

import (
	"os"
	"testing"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

func Test_ResolvePtySize(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()

	require.Equal(t, termsize.Size{Cols: 132, Rows: 43},
		ResolvePtySize(nil, termsize.Size{Cols: 132, Rows: 43}))
	require.Equal(t, termsize.Default, ResolvePtySize(r, termsize.Size{}))
	require.Equal(t, termsize.Default, ResolvePtySize(nil, termsize.Size{}))
	// A half-specified size is not a size.
	require.Equal(t, termsize.Default, ResolvePtySize(nil, termsize.Size{Cols: 132}))
}
