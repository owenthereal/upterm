package tty

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOwnedIsFalseForNilAndForAPipe(t *testing.T) {
	require.False(t, Owned(nil))

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()
	require.False(t, Owned(r), "a pipe is nobody's terminal")
}

func TestSizeFailsForAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = r.Close(); _ = w.Close() }()
	_, err = Size(r)
	require.Error(t, err)
}
