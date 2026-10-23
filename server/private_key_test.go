package server

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStartReportsPrivateKeyReadError(t *testing.T) {
	t.Setenv("PRIVATE_KEY", TestPrivateKeyContent)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "valid-key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0o600))

	for _, tt := range []struct {
		name string
		path string
	}{
		{name: "missing file", path: filepath.Join(dir, "missing-key")},
		{name: "directory", path: dir},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := Start(context.Background(), Opt{
				SSHAddr:     "127.0.0.1:0",
				Network:     "mem",
				PrivateKeys: []string{keyPath, tt.path},
			}, slog.New(slog.DiscardHandler))

			require.ErrorContains(t, err, tt.path)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			require.Equal(t, tt.path, pathErr.Path)
		})
	}
}
