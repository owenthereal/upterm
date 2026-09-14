package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShortenHomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err, "failed to get user home dir")

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "home directory",
			path: home,
			want: "~",
		},
		{
			name: "path under home",
			path: filepath.Join(home, "Documents/file.txt"),
			want: "~/Documents/file.txt",
		},
		{
			name: "path outside home unchanged",
			path: "/etc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "relative path unchanged",
			path: "relative/path",
			want: "relative/path",
		},
		{
			name: "empty path unchanged",
			path: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShortenHomePath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestXDGDirWithFallback(t *testing.T) {
	// Get the actual home directory for fallback tests
	home, err := os.UserHomeDir()
	require.NoError(t, err, "failed to get user home dir")

	xdgPath := t.TempDir()

	tests := []struct {
		name    string
		envVar  string
		envMap  map[string]string
		xdgPath string
		want    string
	}{
		{
			name:    "respects explicitly set env var",
			envVar:  "XDG_RUNTIME_DIR",
			envMap:  map[string]string{"XDG_RUNTIME_DIR": filepath.Join("/tmp", "custom-runtime")},
			xdgPath: filepath.Join("/run", "user", "1000"), // This would be the default
			want:    filepath.Join("/tmp", "custom-runtime", "upterm"),
		},
		{
			name:    "uses xdg path when it exists",
			envVar:  "XDG_RUNTIME_DIR",
			envMap:  map[string]string{},
			xdgPath: xdgPath,
			want:    filepath.Join(xdgPath, "upterm"),
		},
		{
			name:    "falls back to HOME when xdg path doesn't exist",
			envVar:  "XDG_RUNTIME_DIR",
			envMap:  map[string]string{},
			xdgPath: filepath.Join("/nonexistent", "path"),
			want:    filepath.Join(home, ".upterm"),
		},
		{
			name:    "falls back to HOME for all directory types",
			envVar:  "XDG_STATE_HOME",
			envMap:  map[string]string{},
			xdgPath: filepath.Join("/nonexistent", "path"),
			want:    filepath.Join(home, ".upterm"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock env getter - no need for os.Setenv!
			getenv := func(key string) string {
				return tt.envMap[key]
			}

			got := xdgDirWithFallbackEnv(tt.envVar, tt.xdgPath, getenv)
			assert.Equal(t, tt.want, got)
		})
	}
}
