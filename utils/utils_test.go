package utils

import (
	"net/url"
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

func TestCleanURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			url:  "ws://test.com:4433",
			want: "ws://test.com:4433",
		},
		{
			url:  "ws://test.com:80",
			want: "ws://test.com",
		},
		{
			url:  "wss://test.com",
			want: "wss://test.com",
		},
		{
			url:  "wss://test.com:443",
			want: "wss://test.com",
		},
		{
			url:  "http://test.com:80/foo?bar=baz",
			want: "http://test.com/foo?bar=baz",
		},
		{
			url:  "https://test.com:443",
			want: "https://test.com",
		},
		{
			url:  "https://test.com:8080",
			want: "https://test.com:8080",
		},
		{
			url:  "WS://test.com:80",
			want: "ws://test.com",
		},
		{
			url:  "ws://user:pass@test.com:80",
			want: "ws://user:pass@test.com",
		},
		{
			url:  "ws://[::1]:80",
			want: "ws://[::1]",
		},
		{
			url:  "ws://[::1]:8080",
			want: "ws://[::1]:8080",
		},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err, "failed to parse url")
			got := CleanURL(u)
			assert.Equal(t, tt.want, got)
		})
	}
}
