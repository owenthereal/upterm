package internal

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSFTPSession_resolvePath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	session := &SFTPSession{
		readOnly: false,
	}

	// Test cases for path resolution:
	// - Tilde paths (~ or ~/path) are expanded to home directory
	// - Absolute paths (starting with /) are used as-is
	// - Relative paths are passed through (WithStartDirectory handles them at protocol level)
	tests := []struct {
		name     string
		reqPath  string
		wantPath string
	}{
		// Absolute paths - used as-is
		{
			name:     "filesystem root",
			reqPath:  "/",
			wantPath: "/",
		},
		{
			name:     "absolute path",
			reqPath:  "/tmp/file.txt",
			wantPath: "/tmp/file.txt",
		},
		{
			name:     "absolute nested path",
			reqPath:  "/var/log/syslog",
			wantPath: "/var/log/syslog",
		},
		{
			name:     "absolute path with double dots",
			reqPath:  "/tmp/../etc/passwd",
			wantPath: "/etc/passwd",
		},
		// Tilde expansion (OpenSSH may send literal ~)
		{
			name:     "tilde only expands to home",
			reqPath:  "~",
			wantPath: home,
		},
		{
			name:     "tilde with path expands to home subdir",
			reqPath:  "~/Documents",
			wantPath: filepath.Join(home, "Documents"),
		},
		{
			name:     "tilde with nested path",
			reqPath:  "~/Documents/projects/file.txt",
			wantPath: filepath.Join(home, "Documents/projects/file.txt"),
		},
		{
			name:     "tilde with trailing slash",
			reqPath:  "~/upterm/",
			wantPath: filepath.Join(home, "upterm"),
		},
		// Relative paths - passed through as-is (library handles with WithStartDirectory)
		{
			name:     "relative file passed through",
			reqPath:  "file.txt",
			wantPath: "file.txt",
		},
		{
			name:     "relative directory",
			reqPath:  "Downloads",
			wantPath: "Downloads",
		},
		{
			name:     "relative nested path passed through",
			reqPath:  "Documents/file.txt",
			wantPath: "Documents/file.txt",
		},
		{
			name:     "dot passed through",
			reqPath:  ".",
			wantPath: ".",
		},
		{
			name:     "dot-slash prefix cleaned",
			reqPath:  "./Downloads",
			wantPath: "Downloads",
		},
		{
			name:     "dot-slash nested cleaned",
			reqPath:  "./Documents/file.txt",
			wantPath: "Documents/file.txt",
		},
		{
			name:     "parent directory relative",
			reqPath:  "../Downloads",
			wantPath: "../Downloads",
		},
		{
			name:     "parent then child",
			reqPath:  "../other/file.txt",
			wantPath: "../other/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := session.resolvePath(tt.reqPath)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, gotPath)
		})
	}
}

func TestListerat(t *testing.T) {
	tempDir := t.TempDir()

	// Create some test files
	files := []string{"a.txt", "b.txt", "c.txt"}
	for _, f := range files {
		err := os.WriteFile(filepath.Join(tempDir, f), []byte("test"), 0644)
		require.NoError(t, err)
	}

	// Read directory
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	var infos []os.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		infos = append(infos, info)
	}

	lister := listerat(infos)

	// Test ListAt with offset 0
	buf := make([]os.FileInfo, 2)
	n, err := lister.ListAt(buf, 0)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)

	// Test ListAt with offset at end
	n, err = lister.ListAt(buf, int64(len(infos)))
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 0, n)
}
