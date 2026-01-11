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
	tempDir := t.TempDir()

	session := &SFTPSession{
		root:     tempDir,
		readOnly: false,
	}

	tests := []struct {
		name      string
		reqPath   string
		wantPath  string
		wantError bool
	}{
		{
			name:     "root path",
			reqPath:  "/",
			wantPath: tempDir,
		},
		{
			name:     "simple file",
			reqPath:  "/file.txt",
			wantPath: filepath.Join(tempDir, "file.txt"),
		},
		{
			name:     "nested path",
			reqPath:  "/dir/subdir/file.txt",
			wantPath: filepath.Join(tempDir, "dir/subdir/file.txt"),
		},
		{
			name:     "path without leading slash",
			reqPath:  "file.txt",
			wantPath: filepath.Join(tempDir, "file.txt"),
		},
		{
			name:     "directory traversal attempt - stays in root",
			reqPath:  "/../../../etc/passwd",
			wantPath: filepath.Join(tempDir, "etc/passwd"),
		},
		{
			name:     "directory traversal with nested path - stays in root",
			reqPath:  "/dir/../../../etc/passwd",
			wantPath: filepath.Join(tempDir, "etc/passwd"),
		},
		{
			name:     "double dots in middle",
			reqPath:  "/dir/../file.txt",
			wantPath: filepath.Join(tempDir, "file.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := session.resolvePath(tt.reqPath)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
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
