package internal

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSFTPSession_resolvePath(t *testing.T) {
	session := &SFTPSession{
		readOnly: false,
	}

	// Test cases for path resolution:
	// - Absolute paths (starting with /) are used as-is
	// - Relative paths are passed through (WithStartDirectory handles them at protocol level)
	//
	// There are deliberately no tilde cases. Tilde expansion is not part of
	// SFTP, and the branch that used to handle it could never run in
	// production: the library resolves every request against the start
	// directory first, so a handler never sees a path still starting with "~".
	// Testing resolvePath directly bypassed that and made the dead code look
	// alive.
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
		// Windows SFTP paths - leading "/" stripped for drive letter paths
		{
			name:     "windows drive path from SFTP",
			reqPath:  "/C:/Users/foo",
			wantPath: "C:/Users/foo",
		},
		{
			name:     "windows drive path lowercase",
			reqPath:  "/c:/temp/file.txt",
			wantPath: "c:/temp/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := session.resolvePath(tt.reqPath)
			require.NoError(t, err)
			// Use filepath.FromSlash to convert expected path to native separators
			// since filepath.Clean in resolvePath produces native paths
			assert.Equal(t, filepath.FromSlash(tt.wantPath), gotPath)
		})
	}
}

// TestUndoubleDriveLetter covers the repair itself, which is pure so that it is
// exercised on every platform rather than only on the Windows job.
func TestUndoubleDriveLetter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// What a client sending the native "C:\\Users\\me\\notes.txt" or
			// "C:/Users/me/notes.txt" produces once the server has resolved it
			// against a start directory of /C:/Users/me.
			name: "doubled drive letter is repaired",
			in:   "/C:/Users/me/C:/Users/me/notes.txt",
			want: "/C:/Users/me/notes.txt",
		},
		{
			name: "doubled across different drives",
			in:   "/C:/Users/me/D:/data/notes.txt",
			want: "/D:/data/notes.txt",
		},
		{
			name: "lowercase drive letter",
			in:   "/c:/users/me/c:/users/me/notes.txt",
			want: "/c:/users/me/notes.txt",
		},
		{
			name: "already canonical is left alone",
			in:   "/C:/Users/me/notes.txt",
			want: "/C:/Users/me/notes.txt",
		},
		{
			name: "bare drive is left alone",
			in:   "/C:",
			want: "/C:",
		},
		{
			name: "posix path without a drive letter is left alone",
			in:   "/home/me/notes.txt",
			want: "/home/me/notes.txt",
		},
		{
			name: "colon not preceded by a single letter is not a drive",
			in:   "/C:/Users/me/ab:/notes.txt",
			want: "/C:/Users/me/ab:/notes.txt",
		},
		{
			// "f:metadata" is the NTFS alternate data stream "metadata" on
			// the file "f". Reading the "/f:" as a drive would send the
			// request to drive F: instead of the file the client named.
			name: "alternate data stream on a one-letter file is not a drive",
			in:   "/C:/Users/me/f:metadata",
			want: "/C:/Users/me/f:metadata",
		},
		{
			name: "alternate data stream is not a drive even when doubled",
			in:   "/C:/Users/me/C:/Users/me/f:metadata",
			want: "/C:/Users/me/f:metadata",
		},
		{
			// A drive can end the path: this is what "ls C:" doubles into.
			name: "trailing bare drive is repaired",
			in:   "/C:/Users/me/D:",
			want: "/D:",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, undoubleDriveLetter(tt.in))
		})
	}
}

// TestSFTPSession_resolvePathWindows covers what a guest can type as the remote
// path against a Windows host. The protocol form is /C:/dir/file, but people
// reasonably type the path they see in Explorer, and the fork this replaced
// accepted those, so refusing them now would be a silent regression.
func TestSFTPSession_resolvePathWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-letter paths only resolve on Windows")
	}

	session := &SFTPSession{}
	const want = `C:\Users\me\notes.txt`

	// These are the requests as a handler sees them, after the library has
	// resolved them against a start directory of /C:/Users/me. Only two shapes
	// reach here: `notes.txt` and `/C:/Users/me/notes.txt` both arrive already
	// canonical, and both native spellings arrive doubled, because the library
	// converts separators before it joins.
	tests := []struct {
		name    string
		reqPath string
	}{
		{
			name:    "canonical, or a relative path resolved against the start directory",
			reqPath: "/C:/Users/me/notes.txt",
		},
		{
			name:    `native C:\Users\me\notes.txt or C:/Users/me/notes.txt`,
			reqPath: "/C:/Users/me/C:/Users/me/notes.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := session.resolvePath(tt.reqPath)
			require.NoError(t, err)
			assert.Equal(t, want, got)
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
