package ftests

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SFTPTestCases contains all SFTP-related test functions
var SFTPTestCases = []FtestCase{
	testSFTPDownload,
	testSFTPUpload,
	testSFTPReadOnly,
	testSFTPDisabled,
	testSFTPDirectoryListing,
	testSFTPSetstat,
	testSFTPNativeWindowsPath,
}

// TestSFTP runs SFTP tests using the FtestSuite framework
func (suite *FtestSuite) TestSFTP() {
	suite.runTestCategory(SFTPTestCases)
}

// remotePath converts a local filesystem path into the POSIX form SFTP uses on
// the wire.
//
// The sftp client sends paths verbatim; there is not one filepath reference in
// its client.go. On Windows that means an absolute path like C:\dir\file goes
// out as-is, and the server does not see it as absolute, because POSIX rules
// need a leading slash. It therefore joins it onto the session's start
// directory and the request lands on
// /C:/Users/me/C:/dir/file. OpenSSH's own clients encode Windows absolute
// paths as /C:/dir/file, which is what this produces. On Unix it is identity.
//
// Every path handed to the sftp client has to go through this. Missing one is
// silent on Unix and only shows up on the Windows job, as a chtimes or open
// error naming a path with the start directory glued to the front.
func remotePath(p string) string {
	s := filepath.ToSlash(p)
	if filepath.IsAbs(p) && !path.IsAbs(s) {
		s = "/" + s
	}
	return s
}

// TestRemotePathIsPOSIXAbsolute pins the invariant the SFTP tests depend on.
//
// The sftp client sends paths verbatim, and the server treats anything that is
// not POSIX-absolute as relative to the session's start directory, which upterm
// sets to the user's home. A native Windows path is not POSIX-absolute, so
// handing filepath.Join(t.TempDir(), ...) straight to the client made every
// request land on /C:/Users/me/C:/Users/me/... instead of the file.
//
// This fails on Windows if remotePath is ever reduced to the identity, and is
// the cheap, deterministic counterpart to the functional SFTP tests below,
// which cover the same ground but only end to end.
func TestRemotePathIsPOSIXAbsolute(t *testing.T) {
	local := filepath.Join(t.TempDir(), "file.txt")

	got := remotePath(local)
	require.True(t, path.IsAbs(got),
		"remotePath(%q) = %q, which the server would resolve against the start directory", local, got)
	require.False(t, strings.Contains(got, "\\"),
		"remotePath(%q) = %q still contains a native separator", local, got)
}

// TestRemotePath pins the conversion itself, per platform.
func TestRemotePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		assert.Equal(t, "/C:/dir/file.txt", remotePath(`C:\dir\file.txt`))
		assert.Equal(t, "/C:/dir", remotePath(`C:\dir`))
		// Already in wire form, or relative: left alone.
		assert.Equal(t, "/C:/dir/file.txt", remotePath("/C:/dir/file.txt"))
		assert.Equal(t, "dir/file.txt", remotePath(`dir\file.txt`))
		return
	}

	assert.Equal(t, "/dir/file.txt", remotePath("/dir/file.txt"))
	assert.Equal(t, "dir/file.txt", remotePath("dir/file.txt"))
}

// testSFTPNativeWindowsPath checks that a guest can name a file the way it
// looks on the host, not only the way the protocol spells it.
//
// SFTP paths are POSIX everywhere, so an absolute path on a Windows host
// travels as /C:/dir/file, which is what remotePath produces and what the
// other cases here use. But a guest looking at a Windows machine reasonably
// types C:\dir\file, and that is what the fork this replaced used to accept.
// The server sees a path the protocol reads as relative, resolves it against
// the session's start directory, and the request arrives doubled; the host
// repairs it. Nothing to test off Windows: elsewhere ':' is an ordinary
// filename character and the path means what it says.
func testSFTPNativeWindowsPath(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	if runtime.GOOS != "windows" {
		t.Skip("native drive-letter paths only arise against a Windows host")
	}

	require := require.New(t)
	assert := assert.New(t)

	testDir := t.TempDir()
	testContent := "Hello from a native Windows path!\n"
	testFilePath := filepath.Join(testDir, "native-path-test.txt")
	require.NoError(os.WriteFile(testFilePath, []byte(testContent), 0644))

	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(h.Share(hostShareURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(c.Join(session, clientJoinURL))
	defer c.Close()

	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// Deliberately not remotePath: send the native path, backslashes and all.
	require.Contains(testFilePath, `\`, "expected a native Windows path from t.TempDir")

	f, err := sftpClient.Open(testFilePath)
	require.NoError(err, "a native Windows path should be accepted")
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	require.NoError(err)
	assert.Equal(testContent, string(got), "downloaded content should match")
}

// testSFTPDownload tests downloading a file via SFTP
// This test is critical for verifying cluster mode: client connects to one server (ts2)
// while host is on another (ts1), SFTP requests must be properly routed.
func testSFTPDownload(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Create temp directory for test files
	testDir := t.TempDir()

	// Create a test file to download
	testContent := "Hello from SFTP download test!\n"
	testFilePath := filepath.Join(testDir, "download-test.txt")
	err := os.WriteFile(testFilePath, []byte(testContent), 0644)
	require.NoError(err)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err = h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Open SFTP client
	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// Download the file using absolute path (OpenSSH semantics)
	f, err := sftpClient.Open(remotePath(testFilePath))
	require.NoError(err, "should be able to open file via SFTP")
	defer func() { _ = f.Close() }()

	downloadedContent, err := io.ReadAll(f)
	require.NoError(err, "should be able to read file via SFTP")

	assert.Equal(testContent, string(downloadedContent), "downloaded content should match")
}

// testSFTPUpload tests uploading a file via SFTP
// Tests cluster mode routing for write operations.
func testSFTPUpload(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Create temp directory for test files
	testDir := t.TempDir()

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Open SFTP client
	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// Upload a new file using absolute path (OpenSSH semantics)
	uploadFilePath := filepath.Join(testDir, "upload-test.txt")
	uploadContent := "Hello from SFTP upload test!\n"
	f, err := sftpClient.Create(remotePath(uploadFilePath))
	require.NoError(err, "should be able to create file via SFTP")

	_, err = f.Write([]byte(uploadContent))
	require.NoError(err, "should be able to write to file via SFTP")
	err = f.Close()
	require.NoError(err, "should be able to close file via SFTP")

	// Verify file exists on host
	content, err := os.ReadFile(uploadFilePath)
	require.NoError(err, "uploaded file should exist on host")
	assert.Equal(uploadContent, string(content), "uploaded content should match")
}

// testSFTPReadOnly tests that uploads are blocked in read-only mode
func testSFTPReadOnly(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Create temp directory for test files
	testDir := t.TempDir()

	// Create a test file to download (should still work in read-only mode)
	testContent := "Hello from read-only test!\n"
	testFilePath := filepath.Join(testDir, "readonly-test.txt")
	err := os.WriteFile(testFilePath, []byte(testContent), 0644)
	require.NoError(err)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ReadOnly:                 true, // Enable read-only mode
	}
	err = h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Open SFTP client
	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// Download should still work in read-only mode (using absolute path)
	f, err := sftpClient.Open(remotePath(testFilePath))
	require.NoError(err, "download should work in read-only mode")
	downloadedContent, err := io.ReadAll(f)
	require.NoError(err)
	_ = f.Close()
	assert.Equal(testContent, string(downloadedContent), "downloaded content should match")

	// Upload should fail in read-only mode
	uploadFilePath := filepath.Join(testDir, "upload-should-fail.txt")
	_, err = sftpClient.Create(remotePath(uploadFilePath))
	assert.Error(err, "upload should fail in read-only mode")
}

// testSFTPDisabled tests that SFTP subsystem is disabled when configured
func testSFTPDisabled(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		SFTPDisabled:             true, // Disable SFTP
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Trying to open SFTP client should fail when SFTP is disabled
	_, err = c.SFTP()
	assert.Error(err, "SFTP connection should fail when SFTP is disabled")
}

// testSFTPDirectoryListing tests listing directories via SFTP
func testSFTPDirectoryListing(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Create temp directory for test files
	testDir := t.TempDir()

	// Create some test files and directories
	err := os.WriteFile(filepath.Join(testDir, "file1.txt"), []byte("content1"), 0644)
	require.NoError(err)
	err = os.WriteFile(filepath.Join(testDir, "file2.txt"), []byte("content2"), 0644)
	require.NoError(err)
	err = os.Mkdir(filepath.Join(testDir, "subdir"), 0755)
	require.NoError(err)
	err = os.WriteFile(filepath.Join(testDir, "subdir", "file3.txt"), []byte("content3"), 0644)
	require.NoError(err)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err = h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Open SFTP client
	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// List test directory using absolute path (OpenSSH semantics)
	entries, err := sftpClient.ReadDir(remotePath(testDir))
	require.NoError(err, "should be able to list test directory")

	// Verify we see the expected entries
	names := make(map[string]bool)
	for _, entry := range entries {
		names[entry.Name()] = true
	}

	assert.True(names["file1.txt"], "should see file1.txt")
	assert.True(names["file2.txt"], "should see file2.txt")
	assert.True(names["subdir"], "should see subdir")

	// List subdirectory using absolute path
	subDirPath := filepath.Join(testDir, "subdir")
	subEntries, err := sftpClient.ReadDir(remotePath(subDirPath))
	require.NoError(err, "should be able to list subdirectory")
	require.Len(subEntries, 1, "subdir should have one file")
	assert.Equal("file3.txt", subEntries[0].Name(), "should see file3.txt in subdir")
}

// testSFTPSetstat tests file attribute modifications (chmod, truncate, chtimes)
func testSFTPSetstat(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Create temp directory for test files
	testDir := t.TempDir()

	// Create a test file
	testFilePath := filepath.Join(testDir, "setstat-test.txt")
	testContent := "Hello from SFTP setstat test!\n"
	err := os.WriteFile(testFilePath, []byte(testContent), 0644)
	require.NoError(err)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err = h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server and get session
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Connect client
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)
	defer c.Close()

	// Open SFTP client
	sftpClient, err := c.SFTP()
	require.NoError(err, "should be able to open SFTP connection")
	defer func() { _ = sftpClient.Close() }()

	// Test 1: Chmod - change file permissions
	err = sftpClient.Chmod(remotePath(testFilePath), 0600)
	require.NoError(err, "should be able to chmod file")

	info, err := os.Stat(testFilePath)
	require.NoError(err)
	// Check file is writable (0200 bit) - works cross-platform
	// (Windows uses ACLs, not Unix permission bits, so exact mode differs)
	assert.NotZero(info.Mode().Perm()&0200, "file should be writable")

	// Test 2: Truncate - change file size
	err = sftpClient.Truncate(remotePath(testFilePath), 5)
	require.NoError(err, "should be able to truncate file")

	info, err = os.Stat(testFilePath)
	require.NoError(err)
	assert.Equal(int64(5), info.Size(), "file size should be 5 bytes")

	// Verify content is truncated
	content, err := os.ReadFile(testFilePath)
	require.NoError(err)
	assert.Equal("Hello", string(content), "content should be truncated to 'Hello'")

	// Test 3: Truncate to 0 - verify we can truncate to zero bytes
	err = sftpClient.Truncate(remotePath(testFilePath), 0)
	require.NoError(err, "should be able to truncate file to 0 bytes")

	info, err = os.Stat(testFilePath)
	require.NoError(err)
	assert.Equal(int64(0), info.Size(), "file size should be 0 bytes")

	// Test 4: Chtimes - change file timestamps
	atime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	mtime := time.Date(2021, 6, 15, 12, 30, 0, 0, time.UTC)
	err = sftpClient.Chtimes(remotePath(testFilePath), atime, mtime)
	require.NoError(err, "should be able to change file times")

	info, err = os.Stat(testFilePath)
	require.NoError(err)
	// Note: atime may not be preserved on all systems, but mtime should be
	assert.Equal(mtime.Unix(), info.ModTime().Unix(), "mtime should be updated")
}
