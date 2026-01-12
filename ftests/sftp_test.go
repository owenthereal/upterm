package ftests

import (
	"io"
	"os"
	"path/filepath"
	"testing"

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
}

// TestSFTP runs SFTP tests using the FtestSuite framework
func (suite *FtestSuite) TestSFTP() {
	suite.runTestCategory(SFTPTestCases)
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
	f, err := sftpClient.Open(testFilePath)
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
	f, err := sftpClient.Create(uploadFilePath)
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
	f, err := sftpClient.Open(testFilePath)
	require.NoError(err, "download should work in read-only mode")
	downloadedContent, err := io.ReadAll(f)
	require.NoError(err)
	_ = f.Close()
	assert.Equal(testContent, string(downloadedContent), "downloaded content should match")

	// Upload should fail in read-only mode
	uploadFilePath := filepath.Join(testDir, "upload-should-fail.txt")
	_, err = sftpClient.Create(uploadFilePath)
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
	entries, err := sftpClient.ReadDir(testDir)
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
	subEntries, err := sftpClient.ReadDir(subDirPath)
	require.NoError(err, "should be able to list subdirectory")
	require.Len(subEntries, 1, "subdir should have one file")
	assert.Equal("file3.txt", subEntries[0].Name(), "should see file3.txt in subdir")
}
