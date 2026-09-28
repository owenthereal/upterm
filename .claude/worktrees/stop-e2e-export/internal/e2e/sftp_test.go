package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// waitForFile polls until the file exists with non-zero size or timeout.
// scp creates the destination file immediately but writes content progressively,
// so we need to wait for actual content, not just file existence.
func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for file %s", path)
}

// TestSFTPDownload tests downloading a file via scp.
func TestSFTPDownload(t *testing.T) {
	h := newTestHarness(t, 200)

	// Create a test file on the host to download
	testContent := "hello from sftp download test"
	testFile := h.writeFile("download-test.txt", testContent, 0644)

	sshCmd := h.startHost("--accept")
	client := h.splitPane(h.host)

	// Extract user and host separately (username contains ':' which scp misinterprets)
	scpUser, scpHost := extractScpUserHost(sshCmd)
	require.NotEmpty(t, scpUser, "failed to extract scp user from SSH command")
	require.NotEmpty(t, scpHost, "failed to extract scp host from SSH command")

	// Create destination for downloaded file
	downloadDest := filepath.Join(h.tmpDir, "downloaded.txt")

	// Build scp command using -o User= to avoid ':' parsing issues
	// Use absolute path for remote file
	scpCmd := fmt.Sprintf("scp -o User=%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s:%s %s",
		scpUser, h.clientKeyFile, extractScpPortFlag(sshCmd), scpHost, testFile, downloadDest)

	require.NoError(t, client.SendLine(h.ctx, scpCmd))
	require.NoError(t, waitForFile(downloadDest, 30*time.Second), "scp download did not complete")

	// Verify downloaded content
	content, err := os.ReadFile(downloadDest)
	require.NoError(t, err, "downloaded file should exist")
	require.Equal(t, testContent, string(content), "downloaded content should match")
}

// TestSFTPUpload tests uploading a file via scp.
func TestSFTPUpload(t *testing.T) {
	h := newTestHarness(t, 200)

	// Create a local file to upload
	uploadContent := "hello from sftp upload test"
	localFile := h.writeFile("upload-source.txt", uploadContent, 0644)

	sshCmd := h.startHost("--accept")
	client := h.splitPane(h.host)

	// Extract user and host separately (username contains ':' which scp misinterprets)
	scpUser, scpHost := extractScpUserHost(sshCmd)
	require.NotEmpty(t, scpUser, "failed to extract scp user from SSH command")
	require.NotEmpty(t, scpHost, "failed to extract scp host from SSH command")

	// Build scp command using -o User= to avoid ':' parsing issues
	// Use absolute path for remote destination
	uploadedPath := filepath.Join(h.tmpDir, "uploaded.txt")
	scpCmd := fmt.Sprintf("scp -o User=%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s %s:%s",
		scpUser, h.clientKeyFile, extractScpPortFlag(sshCmd), localFile, scpHost, uploadedPath)

	require.NoError(t, client.SendLine(h.ctx, scpCmd))

	// Wait for uploaded file to appear on host
	require.NoError(t, waitForFile(uploadedPath, 30*time.Second), "scp upload did not complete")

	// Verify uploaded content
	content, err := os.ReadFile(uploadedPath)
	require.NoError(t, err, "uploaded file should exist on host")
	require.Equal(t, uploadContent, string(content), "uploaded content should match")
}

// TestSFTPDisabled tests that --no-sftp disables SFTP/SCP.
func TestSFTPDisabled(t *testing.T) {
	h := newTestHarness(t, 200)

	// Create a test file that should NOT be downloadable
	testFile := h.writeFile("forbidden.txt", "you should not see this", 0644)

	// Start host with SFTP disabled
	sshCmd := h.startHost("--accept --no-sftp")
	client := h.splitPane(h.host)

	// Extract user and host separately (username contains ':' which scp misinterprets)
	scpUser, scpHost := extractScpUserHost(sshCmd)
	require.NotEmpty(t, scpUser, "failed to extract scp user from SSH command")
	require.NotEmpty(t, scpHost, "failed to extract scp host from SSH command")

	// Try to download - should fail
	downloadDest := filepath.Join(h.tmpDir, "should-not-exist.txt")
	scpCmd := fmt.Sprintf("scp -o User=%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s:%s %s",
		scpUser, h.clientKeyFile, extractScpPortFlag(sshCmd), scpHost, testFile, downloadDest)

	require.NoError(t, client.SendLine(h.ctx, scpCmd))

	// Wait for scp error output (subsystem request failed)
	require.NoError(t, h.waitForText(client, "subsystem", 30*time.Second), "expected SFTP subsystem error")

	// Verify file was NOT downloaded
	_, err := os.ReadFile(downloadDest)
	require.Error(t, err, "file should not have been downloaded when SFTP is disabled")
}

// TestSFTPReadOnly tests that --read-only prevents uploads.
func TestSFTPReadOnly(t *testing.T) {
	h := newTestHarness(t, 200)

	// Create a test file that should be downloadable
	downloadContent := "read-only download test"
	testFile := h.writeFile("readonly-file.txt", downloadContent, 0644)

	// Start host in read-only mode
	sshCmd := h.startHost("--accept --read-only")
	client := h.splitPane(h.host)

	// Extract user and host separately (username contains ':' which scp misinterprets)
	scpUser, scpHost := extractScpUserHost(sshCmd)
	require.NotEmpty(t, scpUser, "failed to extract scp user from SSH command")
	require.NotEmpty(t, scpHost, "failed to extract scp host from SSH command")

	// Test 1: Download should work
	downloadDest := filepath.Join(h.tmpDir, "downloaded-readonly.txt")
	scpDownloadCmd := fmt.Sprintf("scp -o User=%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s:%s %s",
		scpUser, h.clientKeyFile, extractScpPortFlag(sshCmd), scpHost, testFile, downloadDest)

	require.NoError(t, client.SendLine(h.ctx, scpDownloadCmd))
	require.NoError(t, waitForFile(downloadDest, 30*time.Second), "scp download did not complete")

	content, err := os.ReadFile(downloadDest)
	require.NoError(t, err, "download should work in read-only mode")
	require.Equal(t, downloadContent, string(content))

	// Test 2: Upload should fail
	uploadFile := h.writeFile("try-upload.txt", "this should fail", 0644)
	uploadDest := filepath.Join(h.tmpDir, "should-fail.txt")
	scpUploadCmd := fmt.Sprintf("scp -o User=%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s %s:%s",
		scpUser, h.clientKeyFile, extractScpPortFlag(sshCmd), uploadFile, scpHost, uploadDest)

	require.NoError(t, client.SendLine(h.ctx, scpUploadCmd))

	// Wait for scp to produce error output (permission denied)
	require.NoError(t, h.waitForText(client, "denied", 30*time.Second), "expected permission denied error")

	// Verify file was NOT uploaded
	_, err = os.Stat(uploadDest)
	require.Error(t, err, "upload should fail in read-only mode")
}
