package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/tmux"
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

// printedTransferCommands are the lines the host printed under ➤ SFTP: and
// ➤ SCP:: the sftp line, then scp's upload and download lines.
func (h *testHarness) printedTransferCommands() (sftp, scpUpload, scpDownload string) {
	h.t.Helper()
	scp := h.printedLines("SCP")
	require.Len(h.t, scp, 2, "➤ SCP: should print an upload and a download line")
	return h.printedLines("SFTP")[0], scp[0], scp[1]
}

// asGuest is a line the host printed, run with the guest's key and without
// recording the relay's key, as connectClient runs the ssh line. Everything
// else is left as printed, placeholders filled.
func (h *testHarness) asGuest(printed string, placeholders ...string) string {
	program, rest, _ := strings.Cut(printed, " ")
	line := fmt.Sprintf("%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s",
		program, h.clientKeyFile, rest)
	return strings.NewReplacer(placeholders...).Replace(line)
}

// exitStatusOf runs line in pane and returns its exit status, read from the
// pane once the shell has printed it. The marker is split in the line typed,
// so only the shell's output can match it.
func (h *testHarness) exitStatusOf(pane *tmux.Pane, line string) string {
	h.t.Helper()
	marker := fmt.Sprintf("STATUS_%d", time.Now().UnixNano())
	require.NoError(h.t, pane.SendLine(h.ctx, fmt.Sprintf(`%s; echo "%s""%s=$?"`, line, marker[:3], marker[3:])))
	require.NoError(h.t, h.waitForText(pane, marker+"=", 30*time.Second), "%s did not finish", line)
	output, err := h.captureWithHistory(pane)
	require.NoError(h.t, err)
	m := regexp.MustCompile(regexp.QuoteMeta(marker) + `=(\d+)`).FindStringSubmatch(output)
	require.Len(h.t, m, 2, "no exit status for %s in:\n%s", line, output)
	h.t.Logf("Command exited %s: %s", m[1], line)
	return m[1]
}

// TestSFTPDownload downloads a file with the scp download line as the host
// printed it, which exits 0 once the file is there.
func TestSFTPDownload(t *testing.T) {
	h := newTestHarness(t, 200)

	testContent := "hello from sftp download test"
	testFile := h.writeFile("download-test.txt", testContent, 0644)

	h.startHost("--accept")
	_, _, scpDownload := h.printedTransferCommands()
	client := h.splitPane(h.host)

	downloadDest := filepath.Join(h.tmpDir, "downloaded.txt")
	line := h.asGuest(scpDownload, "<remote>", testFile, "<local>", downloadDest)
	status := h.exitStatusOf(client, line)
	screen, _ := h.captureWithHistory(client)
	require.Equal(t, "0", status, "the printed scp download line failed:\n%s", screen)

	content, err := os.ReadFile(downloadDest)
	require.NoError(t, err, "downloaded file should exist")
	require.Equal(t, testContent, string(content), "downloaded content should match")
}

// TestSFTPUpload uploads a file with the scp upload line as the host printed
// it, which exits 0 once the file is on the host.
func TestSFTPUpload(t *testing.T) {
	h := newTestHarness(t, 200)

	uploadContent := "hello from sftp upload test"
	localFile := h.writeFile("upload-source.txt", uploadContent, 0644)

	h.startHost("--accept")
	_, scpUpload, _ := h.printedTransferCommands()
	client := h.splitPane(h.host)

	uploadedPath := filepath.Join(h.tmpDir, "uploaded.txt")
	line := h.asGuest(scpUpload, "<local>", localFile, "<remote>", uploadedPath)
	status := h.exitStatusOf(client, line)
	screen, _ := h.captureWithHistory(client)
	require.Equal(t, "0", status, "the printed scp upload line failed:\n%s", screen)

	content, err := os.ReadFile(uploadedPath)
	require.NoError(t, err, "uploaded file should exist on host")
	require.Equal(t, uploadContent, string(content), "uploaded content should match")
}

// TestSFTPCommandAsPrinted downloads a file through the sftp line as the host
// printed it, driven by a batch file.
func TestSFTPCommandAsPrinted(t *testing.T) {
	h := newTestHarness(t, 200)

	testContent := "hello from the printed sftp line"
	testFile := h.writeFile("sftp-test.txt", testContent, 0644)
	downloadDest := filepath.Join(h.tmpDir, "sftp-downloaded.txt")
	batch := h.writeFile("sftp-batch", fmt.Sprintf("get %s %s\n", testFile, downloadDest), 0644)

	h.startHost("--accept")
	sftp, _, _ := h.printedTransferCommands()
	client := h.splitPane(h.host)

	line := h.asGuest(strings.Replace(sftp, "sftp ", "sftp -b "+batch+" ", 1))
	status := h.exitStatusOf(client, line)
	screen, _ := h.captureWithHistory(client)
	require.Equal(t, "0", status, "the printed sftp line failed:\n%s", screen)

	content, err := os.ReadFile(downloadDest)
	require.NoError(t, err, "downloaded file should exist")
	require.Equal(t, testContent, string(content))
}

// TestSFTPDisabled tests that --no-sftp disables SFTP/SCP. The host prints no
// transfer lines then, so the guest builds the scp line itself.
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

// TestSFTPReadOnly tests that --read-only allows the printed download line and
// refuses the printed upload line.
func TestSFTPReadOnly(t *testing.T) {
	h := newTestHarness(t, 200)

	downloadContent := "read-only download test"
	testFile := h.writeFile("readonly-file.txt", downloadContent, 0644)

	h.startHost("--accept --read-only")
	_, scpUpload, scpDownload := h.printedTransferCommands()
	client := h.splitPane(h.host)

	// Download works
	downloadDest := filepath.Join(h.tmpDir, "downloaded-readonly.txt")
	status := h.exitStatusOf(client, h.asGuest(scpDownload, "<remote>", testFile, "<local>", downloadDest))
	screen, _ := h.captureWithHistory(client)
	require.Equal(t, "0", status, "the printed scp download line failed in read-only mode:\n%s", screen)
	content, err := os.ReadFile(downloadDest)
	require.NoError(t, err, "download should work in read-only mode")
	require.Equal(t, downloadContent, string(content))

	// Upload is refused
	uploadFile := h.writeFile("try-upload.txt", "this should fail", 0644)
	uploadDest := filepath.Join(h.tmpDir, "should-fail.txt")
	status = h.exitStatusOf(client, h.asGuest(scpUpload, "<local>", uploadFile, "<remote>", uploadDest))
	screen, _ = h.captureWithHistory(client)
	require.NotEqual(t, "0", status, "an upload in read-only mode succeeded:\n%s", screen)
	require.Contains(t, screen, "denied", "expected permission denied error")
	_, err = os.Stat(uploadDest)
	require.Error(t, err, "upload should fail in read-only mode")
}
