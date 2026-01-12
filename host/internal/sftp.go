package internal

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	gssh "github.com/charmbracelet/ssh"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/utils"
	pkgsftp "github.com/pkg/sftp"
)

// SFTPSession tracks permission state for a single SFTP session
type SFTPSession struct {
	readOnly          bool                   // Only allow downloads (no upload/delete)
	permissionChecker sftp.PermissionChecker // Optional: prompts user for permission (nil = auto-allow)
	clientInfo        sftp.ClientInfo        // Client information for permission dialogs
}

// HandleSFTP handles SFTP subsystem requests
func (h *sessionHandler) HandleSFTP(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	// Clean up permission cache when session ends
	if h.sftpPermissionChecker != nil {
		defer h.sftpPermissionChecker.ClearSession(sessionID)
	}

	// Get client info for permission dialogs
	clientInfo := sftp.ClientInfo{
		SessionID: sessionID,
	}
	if pk := sess.PublicKey(); pk != nil {
		clientInfo.Fingerprint = utils.FingerprintSHA256(pk)
	}

	h.logger.Info("SFTP session started", "readonly", h.readonly, "client", clientInfo.Fingerprint)

	// Create permission-checking handlers
	sftpSession := &SFTPSession{
		readOnly:          h.readonly,
		permissionChecker: h.sftpPermissionChecker,
		clientInfo:        clientInfo,
	}

	handlers := pkgsftp.Handlers{
		FileGet:  &sftpFileReader{session: sftpSession, logger: h.logger},
		FilePut:  &sftpFileWriter{session: sftpSession, logger: h.logger},
		FileCmd:  &sftpFileCmder{session: sftpSession, logger: h.logger},
		FileList: &sftpFileLister{session: sftpSession, logger: h.logger},
	}

	// Get user's home directory for SFTP start directory
	userHome, err := os.UserHomeDir()
	if err != nil {
		h.logger.Error("failed to get user home directory", "error", err)
		_ = sess.Exit(1)
		return
	}

	// Set start directory to user's home for relative path resolution
	server := pkgsftp.NewRequestServer(sess, handlers, pkgsftp.WithStartDirectory(userHome))
	if err := server.Serve(); err != nil {
		if err != io.EOF {
			h.logger.Error("sftp server error", "error", err)
		}
	}
	_ = server.Close()

	h.logger.Info("SFTP session ended")
}

// resolvePath resolves a path following standard OpenSSH/SCP semantics.
// - Tilde paths (~ or ~/path) are expanded to home directory
// - Absolute paths (starting with /) are used as-is
// - Relative paths are resolved from the user's home directory
//
// Note: WithStartDirectory(home) is set on the SFTP server, which handles
// relative path resolution at the protocol level.
func (s *SFTPSession) resolvePath(reqPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Handle tilde expansion (OpenSSH may send literal ~ or ~/path)
	if reqPath == "~" {
		return home, nil
	}
	if strings.HasPrefix(reqPath, "~/") {
		return filepath.Join(home, reqPath[2:]), nil
	}

	// Clean and return the path as-is
	// The SFTP server's WithStartDirectory handles relative paths
	return filepath.Clean(reqPath), nil
}

// listerat implements sftp.ListerAt
type listerat []fs.FileInfo

func (l listerat) ListAt(ls []fs.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}

	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}
