package internal

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gssh "github.com/charmbracelet/ssh"
	"github.com/owenthereal/upterm/host/sftp"
	pkgsftp "github.com/pkg/sftp"
)

// SFTPSession tracks permission state for a single SFTP session
type SFTPSession struct {
	root              string            // Root directory for file access
	readOnly          bool              // Only allow downloads (no upload/delete)
	alwaysAllow       bool              // User clicked "Always" in dialog
	permissionChecker sftp.PermissionChecker // Optional: prompts user for permission (nil = auto-allow)
	mu                sync.Mutex
}

// HandleSFTP handles SFTP subsystem requests
func (h *sessionHandler) HandleSFTP(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	// Determine root directory
	root := h.sftpRoot
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			h.logger.Error("failed to get working directory", "error", err)
			_ = sess.Exit(1)
			return
		}
	}

	// Ensure root is absolute and clean
	root, err := filepath.Abs(root)
	if err != nil {
		h.logger.Error("failed to resolve SFTP root", "error", err)
		_ = sess.Exit(1)
		return
	}

	h.logger.Info("SFTP session started", "root", root, "readonly", h.readonly)

	// Create permission-checking handlers
	sftpSession := &SFTPSession{
		root:              root,
		readOnly:          h.readonly,
		permissionChecker: h.sftpPermissionChecker,
	}

	handlers := pkgsftp.Handlers{
		FileGet:  &sftpFileReader{session: sftpSession, logger: h.logger},
		FilePut:  &sftpFileWriter{session: sftpSession, logger: h.logger},
		FileCmd:  &sftpFileCmder{session: sftpSession, logger: h.logger},
		FileList: &sftpFileLister{session: sftpSession, logger: h.logger},
	}

	server := pkgsftp.NewRequestServer(sess, handlers)
	if err := server.Serve(); err != nil {
		if err != io.EOF {
			h.logger.Error("sftp server error", "error", err)
		}
	}
	_ = server.Close()

	h.logger.Info("SFTP session ended")
}

// resolvePath validates and resolves a path within the SFTP root
func (s *SFTPSession) resolvePath(reqPath string) (string, error) {
	// Clean the requested path and make it relative
	cleanPath := filepath.Clean("/" + reqPath)

	// Join with root
	absPath := filepath.Join(s.root, cleanPath)

	// Ensure path stays within root (prevent directory traversal)
	// We need to handle the case where root itself is being accessed
	if !strings.HasPrefix(absPath, s.root) {
		return "", os.ErrPermission
	}

	// Also check that after cleaning, the path still starts with root
	// This handles cases like /root/../etc
	absPath = filepath.Clean(absPath)
	if !strings.HasPrefix(absPath, s.root) && absPath != s.root {
		return "", os.ErrPermission
	}

	return absPath, nil
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
