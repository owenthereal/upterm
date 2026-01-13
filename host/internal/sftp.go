package internal

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	gssh "github.com/charmbracelet/ssh"
	hostsftp "github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/utils"
	"github.com/pkg/sftp"
)

// SFTPSession tracks permission state for a single SFTP session
type SFTPSession struct {
	readOnly          bool                      // Only allow downloads (no upload/delete)
	permissionChecker hostsftp.PermissionChecker // Optional: prompts user for permission (nil = auto-allow)
	clientInfo        hostsftp.ClientInfo        // Client information for permission dialogs
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
	clientInfo := hostsftp.ClientInfo{
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

	handlers := sftp.Handlers{
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
	server := sftp.NewRequestServer(sess, handlers, sftp.WithStartDirectory(userHome))
	if err := server.Serve(); err != nil {
		if err != io.EOF {
			h.logger.Error("sftp server error", "error", err)
		}
	}
	_ = server.Close()

	h.logger.Info("SFTP session ended")
}

// checkPermission prompts user for permission if needed
func (s *SFTPSession) checkPermission(op hostsftp.Operation, path string) error {
	// No checker = auto-allow (headless/CI mode)
	if s.permissionChecker == nil {
		return nil
	}

	// Check permission (the checker handles caching of "Allow All" decisions)
	result, err := s.permissionChecker.CheckPermission(op, path, s.clientInfo)
	if err != nil {
		// Checker unavailable (headless system)
		// Allow operation - connection-level consent is sufficient
		return nil
	}

	if result == hostsftp.PermissionDenied {
		return fmt.Errorf("permission denied by user")
	}
	return nil
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

// sftpFileReader handles file download requests
type sftpFileReader struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileReader) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	// Check permission (shows zenity dialog if needed)
	if err := h.session.checkPermission(hostsftp.OpDownload, path); err != nil {
		h.logger.Info("SFTP download denied", "path", path)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	h.logger.Info("SFTP download", "path", path)
	return os.Open(path)
}

// sftpFileWriter handles file upload requests
type sftpFileWriter struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileWriter) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	// Deny uploads in read-only mode
	if h.session.readOnly {
		h.logger.Info("SFTP upload denied (read-only mode)", "path", r.Filepath)
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	logger := h.logger.With("original_path", r.Filepath)
	logger.Debug("SFTP upload request", "original_path", r.Filepath)

	path, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	logger = logger.With("resolved_path", path)

	if err := h.session.checkPermission(hostsftp.OpUpload, path); err != nil {
		logger.Info("SFTP upload denied")
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	logger.Info("SFTP upload")

	// Get file flags from request
	pflags := r.Pflags()
	osFlags := os.O_WRONLY

	if pflags.Creat {
		osFlags |= os.O_CREATE
	}
	if pflags.Trunc {
		osFlags |= os.O_TRUNC
	}
	if pflags.Append {
		osFlags |= os.O_APPEND
	}
	if pflags.Excl {
		osFlags |= os.O_EXCL
	}

	return os.OpenFile(path, osFlags, 0644)
}

// sftpFileCmder handles mkdir, remove, rename, etc.
type sftpFileCmder struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileCmder) Filecmd(r *sftp.Request) error {
	// Deny all modifications in read-only mode
	if h.session.readOnly {
		h.logger.Info("SFTP command denied (read-only mode)", "method", r.Method, "path", r.Filepath)
		return sftp.ErrSSHFxPermissionDenied
	}

	path, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return sftp.ErrSSHFxPermissionDenied
	}

	// Map request method to operation
	var op hostsftp.Operation
	switch r.Method {
	case "Remove":
		op = hostsftp.OpDelete
	case "Mkdir":
		op = hostsftp.OpMkdir
	case "Rename":
		op = hostsftp.OpRename
	case "Rmdir":
		op = hostsftp.OpRmdir
	case "Symlink":
		op = hostsftp.OpSymlink
	case "Link":
		op = hostsftp.OpLink
	case "Setstat":
		op = hostsftp.OpSetstat
	default:
		h.logger.Info("SFTP unsupported command", "method", r.Method, "path", path)
		return sftp.ErrSSHFxOpUnsupported
	}

	if err := h.session.checkPermission(op, path); err != nil {
		h.logger.Info("SFTP command denied", "method", r.Method, "path", path)
		return sftp.ErrSSHFxPermissionDenied
	}

	h.logger.Info("SFTP command", "method", r.Method, "path", path)

	// Execute the actual operation
	switch r.Method {
	case "Remove":
		return os.Remove(path)
	case "Mkdir":
		return os.Mkdir(path, 0755)
	case "Rmdir":
		return os.Remove(path)
	case "Rename":
		targetPath, err := h.session.resolvePath(r.Target)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
		return os.Rename(path, targetPath)
	case "Symlink":
		// For symlink, Filepath is the link name and Target is the target
		targetPath, err := h.session.resolvePath(r.Target)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
		return os.Symlink(targetPath, path)
	case "Link":
		// For hard link, Filepath is the link name and Target is the existing file
		targetPath, err := h.session.resolvePath(r.Target)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
		return os.Link(targetPath, path)
	case "Setstat":
		// Handle file attribute changes
		attrs := r.Attributes()
		if attrs.Size != 0 {
			if err := os.Truncate(path, int64(attrs.Size)); err != nil {
				return err
			}
		}
		if attrs.Mtime != 0 {
			// Use atime if provided, otherwise fall back to mtime
			atime := attrs.AccessTime()
			if attrs.Atime == 0 {
				atime = attrs.ModTime()
			}
			if err := os.Chtimes(path, atime, attrs.ModTime()); err != nil {
				return err
			}
		}
		if attrs.Mode != 0 {
			if err := os.Chmod(path, attrs.FileMode()); err != nil {
				return err
			}
		}
		return nil
	}

	return sftp.ErrSSHFxOpUnsupported
}

// sftpFileLister handles directory listing and stat
type sftpFileLister struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileLister) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	// No permission prompt for listing - just path validation
	// (Listing directories doesn't expose file contents)

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		// Convert DirEntry to FileInfo
		var infos []fs.FileInfo
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue // Skip entries we can't stat
			}
			infos = append(infos, info)
		}
		return listerat(infos), nil

	case "Stat":
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return listerat{info}, nil

	case "Lstat":
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return listerat{info}, nil

	case "Readlink":
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		// Return a fake FileInfo with the link target as the name
		return listerat{linkInfo{name: target}}, nil
	}

	return nil, sftp.ErrSSHFxOpUnsupported
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

// linkInfo is a minimal FileInfo for Readlink responses
type linkInfo struct {
	name string
}

func (l linkInfo) Name() string       { return l.name }
func (l linkInfo) Size() int64        { return 0 }
func (l linkInfo) Mode() fs.FileMode  { return 0 }
func (l linkInfo) ModTime() time.Time { return time.Time{} }
func (l linkInfo) IsDir() bool        { return false }
func (l linkInfo) Sys() any           { return nil }
