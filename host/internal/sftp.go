package internal

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	gssh "charm.land/ssh"
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

// checkPermission prompts user for permission if needed.
// For two-path operations (rename, symlink, link), pass both source and target paths.
func (s *SFTPSession) checkPermission(op hostsftp.Operation, paths ...string) error {
	// No checker = auto-allow (headless/CI mode)
	if s.permissionChecker == nil {
		return nil
	}

	// Check permission (the checker handles caching of "Allow All" decisions)
	result, err := s.permissionChecker.CheckPermission(op, s.clientInfo, paths...)
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

// resolvePath turns the POSIX path the client sent into a local one.
//
// Absolute paths are used as-is. Relative paths arrive already resolved
// against the session's start directory, which WithStartDirectory sets to the
// user's home, so there is nothing to do for them here.
//
// There is no tilde handling. Tilde expansion is not part of SFTP, and the
// branch that used to be here could never run: the library resolves every
// request against the start directory before a handler sees it, so reqPath is
// always absolute by this point and never still begins with "~". Relative
// paths already resolve to the home directory, so "notes.txt" covers what
// "~/notes.txt" was reaching for.
func (s *SFTPSession) resolvePath(reqPath string) (string, error) {
	if runtime.GOOS == "windows" {
		reqPath = undoubleDriveLetter(reqPath)
	}

	// SFTP sends Windows paths like "/C:/foo" - strip leading "/" for proper handling
	if len(reqPath) >= 3 && reqPath[0] == '/' && reqPath[2] == ':' {
		reqPath = reqPath[1:]
	}

	return filepath.Clean(reqPath), nil
}

// undoubleDriveLetter repairs a path a client sent in native Windows form.
//
// SFTP paths are POSIX on every platform, so an absolute path on a Windows
// host travels as /C:/dir/file. A client that sends the native C:\dir\file or
// C:/dir/file is sending something the protocol reads as relative, so the
// server resolves it against the session's start directory and the request
// arrives doubled, as /C:/Users/me/C:/dir/file.
//
// A path component of exactly "X:" cannot be a filename -- Windows does not
// allow ':' in one -- so a drive letter anywhere but the front can only have
// arrived this way, and the last one is the path the client meant. Callers
// must only apply this on Windows: ':' is legal in a POSIX filename, and on a
// Linux host a client asking for C:\foo really is naming a file under the
// start directory.
func undoubleDriveLetter(p string) string {
	last := -1
	for i := 0; i+2 < len(p); i++ {
		if p[i] != '/' || p[i+2] != ':' || !isDriveLetter(p[i+1]) {
			continue
		}
		// The drive must be the whole component: it either introduces a
		// path or ends the string. A colon that merely follows a one-letter
		// name is NTFS alternate-data-stream syntax -- "/C:/dir/f:meta" is
		// the "meta" stream of the file "f" -- and rewriting that would
		// silently retarget the request at drive F: instead.
		if i+3 == len(p) || p[i+3] == '/' {
			last = i
		}
	}

	// last == 0 is the ordinary "/C:/dir" form, which needs no repair.
	if last > 0 {
		return p[last:]
	}
	return p
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
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

	// Resolve target path upfront for two-path operations
	var targetPath string
	isTwoPathOp := r.Method == "Rename" || r.Method == "Symlink" || r.Method == "Link"
	if isTwoPathOp {
		targetPath, err = h.session.resolvePath(r.Target)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
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

	// Check permission - pass both paths for two-path operations
	if isTwoPathOp {
		err = h.session.checkPermission(op, path, targetPath)
	} else {
		err = h.session.checkPermission(op, path)
	}
	if err != nil {
		h.logger.Info("SFTP command denied", "method", r.Method, "path", path)
		return sftp.ErrSSHFxPermissionDenied
	}

	h.logger.Info("SFTP command", "method", r.Method, "path", path)

	// Execute the operation
	switch r.Method {
	case "Remove":
		return os.Remove(path)
	case "Mkdir":
		return os.Mkdir(path, 0755)
	case "Rmdir":
		return os.Remove(path)
	case "Rename":
		return os.Rename(path, targetPath)
	case "Symlink":
		return os.Symlink(targetPath, path)
	case "Link":
		return os.Link(targetPath, path)
	case "Setstat":
		// Handle file attribute changes
		attrs := r.Attributes()
		flags := r.AttrFlags()

		// Handle size change (truncate) - use flags to detect if size was set (allows truncate to 0)
		if flags.Size {
			if err := os.Truncate(path, int64(attrs.Size)); err != nil {
				return err
			}
		}

		// Handle ownership change
		if flags.UidGid {
			if err := os.Chown(path, int(attrs.UID), int(attrs.GID)); err != nil {
				return err
			}
		}

		// Handle permission change
		if flags.Permissions {
			if err := os.Chmod(path, attrs.FileMode()); err != nil {
				return err
			}
		}

		// Handle timestamp change
		if flags.Acmodtime {
			atime := attrs.AccessTime()
			mtime := attrs.ModTime()
			if err := os.Chtimes(path, atime, mtime); err != nil {
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
