package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/utils"
	"github.com/pkg/sftp"
)

const sftpApprovalHint = "SFTP needs approval in the primary host terminal; the host can attach with approval escapes enabled or use --accept"

// SFTPSession tracks permission state for a single SFTP session
type SFTPSession struct {
	readOnly          bool // Only allow downloads (no upload/delete)
	permissionChecker consent.PermissionChecker
	clientInfo        consent.ClientInfo
	logger            *slog.Logger
	ctx               context.Context
	autoAccept        bool
}

// HandleSFTP handles SFTP subsystem requests
func (h *sessionHandler) HandleSFTP(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)

	// Get client info for terminal approval. The fingerprint is the guest's
	// own key, as the client list shows it: sess.PublicKey() is the
	// certificate the relay minted for its hop to the host.
	clientInfo := consent.ClientInfo{
		ConnectionID: sessionID,
	}
	guest, isGuest := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest)
	if isGuest && guest.key != nil {
		clientInfo.Fingerprint = utils.FingerprintSHA256(guest.key)
	}

	h.logger.Info("SFTP session started", "readonly", h.readonly, "client", clientInfo.Fingerprint)

	// Channel CLOSE cancels workers independently of pkg/sftp's own request
	// cancellation, which happens only after its workers have returned.
	ctx, cancel := sessionOperationContext(h.stopCtx, sess)
	defer cancel()

	// Create permission-checking handlers
	sftpSession := &SFTPSession{
		readOnly:          h.readonly,
		ctx:               ctx,
		autoAccept:        h.sftpAutoAccept,
		permissionChecker: h.permissionChecker,
		clientInfo:        clientInfo,
		logger:            h.logger,
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
	if isGuest {
		id := clientEventID(sessionID)
		emitClientJoinEvent(h.eventEmmiter, id, guest.auth, guest.key)
		defer emitClientLeftEvent(h.eventEmmiter, id)
	}
	if err := server.Serve(); err != nil {
		if err != io.EOF {
			h.logger.Error("sftp server error", "error", err)
		}
	}
	_ = server.Close()

	h.logger.Info("SFTP session ended")
}

// operationContext combines the request lifetime with channel and host loss.
// Consent gets its own deadline; an allowed transfer retains this context.
func (s *SFTPSession) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.ctx, cancel)
	if s.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

// checkPermission retains the original handler-entry deadline across queueing
// and re-coalescing. Paired operations always supply their complete tuple.
func (s *SFTPSession) checkPermission(ctx context.Context, arrived time.Time, op consent.Operation, paths ...string) (resultErr error) {
	defer func() { s.logPermission(op, paths, resultErr) }()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if op.Capability() != consent.CapabilitySFTP {
		return consent.ErrDenied
	}
	if s.readOnly && op != consent.OpDownload {
		return consent.ErrDenied
	}
	if s.autoAccept {
		return nil
	}
	if s.permissionChecker == nil {
		return fmt.Errorf("%w: %s", consent.ErrUnavailable, sftpApprovalHint)
	}
	permissionCtx, cancel := context.WithDeadline(ctx, arrived.Add(consent.PermissionTimeout))
	defer cancel()
	if permissionCtx.Err() != nil {
		return permissionCtx.Err()
	}
	decision, err := s.permissionChecker.CheckPermission(permissionCtx, op, s.clientInfo, paths...)
	if err == nil {
		err = permissionCtx.Err()
		if deadline, ok := permissionCtx.Deadline(); err == nil && ok && !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
		}
	}
	// The original contexts are authoritative even if an AfterFunc is still queued.
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = s.ctx.Err()
	}
	if errors.Is(err, consent.ErrUnavailable) {
		return fmt.Errorf("%w: %s", err, sftpApprovalHint)
	}
	if err != nil {
		return err
	}
	if decision != consent.AllowConnection && decision != consent.AllowGuest {
		return consent.ErrDenied
	}
	return nil
}

// Consent failures are actionable in the host log. Writing a diagnostic to an
// unread SSH stderr stream here could otherwise hold permission cleanup open.
func (s *SFTPSession) logPermission(op consent.Operation, paths []string, err error) {
	outcome := "allowed"
	switch {
	case errors.Is(err, consent.ErrUnavailable):
		outcome = "unavailable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, consent.ErrTimeout):
		outcome = "timeout"
	case errors.Is(err, context.Canceled), errors.Is(err, consent.ErrCanceled):
		outcome = "canceled"
	case errors.Is(err, consent.ErrOverloaded):
		outcome = "overloaded"
	case err != nil:
		outcome = "denied"
	}
	subjects := make([]string, 0, 2)
	for i, path := range paths {
		if i == 2 {
			break
		}
		subjects = append(subjects, sftpLogText(path))
	}
	reason := ""
	if err != nil {
		reason = sftpLogText(err.Error())
	}
	s.logger.Info("SFTP permission policy", "outcome", outcome, "operation", op, "subjects", subjects, "fingerprint", sftpLogText(s.clientInfo.Fingerprint), "connection_id", sftpLogText(s.clientInfo.ConnectionID), "request_id", "", "reason", reason)
}
func sftpLogText(text string) string {
	if len(text) > 256 {
		text = text[:256] + "..."
	}
	return strconv.QuoteToASCII(text)
}

// pkg/sftp preserves Error() as the status message and finds the wrapped fxerr
// for its status code. Use its normal reply path, without a separate SSH write.
func sftpPermissionError(err error) error {
	if errors.Is(err, consent.ErrUnavailable) {
		return fmt.Errorf("%w: %s", sftp.ErrSSHFxPermissionDenied, sftpApprovalHint)
	}
	return sftp.ErrSSHFxPermissionDenied
}

func sftpOperationError(ctx context.Context, r *sftp.Request, s *SFTPSession) error {
	if ctx.Err() != nil || r.Context().Err() != nil || s.ctx.Err() != nil {
		return sftp.ErrSSHFxPermissionDenied
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
	arrived := time.Now()
	ctx, cancel := h.session.operationContext(r.Context())
	defer cancel()
	path, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	// Check permission before opening the file.
	if err := h.session.checkPermission(ctx, arrived, consent.OpDownload, path); err != nil {
		h.logger.Info("SFTP download denied", "path", path)
		return nil, sftpPermissionError(err)
	}

	h.logger.Info("SFTP download", "path", path)
	if err := sftpOperationError(ctx, r, h.session); err != nil {
		return nil, err
	}
	return os.Open(path)
}

// sftpFileWriter handles file upload requests
type sftpFileWriter struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileWriter) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	arrived := time.Now()
	ctx, cancel := h.session.operationContext(r.Context())
	defer cancel()
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

	if err := h.session.checkPermission(ctx, arrived, consent.OpUpload, path); err != nil {
		logger.Info("SFTP upload denied")
		return nil, sftpPermissionError(err)
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

	if err := sftpOperationError(ctx, r, h.session); err != nil {
		return nil, err
	}
	return os.OpenFile(path, osFlags, 0644)
}

// sftpFileCmder handles mkdir, remove, rename, etc.
type sftpFileCmder struct {
	session *SFTPSession
	logger  *slog.Logger
}

func (h *sftpFileCmder) Filecmd(r *sftp.Request) error {
	arrived := time.Now()
	ctx, cancel := h.session.operationContext(r.Context())
	defer cancel()
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
	var op consent.Operation
	switch r.Method {
	case "Remove":
		op = consent.OpDelete
	case "Mkdir":
		op = consent.OpMkdir
	case "Rename":
		op = consent.OpRename
	case "Rmdir":
		op = consent.OpRmdir
	case "Symlink":
		op = consent.OpSymlink
	case "Link":
		op = consent.OpLink
	case "Setstat":
		op = consent.OpSetstat
	default:
		h.logger.Info("SFTP unsupported command", "method", r.Method, "path", path)
		return sftp.ErrSSHFxOpUnsupported
	}

	// Check permission - pass both paths for two-path operations
	if isTwoPathOp {
		err = h.session.checkPermission(ctx, arrived, op, path, targetPath)
	} else {
		err = h.session.checkPermission(ctx, arrived, op, path)
	}
	if err != nil {
		h.logger.Info("SFTP command denied", "method", r.Method, "path", path)
		return sftpPermissionError(err)
	}

	h.logger.Info("SFTP command", "method", r.Method, "path", path)

	if err := sftpOperationError(ctx, r, h.session); err != nil {
		return err
	}

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
			if err := sftpOperationError(ctx, r, h.session); err != nil {
				return err
			}
			if err := os.Truncate(path, int64(attrs.Size)); err != nil {
				return err
			}
		}

		// Handle ownership change
		if flags.UidGid {
			if err := sftpOperationError(ctx, r, h.session); err != nil {
				return err
			}
			if err := os.Chown(path, int(attrs.UID), int(attrs.GID)); err != nil {
				return err
			}
		}

		// Handle permission change
		if flags.Permissions {
			if err := sftpOperationError(ctx, r, h.session); err != nil {
				return err
			}
			if err := os.Chmod(path, attrs.FileMode()); err != nil {
				return err
			}
		}

		// Handle timestamp change
		if flags.Acmodtime {
			if err := sftpOperationError(ctx, r, h.session); err != nil {
				return err
			}
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
