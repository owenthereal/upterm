package internal

import (
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"

	hostsftp "github.com/owenthereal/upterm/host/sftp"
	"github.com/pkg/sftp"
)

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
