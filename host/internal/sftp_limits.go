package internal

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/sftp"
)

// SFTPWriteLimits optionally restricts rooted uploads for one host lifetime.
// Files maps canonical relative names to both their maximum logical extent
// and cumulative accepted write bytes. TotalBytes bounds accepted writes
// across all names. Each name permits only one writable OPEN, including a
// failed OPEN; close, remove, truncation and reconnect never reset allowances.
// Configure before Run/Serve. The server copies the declaration before use.
type SFTPWriteLimits struct {
	Files      map[string]int64
	TotalBytes int64
}

// CopySFTPWriteLimits validates and snapshots the caller's declaration before
// host startup can serve or publish anything. Nil preserves ordinary behavior.
func CopySFTPWriteLimits(root *os.Root, limits *SFTPWriteLimits) (*SFTPWriteLimits, error) {
	if limits == nil {
		return nil, nil
	}
	if root == nil {
		return nil, fmt.Errorf("SFTPWriteLimits requires SFTPRoot")
	}
	if limits.TotalBytes < 0 {
		return nil, fmt.Errorf("SFTPWriteLimits: negative total byte limit")
	}
	copy := &SFTPWriteLimits{Files: make(map[string]int64, len(limits.Files)), TotalBytes: limits.TotalBytes}
	for name, size := range limits.Files {
		rel, err := rootedSFTPPath(root, name)
		if err != nil || name == "." || filepath.ToSlash(rel) != name || size < 0 {
			return nil, fmt.Errorf("SFTPWriteLimits: invalid relative file or byte limit %q", name)
		}
		copy.Files[name] = size
	}
	return copy, nil
}

// All sessions and transports of a Server share this state. In particular it
// must not be constructed in HandleSFTP, where reconnect would replenish it.
type rootedSFTPWriteLimits struct {
	mu        sync.Mutex
	files     map[string]*sftpFileAllowance
	remaining int64
}

type sftpFileAllowance struct {
	limit, remaining int64
	opened           bool
}

func newRootedSFTPWriteLimits(root *os.Root, limits *SFTPWriteLimits) (*rootedSFTPWriteLimits, error) {
	declaration, err := CopySFTPWriteLimits(root, limits)
	if err != nil || declaration == nil {
		return nil, err
	}
	state := &rootedSFTPWriteLimits{files: make(map[string]*sftpFileAllowance, len(declaration.Files)), remaining: declaration.TotalBytes}
	for name, size := range declaration.Files {
		state.files[filepath.FromSlash(name)] = &sftpFileAllowance{limit: size, remaining: size}
	}
	return state, nil
}

func (s *rootedSFTPWriteLimits) open(root *os.Root, name string, flags int) (io.WriterAt, error) {
	s.mu.Lock()
	allowance, allowed := s.files[name]
	if !allowed || allowance.opened || flags&os.O_CREATE == 0 || flags&os.O_APPEND != 0 || flags&(os.O_TRUNC|os.O_EXCL) == 0 {
		s.mu.Unlock()
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	// Claim before filesystem access, never recycle even after an open error.
	allowance.opened = true
	s.mu.Unlock()
	f, err := root.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	return &limitedSFTPWriter{file: f, limits: s, allowance: allowance}, nil
}

type limitedSFTPWriter struct {
	file      *os.File
	limits    *rootedSFTPWriteLimits
	allowance *sftpFileAllowance
}

func (w *limitedSFTPWriter) WriteAt(p []byte, offset int64) (int, error) {
	size := int64(len(p))
	w.limits.mu.Lock()
	if offset < 0 || offset > w.allowance.limit || size > w.allowance.limit-offset ||
		size > w.allowance.remaining || size > w.limits.remaining {
		w.limits.mu.Unlock()
		return 0, sftp.ErrSSHFxPermissionDenied
	}
	w.allowance.remaining -= size
	w.limits.remaining -= size
	w.limits.mu.Unlock()
	// Reserve before I/O, without refund on a short or failed write. This
	// remains safe for concurrent writes and deleted-but-still-open handles.
	return w.file.WriteAt(p, offset)
}

func (w *limitedSFTPWriter) Close() error { return w.file.Close() }
