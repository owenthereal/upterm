package internal

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	gssh "charm.land/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Only descriptor-backed Root implementations are supported. In particular,
// js and plan9 cannot keep this boundary across concurrent namespace changes.
func rootedSFTPSupported() bool {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris", "windows":
		return true
	default:
		return false
	}
}

// This conversion selects a name, never authorizes an ambient filesystem
// operation. Every subsequent access is through Root, even after a rename or
// symlink replacement. Absolute names must lie under the root's declared name.
func rootedSFTPPath(root *os.Root, name string) (string, error) {
	if !rootedSFTPSupported() {
		return "", sftp.ErrSSHFxOpUnsupported
	}
	base, err := filepath.Abs(root.Name())
	if err != nil {
		return "", err
	}
	base = filepath.ToSlash(base)
	if runtime.GOOS == "windows" {
		// pkg/sftp resolves a native drive path as relative to its POSIX
		// start directory. Restore that spelling before checking our root.
		name = undoubleDriveLetter(name)
		base = "/" + base
	}
	if strings.ContainsAny(name, "\\\x00") {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	base = path.Clean(base)
	prefix := strings.TrimSuffix(base, "/") + "/"
	name = path.Clean(name)
	if path.IsAbs(name) {
		switch {
		case name == base:
			name = "."
		case strings.HasPrefix(name, prefix):
			name = strings.TrimPrefix(name, prefix)
		default:
			return "", sftp.ErrSSHFxPermissionDenied
		}
	}
	if !filepath.IsLocal(name) || strings.Contains(name, ":") {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	for _, component := range strings.Split(name, "/") {
		// Reserve Windows device spellings on every platform; a runner's
		// remotely supplied paths must never become devices when moved to Windows.
		stem, _, _ := strings.Cut(strings.ToUpper(strings.TrimRight(component, " .")), ".")
		switch stem {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
			return "", sftp.ErrSSHFxPermissionDenied
		}
		if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
			suffix := []rune(stem[3:])
			if len(suffix) == 1 && strings.ContainsRune("123456789¹²³", suffix[0]) {
				return "", sftp.ErrSSHFxPermissionDenied
			}
		}
	}
	return filepath.FromSlash(name), nil
}

func (h *sftpFileLister) rootedList(r *sftp.Request) (sftp.ListerAt, error) {
	if err := sftpOperationError(r.Context(), r, h.session); err != nil {
		return nil, err
	}
	name, err := h.session.resolvePath(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		dir, err := h.session.root.Open(name)
		if err != nil {
			return nil, err
		}
		defer func() { _ = dir.Close() }()
		// Root-opened directory descriptors keep entry metadata descriptor-
		// relative too; never use ambient ReadDir or lazy pathname Info calls.
		infos, err := dir.Readdir(-1)
		return listerat(infos), err
	case "Stat":
		info, err := h.session.root.Stat(name)
		if err != nil {
			return nil, err
		}
		return listerat{info}, nil
	case "Lstat":
		info, err := h.session.root.Lstat(name)
		if err != nil {
			return nil, err
		}
		return listerat{info}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

type rootedSFTPFileLister struct{ sftpFileLister }

func (h *rootedSFTPFileLister) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return h.Filelist(r)
}

// RealPath only returns the canonical protocol spelling. It does not resolve
// symlinks, and cannot disclose an outside path or bypass the access handlers.
func (h *rootedSFTPFileLister) RealPath(name string) (string, error) {
	rel, err := h.session.resolvePath(name)
	if err != nil {
		return "", err
	}
	base, err := filepath.Abs(h.session.root.Name())
	if err != nil {
		return "", err
	}
	base = filepath.ToSlash(base)
	if runtime.GOOS == "windows" {
		base = "/" + base
	}
	return path.Join(base, filepath.ToSlash(rel)), nil
}

// Closing a channel alone can wait for an unresponsive peer. At host shutdown,
// close the rooted sessions' SSH transports to release both reads and writes.
// A closed admission gate and the final Serve return are both needed: Serve
// joins pkg/sftp workers and closes their handles before the registry releases.
type rootedSFTPWorkers struct {
	mu      sync.Mutex
	stopped bool
	done    chan struct{}
	active  map[chan struct{}]ssh.Conn
}

func (w *rootedSFTPWorkers) admit(sess gssh.Session) (func(), bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	conn, ok := sess.Context().Value(gssh.ContextKeyConn).(ssh.Conn)
	if w.stopped || !ok {
		return nil, false
	}
	if w.done == nil {
		w.done = make(chan struct{})
	}
	if w.active == nil {
		w.active = make(map[chan struct{}]ssh.Conn)
	}
	id := make(chan struct{})
	w.active[id] = conn
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.active, id)
		if w.stopped && len(w.active) == 0 {
			close(w.done)
		}
	}, true
}

func (w *rootedSFTPWorkers) stop() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.stopped = true
	if w.done == nil {
		w.done = make(chan struct{})
	}
	connections := make([]ssh.Conn, 0, len(w.active))
	for _, conn := range w.active {
		connections = append(connections, conn)
	}
	if len(w.active) == 0 {
		close(w.done)
	}
	w.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (s *Server) WaitSFTP(ctx context.Context) error {
	if s.SFTPRoot == nil {
		return nil
	}
	w := &s.sftpWorkers
	w.mu.Lock()
	if w.done == nil {
		w.done = make(chan struct{})
	}
	done := w.done
	w.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
