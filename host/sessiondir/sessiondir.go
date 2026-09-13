// Package sessiondir owns the on-disk identity of a session: which name it
// holds, where its sockets live, whether the process that claimed it is still
// alive, and how it ended.
package sessiondir

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var (
	// ErrNameInUse is returned when a name is held by a live session.
	ErrNameInUse = errors.New("sessiondir: name is in use by a running session")
	// ErrInvalidName is returned for a name that is not a single safe path
	// component.
	ErrInvalidName = errors.New("sessiondir: invalid session name")
)

const (
	// Runtime and state live in distinct sub-namespaces because the two roots
	// are frequently the same directory: utils.UptermRuntimeDir and
	// UptermStateDir both resolve to %LOCALAPPDATA%\upterm on Windows and both
	// fall back to $HOME/.upterm. Without this split, removing a session's
	// runtime directory would delete the completion record beside it.
	sessionsDirName = "sessions"
	resultsDirName  = "results"

	registryLockFile = ".registry.lock"
	sessionLockFile  = "lock"
	adminSocketFile  = "admin.sock"
	attachSocketFile = "attach.sock"
	recordFile       = "session.json"
	logFileName      = "daemon.log"

	registryWaitInitial = time.Millisecond
	registryWaitMax     = 50 * time.Millisecond
)

// nameRe is an allowlist, not a denylist. A name becomes a path component and
// then a target for RemoveAll, so anything that is not obviously safe is
// refused: no separators, no leading dot (which would also let a name collide
// with .registry.lock), and a bounded length.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxNameLen is the length nameRe bounds names to, 1 + 63. Change both together.
const maxNameLen = 64

// ValidateName reports whether name is a single safe path component.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %q must match %s", ErrInvalidName, name, nameRe)
	}
	return nil
}

func sessionsRoot(runtimeRoot string) string { return filepath.Join(runtimeRoot, sessionsDirName) }
func resultsRoot(stateRoot string) string    { return filepath.Join(stateRoot, resultsDirName) }

// SessionsRoot returns the directory session runtime directories live in.
func SessionsRoot(runtimeRoot string) string { return sessionsRoot(runtimeRoot) }

// AdminSocketPath returns a named session's admin socket without claiming it,
// so a caller can look up a session it does not own.
func AdminSocketPath(runtimeRoot, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return filepath.Join(sessionsRoot(runtimeRoot), name, adminSocketFile), nil
}

// ClaimOptions configures a claim.
type ClaimOptions struct {
	RuntimeRoot  string
	StateRoot    string
	Name         string
	Command      []string
	ForceCommand []string
}

// Dir is a claimed session name and the paths that belong to it. The claim
// lasts as long as its lock file stays open.
type Dir struct {
	name      string
	launchID  string
	startedAt time.Time
	runtime   string
	state     string
	lockFile  *os.File

	// mu guards record. Update does read-modify-write in memory rather than
	// against the file, so concurrent updates cannot lose one another.
	mu     sync.Mutex
	record Record
}

func (d *Dir) Name() string         { return d.name }
func (d *Dir) LaunchID() string     { return d.launchID }
func (d *Dir) StartedAt() time.Time { return d.startedAt }
func (d *Dir) AdminSocket() string  { return filepath.Join(d.runtime, adminSocketFile) }
func (d *Dir) AttachSocket() string { return filepath.Join(d.runtime, attachSocketFile) }
func (d *Dir) RecordPath() string   { return filepath.Join(d.state, recordFile) }
func (d *Dir) LogPath() string      { return filepath.Join(d.state, logFileName) }

// Claim takes ownership of a name and publishes its initial state and outcome.
//
// Everything here happens inside one critical section held on a registry lock
// in the parent directory. Two reasons, both learned the hard way:
//
// A lock inside the session directory cannot protect the session directory. A
// reaper can remove the directory after the claimer has locked a file within
// it, leaving the claimer holding a valid lock on an unreachable inode and the
// name free for a third process.
//
// And the initial result must be published before the lock is released. If it
// were written afterwards, a process that claimed the name and then died would
// leave the previous run's exit code sitting there looking current — reporting
// success for a run that never started.
func Claim(ctx context.Context, opts ClaimOptions) (*Dir, error) {
	name := opts.Name
	if name == "" {
		name = GenerateName(opts.Command)
	}
	// Before any filesystem operation: this name becomes a path and then a
	// RemoveAll target.
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	sessRoot := sessionsRoot(opts.RuntimeRoot)
	reg, err := lockRegistry(ctx, sessRoot)
	if err != nil {
		return nil, err
	}
	defer releaseRegistry(reg)

	sessRuntime := filepath.Join(sessRoot, name)
	sessState := filepath.Join(resultsRoot(opts.StateRoot), name)

	if err := os.Mkdir(sessRuntime, 0700); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		// The name exists. It is stale if nobody holds its lock, and stale is
		// recoverable: requiring a manual reap after every crash is not a
		// contract anyone can live with.
		held, err := nameIsHeld(sessRuntime)
		if err != nil {
			return nil, err
		}
		if held {
			return nil, fmt.Errorf("%w: %s", ErrNameInUse, name)
		}
		if err := os.RemoveAll(sessRuntime); err != nil {
			return nil, err
		}
		if err := os.Mkdir(sessRuntime, 0700); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(sessState, 0700); err != nil {
		return nil, err
	}

	lf, err := os.OpenFile(filepath.Join(sessRuntime, sessionLockFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ok, err := tryLock(lf)
	if err != nil || !ok {
		_ = lf.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", ErrNameInUse, name)
	}

	d := &Dir{
		name:      name,
		launchID:  randomHex(8),
		startedAt: time.Now().UTC(),
		runtime:   sessRuntime,
		state:     sessState,
		lockFile:  lf,
	}

	// One publication, so there is no window in which the name is claimed but
	// the previous run's outcome is still what a reader would find.
	if err := d.Update(func(r *Record) {
		r.Command = opts.Command
		r.ForceCommand = opts.ForceCommand
		r.StartedAt = d.startedAt
		r.Status = StatusStarting
		r.Reason = ReasonUnknown
	}); err != nil {
		_ = d.releaseKeepingDir()
		return nil, err
	}

	return d, nil
}

// releaseTimeout bounds how long teardown will wait for the registry lock.
const releaseTimeout = 5 * time.Second

// Release gives the name back and removes the runtime directory. The state
// directory is deliberately left behind: it holds the outcome, which has to
// outlive the session that produced it.
//
// The lock is always dropped, even when the registry lock cannot be had. A
// teardown that can block forever is worse than a directory left behind: the
// directory is reapable by anyone later, whereas a Host.Run that never returns
// is not recoverable from outside. ctx bounds the wait; the caller may pass a
// shorter one.
func (d *Dir) Release(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()

	// The session lock is held across the registry acquisition, and released
	// only once we are inside the registry's critical section.
	//
	// An earlier draft unlocked first, "because the name needs no registry lock
	// to release". That opened a window: we unlock, a replacement claims the
	// name and recreates the directory, we then acquire the registry lock and
	// RemoveAll — deleting the replacement's directory out from under a live
	// session. Holding the session lock until we own the registry means no
	// replacement can exist to delete.
	//
	// This does not deadlock against Claim. Claim takes the registry lock first
	// and only then tests session locks, and that test is non-blocking: a
	// claimer that meets our held lock reports ErrNameInUse immediately rather
	// than waiting on it.
	reg, err := lockRegistry(ctx, filepath.Dir(d.runtime))
	if err != nil {
		// Give the name back without removing anything. The directory is left
		// for the next Claim or Reap, which is recoverable; a teardown that
		// blocks forever is not.
		_ = unlock(d.lockFile)
		_ = d.lockFile.Close()
		return fmt.Errorf("sessiondir: leaving %s for later reaping: %w", d.runtime, err)
	}
	defer releaseRegistry(reg)

	_ = unlock(d.lockFile)
	_ = d.lockFile.Close()
	return os.RemoveAll(d.runtime)
}

// Inspect reads a name's record and ownership as one observation.
//
// Both under the registry lock, because they are two facts about one thing and
// a caller that reads them separately can mix generations: read A's record,
// then observe B's ownership. Under the lock a name is either unclaimed or
// fully published, since Claim holds the lock across mkdir, lock and the
// initial publication — so held implies rec != nil, and a caller need not
// defend against a record that vanished between the two reads.
func Inspect(ctx context.Context, runtimeRoot, stateRoot, name string) (rec *Record, held bool, err error) {
	if err := ValidateName(name); err != nil {
		return nil, false, err
	}

	sessRoot := sessionsRoot(runtimeRoot)
	reg, err := lockRegistry(ctx, sessRoot)
	if err != nil {
		return nil, false, err
	}
	defer releaseRegistry(reg)

	path := filepath.Join(sessRoot, name)
	if _, statErr := os.Stat(path); statErr == nil {
		held, err = nameIsHeld(path)
		if err != nil {
			return nil, false, err
		}
	} else if !os.IsNotExist(statErr) {
		return nil, false, statErr
	}

	rec, err = readRecordLocked(stateRoot, name)
	if err != nil && !os.IsNotExist(err) {
		return nil, held, err
	}
	if os.IsNotExist(err) {
		rec, err = nil, nil
	}

	return rec, held, err
}

// releaseKeepingDir drops the lock without removing anything, leaving exactly
// what a crashed process leaves. It exists for tests and for the failure paths
// in Claim.
func (d *Dir) releaseKeepingDir() error {
	if err := unlock(d.lockFile); err != nil {
		return err
	}
	return d.lockFile.Close()
}

// Reap removes session directories whose owner is gone.
func Reap(ctx context.Context, runtimeRoot string) error {
	sessRoot := sessionsRoot(runtimeRoot)
	reg, err := lockRegistry(ctx, sessRoot)
	if err != nil {
		return err
	}
	defer releaseRegistry(reg)

	entries, err := os.ReadDir(sessRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, e := range entries {
		if !e.IsDir() || ValidateName(e.Name()) != nil {
			continue
		}
		path := filepath.Join(sessRoot, e.Name())
		held, err := nameIsHeld(path)
		if err != nil || held {
			continue
		}
		_ = os.RemoveAll(path)
	}

	return nil
}

// nameIsHeld reports whether a session directory's lock is held. Only valid
// with the registry lock held.
func nameIsHeld(sessRuntime string) (bool, error) {
	lf, err := os.OpenFile(filepath.Join(sessRuntime, sessionLockFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer func() { _ = lf.Close() }()

	ok, err := tryLock(lf)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	_ = unlock(lf)
	return false, nil
}

// lockRegistry waits for the registry lock, backing off and honouring ctx.
//
// The critical sections it guards are a handful of syscalls, so contention is
// rare and brief — but "rare and brief" is not "never", and a suspended owner
// would otherwise spin a caller at full tilt forever.
func lockRegistry(ctx context.Context, sessRoot string) (*os.File, error) {
	if err := os.MkdirAll(sessRoot, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(sessRoot, registryLockFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	wait := registryWaitInitial
	for {
		ok, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if ok {
			return f, nil
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			return nil, fmt.Errorf("sessiondir: waiting for the session registry lock: %w", ctx.Err())
		case <-timer.C:
		}

		if wait < registryWaitMax {
			wait *= 2
		}
	}
}

func releaseRegistry(f *os.File) {
	_ = unlock(f)
	_ = f.Close()
}

// GenerateName derives a readable, collision-resistant name from a command. It
// always returns something ValidateName accepts.
func GenerateName(command []string) string {
	base := "session"
	if len(command) > 0 && command[0] != "" {
		if b := filepath.Base(command[0]); ValidateName(b) == nil {
			base = b
		}
	}
	// The suffix costs "-" plus four hex characters, so a basename that is
	// itself at the limit would push the result past it and Claim would then
	// reject a name the caller never chose. nameRe admits only ASCII, so
	// cutting bytes cannot split a character.
	if len(base) > maxNameLen-5 {
		base = base[:maxNameLen-5]
	}
	return fmt.Sprintf("%s-%s", base, randomHex(2))
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Falling back to a timestamp keeps this total. Claim reports a
		// collision rather than clobbering, so a weak suffix is recoverable.
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n*2]
	}
	return hex.EncodeToString(b)
}
