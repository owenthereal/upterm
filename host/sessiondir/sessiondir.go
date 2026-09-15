// Package sessiondir owns the on-disk identity of a session: which name it
// holds, where its sockets live, whether the process that claimed it is still
// alive, and how it ended.
//
// A name is owned on both roots, not just the runtime one. The two roots move
// independently: on Linux a login session and a cron job get different
// XDG_RUNTIME_DIRs and the same state directory, so a name guarded only under
// RuntimeRoot would let two hosts each hold "their" lock and publish into one
// results/<name>/session.json — and once the first ended, its exit code is
// what a reader finds for the second, still running.
//
// So there are two registry locks, and exactly one order between them: the
// sessions registry (RuntimeRoot/sessions/.registry.lock) is taken before the
// results registry (StateRoot/results/.registry.lock), and no function takes
// the sessions registry while holding the results registry. Claim takes both,
// in that order; Release and Reap take only the sessions registry; Inspect and
// Prune take only the results registry, which is why neither is given a
// runtime root at all. A per-name lock is only ever acquired under the
// registry that guards the directory it lives in, because a lock inside a
// directory cannot protect that directory from removal.
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
	// ErrSocketPathTooLong is returned when a name is legal but would put the
	// session's sockets past what a unix socket address can hold.
	ErrSocketPathTooLong = errors.New("sessiondir: session socket path is too long")
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
	// resultLockFile may share sessionLockFile's name because the two live in
	// different directories, one per root, even when the roots coincide.
	resultLockFile   = "lock"
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

// maxSocketPath is the longest a unix socket path may be, in bytes.
//
// darwin's sun_path is a 104-byte buffer that must also hold the terminating
// NUL, so 103 is the longest path that actually binds there; linux and
// windows' AF_UNIX allow 107 the same way, out of a 108-byte buffer. One
// constant, the tightest, governs every platform — a name that works on Linux
// and fails on macOS is a worse contract than one refused everywhere.
const maxSocketPath = 103

// maxGeneratedBase bounds the basename a generated name is built from. Far
// below maxNameLen on purpose: a default name the user never chose must never
// be the thing that pushes a session's sockets past maxSocketPath, and the
// runtime root those paths sit under is not something GenerateName can see.
const maxGeneratedBase = 20

// ValidateName reports whether name is a single safe path component.
func ValidateName(name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: %q is longer than %d bytes", ErrInvalidName, name, maxNameLen)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %q must match %s", ErrInvalidName, name, nameRe)
	}
	return nil
}

// CheckSocketPath reports whether a name's sockets would fit in a unix socket
// address under runtimeRoot. The name is expected to have passed ValidateName
// already.
//
// It measures attach.sock, the longest name a session puts in its directory,
// rather than admin.sock, the one bound first. Both hang off the same parent,
// so the shorter fitting says nothing about the longer: a name checked against
// admin.sock could be accepted here and still be one byte too long to bind,
// with the name already claimed and its directory already made. One byte of
// name is the whole cost, and the error quotes the path it measured so that
// byte is visible to whoever has to shorten something.
//
// Length is a property of the name *and* where it lives, so it cannot be
// folded into ValidateName: the same name is fine under /run/user/1000 and
// impossible under ~/Library/Application Support. It is exported so the CLI
// can refuse an over-long --name at flag validation, because the alternative
// is a bind failure minutes later, after the tunnel is already up.
func CheckSocketPath(runtimeRoot, name string) error {
	path := filepath.Join(sessionsRoot(runtimeRoot), name, attachSocketFile)
	if len(path) > maxSocketPath {
		return fmt.Errorf("%w: %q gives %d bytes, limit %d", ErrSocketPathTooLong, path, len(path), maxSocketPath)
	}
	return nil
}

func sessionsRoot(runtimeRoot string) string { return filepath.Join(runtimeRoot, sessionsDirName) }
func resultsRoot(stateRoot string) string    { return filepath.Join(stateRoot, resultsDirName) }

// SessionsRoot returns the directory session runtime directories live in.
func SessionsRoot(runtimeRoot string) string { return sessionsRoot(runtimeRoot) }

// ResultsRoot returns the directory session records live in, which is where
// ListLive finds the sessions that exist. Exported for the reason SessionsRoot
// is: `session list` says in its help where the names it prints came from, and
// that is this directory rather than any one runtime root.
func ResultsRoot(stateRoot string) string { return resultsRoot(stateRoot) }

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
// lasts as long as its two lock files stay open: one per root, because a name
// is owned on both. See the package comment for the order they are taken in.
type Dir struct {
	name       string
	launchID   string
	startedAt  time.Time
	runtime    string
	state      string
	lockFile   *os.File
	resultLock *os.File

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
//
// The same two reasons apply to the results side, which is claimed the same
// way under its own registry: the name is not ours until both roots say so,
// and the record is published before either registry is given back.
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
	// Also before any filesystem operation, and for a related reason: a name
	// whose sockets cannot be bound is unusable, and finding that out at bind
	// time means finding it out after the tunnel is up, with the name already
	// claimed. Refusing here leaves nothing behind.
	if err := CheckSocketPath(opts.RuntimeRoot, name); err != nil {
		return nil, err
	}

	sessRoot := sessionsRoot(opts.RuntimeRoot)
	reg, err := lockRegistry(ctx, sessRoot)
	if err != nil {
		return nil, err
	}
	defer releaseRegistry(reg)

	sessRuntime := filepath.Join(sessRoot, name)

	if err := os.Mkdir(sessRuntime, 0700); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		// The name exists. It is stale if nobody holds its lock, and stale is
		// recoverable: requiring a manual reap after every crash is not a
		// contract anyone can live with.
		held, err := lockIsHeld(filepath.Join(sessRuntime, sessionLockFile))
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
	// The runtime lock is ours from here until the Dir below takes ownership of
	// it, so every failure in between has to hand it back.
	dropRuntimeLock := func() {
		_ = unlock(lf)
		_ = lf.Close()
	}

	// The results registry, taken second and — by the order of these defers —
	// released first. Holding it across the results lock and the initial
	// publication is what makes the record side of the name atomic: a reader
	// under any runtime root sees the name unclaimed or fully published, never
	// mid-claim.
	resRoot := resultsRoot(opts.StateRoot)
	resReg, err := lockRegistry(ctx, resRoot)
	if err != nil {
		dropRuntimeLock()
		return nil, err
	}
	defer releaseRegistry(resReg)

	sessState := filepath.Join(resRoot, name)
	if err := os.MkdirAll(sessState, 0700); err != nil {
		dropRuntimeLock()
		return nil, err
	}

	rlf, err := os.OpenFile(filepath.Join(sessState, resultLockFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		dropRuntimeLock()
		return nil, err
	}
	ok, err = tryLock(rlf)
	if err != nil || !ok {
		_ = rlf.Close()
		dropRuntimeLock()
		// Nothing can have claimed the runtime directory we just made — the
		// sessions registry is still held — so removing it leaves a refused
		// claim with nothing behind, rather than a directory that will look
		// stale to the next reaper.
		_ = os.RemoveAll(sessRuntime)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", ErrNameInUse, name)
	}

	d := &Dir{
		name:       name,
		launchID:   randomHex(8),
		startedAt:  time.Now().UTC(),
		runtime:    sessRuntime,
		state:      sessState,
		lockFile:   lf,
		resultLock: rlf,
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

// Release gives the name back on both roots and removes the runtime directory.
// The results directory is deliberately left behind, only its lock dropped: it
// holds the outcome, which has to outlive the session that produced it, and it
// goes when Prune finds it old enough rather than when the session ends.
//
// Call it at most once, and call nothing else on the Dir afterwards. Both
// rules exist because the name is free the instant this returns and a
// successor may already own it: a second Release would RemoveAll the
// successor's directory, and an Update after Release would overwrite the
// successor's record with this run's outcome. Neither is detectable from
// here — the successor's files are at the same paths, which is the point of a
// name — so the ordering is the caller's to keep.
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
		_ = d.dropLocks()
		return fmt.Errorf("sessiondir: leaving %s for later reaping: %w", d.runtime, err)
	}
	defer releaseRegistry(reg)

	_ = unlock(d.lockFile)
	_ = d.lockFile.Close()
	err = os.RemoveAll(d.runtime)

	// The results lock goes last, and needs no registry of its own: it only
	// ever protects the results directory from a Prune, and Prune removes a
	// directory only after finding its lock free. Dropping it after the
	// runtime directory is gone means the name is never observably free on the
	// results side while this run's directory still exists.
	_ = unlock(d.resultLock)
	_ = d.resultLock.Close()
	return err
}

// dropLocks gives both halves of the name back, whatever either one does. A
// name left held on one root and free on the other is exactly the split this
// package's two locks exist to prevent, so a failure on one side must not skip
// the other.
func (d *Dir) dropLocks() error {
	err := unlock(d.lockFile)
	if cerr := d.lockFile.Close(); err == nil {
		err = cerr
	}
	if rerr := unlock(d.resultLock); err == nil {
		err = rerr
	}
	if cerr := d.resultLock.Close(); err == nil {
		err = cerr
	}
	return err
}

// Inspect reads a name's record and ownership as one observation.
//
// Both under the results registry lock, because they are facts about one thing
// and a caller that reads them separately can mix generations: read A's
// record, then observe B's ownership. Under that lock a name is either
// unclaimed or fully published, since Claim holds the results registry across
// the results lock and the initial publication — so held implies rec != nil,
// and a caller need not defend against a record that vanished between the two
// reads.
//
// Ownership is the lock beside the record and nothing else. That lock is held
// by whoever is publishing into this record, whatever runtime root they
// claimed under, which is why a holder this caller cannot otherwise see is
// still reported. The runtime lock cannot stand in for it and is not
// consulted: it says only that *someone* holds this name under this runtime
// root, and that someone may be a different session with a different state
// root. Taking the disjunction of the two let a fresh claim under (R, stateA)
// lend its liveness to a SIGKILLed session's record under (R, stateB), which
// reported a dead session as ready and its name as held by it.
//
// So there is no runtime root in this signature. One used to be taken, for
// symmetry with Claim, and read by nothing: a parameter this function may not
// consult is an invitation to go back to consulting it.
func Inspect(ctx context.Context, stateRoot, name string) (rec *Record, held bool, err error) {
	if err := ValidateName(name); err != nil {
		return nil, false, err
	}

	resRoot := resultsRoot(stateRoot)
	resReg, err := lockRegistry(ctx, resRoot)
	if err != nil {
		return nil, false, err
	}
	defer releaseRegistry(resReg)

	// A missing results directory, or a missing lock inside one, is nobody's:
	// lockIsHeld reports that rather than failing, and a name with no record
	// here is a name this state root has never seen published.
	held, err = lockIsHeld(filepath.Join(resRoot, name, resultLockFile))
	if err != nil {
		return nil, false, err
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

// ListLive returns the record of every session that exists right now, in name
// order.
//
// The set is the names whose results lock is held, because that lock is the
// one thing every live session has wherever it was started: a host under a
// different XDG_RUNTIME_DIR — which Linux gives a login session and denies a
// cron job — publishes into the same results root and leaves nothing under
// this one. A caller that walked a runtime root instead would answer "no
// sessions" for a session it could then look up by name.
//
// Held names only, and ownership comes from the lock for the reason Inspect
// gives: a record says what its owner last published, which after a SIGKILL is
// frequently "ready".
//
// One bad entry is not a failed listing, the same way it is not a failed
// Prune: a record that cannot be read or parsed is skipped, since a listing
// that fails entirely over one unreadable name tells the user less than one
// that is short by a row.
func ListLive(ctx context.Context, stateRoot string) ([]Record, error) {
	resRoot := resultsRoot(stateRoot)
	resReg, err := lockRegistry(ctx, resRoot)
	if err != nil {
		return nil, err
	}
	defer releaseRegistry(resReg)

	entries, err := os.ReadDir(resRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var live []Record
	for _, e := range entries {
		if !e.IsDir() || ValidateName(e.Name()) != nil {
			continue
		}
		held, err := lockIsHeld(filepath.Join(resRoot, e.Name(), resultLockFile))
		if err != nil || !held {
			continue
		}
		rec, err := readRecordLocked(stateRoot, e.Name())
		if err != nil {
			continue
		}
		live = append(live, *rec)
	}

	return live, nil
}

// releaseKeepingDir drops both locks without removing anything, leaving
// exactly what a crashed process leaves — a crash drops every lock the process
// held, on both roots. It exists for tests and for the failure paths in Claim.
func (d *Dir) releaseKeepingDir() error { return d.dropLocks() }

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
		held, err := lockIsHeld(filepath.Join(path, sessionLockFile))
		if err != nil || held {
			continue
		}
		_ = os.RemoveAll(path)
	}

	return nil
}

// lockIsHeld reports whether the lock file at path is held by someone else. It
// serves both roots, and is only valid with that root's registry lock held.
//
// A name with no directory under this root is nobody's, which is the answer a
// caller wants rather than the ENOENT that creating the lock file under a
// missing parent would give: a session claimed under another runtime root has
// no directory under this one.
func lockIsHeld(path string) (bool, error) {
	lf, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
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
func lockRegistry(ctx context.Context, root string) (*os.File, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, registryLockFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
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
			// Named: this guards both the sessions and the results registry,
			// and a caller timing out needs to know which one is contended
			// rather than a fixed phrase that is wrong for half its callers.
			return nil, fmt.Errorf("sessiondir: waiting for the registry lock %s: %w", path, ctx.Err())
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
	// Cut to maxGeneratedBase rather than to what nameRe would still accept.
	// Staying inside ValidateName is not enough: the name also becomes a path
	// under a runtime root of unknown depth, and a default name the caller
	// never chose must not be what makes Claim refuse the session. nameRe
	// admits only ASCII, so cutting bytes cannot split a character.
	if len(base) > maxGeneratedBase {
		base = base[:maxGeneratedBase]
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
