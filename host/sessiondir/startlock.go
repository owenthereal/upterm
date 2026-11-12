package sessiondir

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// The directories, under the state root, that hold the delegated start
// locks, created and secured as a session directory is: only this user can
// reach them.
const (
	delegatedDirName      = "delegated"
	delegatedLocksDirName = "locks"
)

// StartLock is a held start lock of one delegated name.
type StartLock struct{ f *os.File }

// LockDelegatedStart waits for the start lock of the delegated session name,
// of account on service, honouring ctx, and holds it until Release. service,
// account and name must hold no line feed.
//
// A start of a name holds it while it looks for a session running here as
// that name and until its own session is published in its record, where the
// next start looks. Without it, two starts could each find no session
// running and the second replace the first, whose delegation had not been
// published yet. One lock per name, under the state root, because that is
// where every session's record is, whatever runtime root it was started
// under.
//
// The lock is the process's, not the file's: one whose holder was killed, or
// is gone with a reboot, is free again, whatever the file says. So the file
// is never removed, for the reason a registry lock's isn't: a start waiting
// on it would be left holding a lock on a file the next start can't see.
func LockDelegatedStart(ctx context.Context, stateRoot, service, account, name string) (*StartLock, error) {
	if stateRoot == "" || service == "" || account == "" || name == "" {
		return nil, errors.New("a delegated start lock needs a state root, a service, an account and a name")
	}
	dir, err := makeDelegatedLockDir(stateRoot)
	if err != nil {
		return nil, err
	}
	// Named by the hash so that no field can make it a path, with a newline
	// between the fields, which a caller's service, account and name must
	// not contain: with one, two names could share a file.
	sum := sha256.Sum256([]byte(service + "\n" + account + "\n" + name))
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := waitLock(ctx, f, "the delegated start lock "+path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &StartLock{f: f}, nil
}

// Release lets the next start of the name go. Call it once.
func (l *StartLock) Release() error {
	err := unlock(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// makeDelegatedLockDir creates the directory the delegated start locks live
// in, and the directory above it, each 0700 and secured as a session
// directory is, and returns it. One that exists is used as it is.
func makeDelegatedLockDir(stateRoot string) (string, error) {
	if err := os.MkdirAll(stateRoot, 0700); err != nil {
		return "", err
	}
	dir := stateRoot
	for _, name := range []string{delegatedDirName, delegatedLocksDirName} {
		dir = filepath.Join(dir, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			if !os.IsExist(err) {
				return "", err
			}
			continue
		}
		if err := secureSessionDir(dir); err != nil {
			_ = os.Remove(dir)
			return "", err
		}
	}
	return dir, nil
}
