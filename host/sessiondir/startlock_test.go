package sessiondir

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testDelegationService = "https://authority.example"
	testDelegationAccount = "11111111-1111-4111-8111-111111111111"
)

// One start of a delegated name at a time: another start of it waits for
// the lock for as long as its context lets it, and gets it once it is let go.
// Starts of another name, account or service never wait on it.
func TestStartLockKeepsStartsApart(t *testing.T) {
	_, stateRoot := roots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	held, err := LockDelegatedStart(ctx, stateRoot, testDelegationService, testDelegationAccount, "work")
	require.NoError(t, err)

	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelShort()
	_, err = LockDelegatedStart(short, stateRoot, testDelegationService, testDelegationAccount, "work")
	require.ErrorIs(t, err, context.DeadlineExceeded, "a second start of the name waits for the first")
	require.ErrorContains(t, err, "waiting for the delegated start lock "+filepath.Join(stateRoot, "delegated", "locks")+string(filepath.Separator))

	for _, other := range [][3]string{
		{testDelegationService, testDelegationAccount, "home"},
		{testDelegationService, "22222222-2222-4222-8222-222222222222", "work"},
		{"https://other.example", testDelegationAccount, "work"},
	} {
		l, err := LockDelegatedStart(ctx, stateRoot, other[0], other[1], other[2])
		require.NoError(t, err, "%v waits for no other name's start", other)
		require.NoError(t, l.Release())
	}

	next := make(chan error, 1)
	go func() {
		l, err := LockDelegatedStart(ctx, stateRoot, testDelegationService, testDelegationAccount, "work")
		if err == nil {
			err = l.Release()
		}
		next <- err
	}()
	require.NoError(t, held.Release())
	select {
	case err := <-next:
		require.NoError(t, err, "a released lock is the next start's")
	case <-time.After(5 * time.Second):
		t.Fatal("the next start never got the released lock")
	}
}

// The lock is a file of the state root's, named by the name it is for, in
// directories only this user can reach.
func TestStartLockLivesUnderTheStateRoot(t *testing.T) {
	_, stateRoot := roots(t)
	l, err := LockDelegatedStart(context.Background(), stateRoot, testDelegationService, testDelegationAccount, "work")
	require.NoError(t, err)
	defer func() { require.NoError(t, l.Release()) }()

	sum := sha256.Sum256([]byte(testDelegationService + "\n" + testDelegationAccount + "\nwork"))
	_, err = os.Stat(filepath.Join(stateRoot, "delegated", "locks", hex.EncodeToString(sum[:])+".lock"))
	require.NoError(t, err)
	if runtime.GOOS == "windows" {
		return
	}
	for _, dir := range []string{filepath.Join(stateRoot, "delegated"), filepath.Join(stateRoot, "delegated", "locks")} {
		info, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm(), dir)
	}
}
