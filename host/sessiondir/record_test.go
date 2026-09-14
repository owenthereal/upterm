package sessiondir

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Result_RoundTrip(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	code := 42
	require.NoError(t, d.Update(func(r *Record) {
		r.SessionID = "abc"
		r.FinishedAt = time.Now().UTC()
		r.Status = StatusEnding
		r.Reason = ReasonExited
		r.ExitCode = &code
	}))

	got, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, ReasonExited, got.Reason)
	require.Equal(t, StatusEnding, got.Status)
	require.Equal(t, d.LaunchID(), got.LaunchID)
	require.NotNil(t, got.ExitCode)
	require.Equal(t, 42, *got.ExitCode)

	// Update is read-modify-write against the in-memory copy, so a field set
	// by an earlier update survives a later one that does not mention it.
	require.Equal(t, []string{"bash"}, got.Command)
}

func Test_Result_SurvivesRelease(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	require.NoError(t, d.Release(context.Background()))

	got, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err, "the outcome must outlive the session that produced it")
	require.Equal(t, ReasonUnknown, got.Reason)
}

func Test_Record_PublicationIsAtomicUnderAConcurrentReader(t *testing.T) {
	// Review fix: the previous version of this test had no concurrent reader,
	// so its name promised more than it checked. Atomicity is only observable
	// against someone reading while you write.
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	stop := make(chan struct{})
	bad := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec, err := ReadRecord(stateRoot, "demo")
			if err != nil {
				// A reader may never see a half-written or absent record
				// while the session is live.
				select {
				case bad <- err.Error():
				default:
				}
				return
			}
			if rec.Status != StatusStarting && rec.Status != StatusReady {
				select {
				case bad <- "unexpected status " + rec.Status:
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 500; i++ {
		status := StatusReady
		if i%2 == 0 {
			status = StatusStarting
		}
		require.NoError(t, d.Update(func(r *Record) { r.Status = status }))
	}

	close(stop)
	<-done

	select {
	case msg := <-bad:
		t.Fatalf("concurrent reader observed a torn or missing record: %s", msg)
	default:
	}

	_, err = os.Stat(d.RecordPath() + ".tmp")
	require.True(t, os.IsNotExist(err), "no temporary file may be left behind")
}

func Test_ReadRecord_DuringNameReuseNeverMixesLaunches(t *testing.T) {
	// The failure one file exists to prevent: a reader must never combine a
	// new launch's status with a previous launch's exit code.
	runtimeRoot, stateRoot := roots(t)

	first, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	code := 0
	require.NoError(t, first.Update(func(r *Record) {
		r.Status = StatusEnding
		r.Reason = ReasonExited
		r.ExitCode = &code
	}))
	firstLaunch := first.LaunchID()
	require.NoError(t, first.Release(context.Background()))

	stop := make(chan struct{})
	bad := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec, err := ReadRecord(stateRoot, "demo")
			if err != nil {
				continue
			}
			// Whatever launch it is, its fields must be that launch's.
			if rec.LaunchID == firstLaunch {
				if rec.Reason != ReasonExited || rec.ExitCode == nil {
					select {
					case bad <- "first launch seen without its outcome":
					default:
					}
					return
				}
			} else if rec.ExitCode != nil {
				select {
				case bad <- "new launch seen carrying the previous exit code":
				default:
				}
				return
			}
		}
	}()

	second, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	close(stop)
	<-done
	require.NoError(t, second.Release(context.Background()))

	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
}

func Test_Inspect_LivenessComesFromTheLockNotTheRecord(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	ctx := context.Background()

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)

	rec, held, err := Inspect(ctx, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	require.True(t, held)
	require.NotNil(t, rec, "held implies a published record, since Claim publishes under the lock")

	// A SIGKILL leaves the record saying whatever was last written, which may
	// well be "ready". Only the lock knows the process is gone.
	require.NoError(t, d.Update(func(r *Record) { r.Status = StatusReady }))
	require.NoError(t, d.releaseKeepingDir())

	rec, held, err = Inspect(ctx, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, StatusReady, rec.Status, "the stale record still claims ready")
	require.False(t, held, "liveness must come from the lock, not the record")

	rec, held, err = Inspect(ctx, runtimeRoot, stateRoot, "never-existed")
	require.NoError(t, err)
	require.False(t, held)
	require.Nil(t, rec, "a name that never existed yields no record, not an error")
}

func Test_Inspect_SeesAHolderUnderAnotherRuntimeRoot(t *testing.T) {
	// A reader that shares only the state root still has to see the holder,
	// or it reports the live session's record as nobody's and offers the name.
	runtimeA, runtimeB, stateRoot := splitRoots(t)
	ctx := context.Background()

	a, err := claim(t, runtimeA, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = a.Release(ctx) }()

	rec, held, err := Inspect(ctx, runtimeB, stateRoot, "demo")
	require.NoError(t, err)
	require.True(t, held, "a name held under another runtime root is held")
	require.NotNil(t, rec, "held implies a readable record, across roots as within one")
	require.Equal(t, StatusStarting, rec.Status)
}

func Test_Release_DoesNotDeleteAReplacement(t *testing.T) {
	// The interleaving that an unlock-before-registry-lock ordering allows:
	// A unlocks, B claims and recreates the directory, A then acquires the
	// registry lock and removes B's directory out from under it.
	runtimeRoot, stateRoot := roots(t)
	ctx := context.Background()

	a, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)

	// Hold the registry lock so A's Release blocks after it has committed to
	// releasing but before it can remove anything. This is the window.
	reg, err := lockRegistry(ctx, sessionsRoot(runtimeRoot))
	require.NoError(t, err)

	releaseErr := make(chan error, 1)
	go func() { releaseErr <- a.Release(ctx) }()

	// While A is blocked, B must not be able to claim: A still holds the
	// session lock, which is the property that makes the interleaving
	// impossible rather than merely unlikely.
	time.Sleep(50 * time.Millisecond)
	held, err := lockIsHeld(filepath.Join(sessionsRoot(runtimeRoot), "demo", sessionLockFile))
	require.NoError(t, err)
	require.True(t, held, "the session lock must be held until the registry lock is acquired")

	releaseRegistry(reg)
	require.NoError(t, <-releaseErr)

	b, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = b.Release(ctx) }()

	// B's directory and record survive.
	_, err = os.Stat(filepath.Join(sessionsRoot(runtimeRoot), "demo"))
	require.NoError(t, err)
	recB, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, b.LaunchID(), recB.LaunchID)
}

func Test_ReadResult_MissingIsNotFound(t *testing.T) {
	_, stateRoot := roots(t)

	_, err := ReadRecord(stateRoot, "never-ran")
	require.True(t, os.IsNotExist(err),
		"an absent record means not found within retained history, which is a lookup failure and distinct from a recorded unknown")
}
