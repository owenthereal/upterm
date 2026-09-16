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

// Test_Record_CarriesTheAdminSocketPath pins that the record says where the
// session's admin socket is, from the first publish on. The record is the one
// thing a reader under another runtime root shares with the session, and the
// path is fixed the moment the name is claimed, so there is no publish that
// could honestly leave it out.
func Test_Record_CarriesTheAdminSocketPath(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	rec, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, d.AdminSocket(), rec.AdminSocket,
		"the path is known when the name is claimed and published with it")

	// Forced the way Name and LaunchID are, not merely defaulted: a publisher
	// that writes a wrong path is overruled, not just one that blanks it, so
	// no Update can leave a reader with any path but the one the claim made.
	// A set-when-empty implementation would pass the blank case and fail
	// this one.
	require.NoError(t, d.Update(func(r *Record) {
		r.AdminSocket = "/nowhere/sessions/demo/admin.sock"
		r.Status = StatusReady
	}))
	rec, err = ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, d.AdminSocket(), rec.AdminSocket)
	require.Equal(t, StatusReady, rec.Status, "the rest of the update still lands")
}

// Test_Record_AttachSocketIsForcedOnEveryPublish pins that AttachSocket is
// republished on every Update the way AdminSocket is: a publisher that writes
// a wrong path is overruled, not just one that blanks it.
func Test_Record_AttachSocketIsForcedOnEveryPublish(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "attach-sock")
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Release(context.Background()) })

	require.NoError(t, d.Update(func(r *Record) { r.AttachSocket = "/nowhere/attach.sock" }))

	rec, err := ReadRecord(stateRoot, "attach-sock")
	require.NoError(t, err)
	require.Equal(t, d.AttachSocket(), rec.AttachSocket,
		"a publisher must not be able to leave the attach socket out or wrong")
	require.Equal(t, filepath.Join(filepath.Dir(rec.AdminSocket), "attach.sock"), rec.AttachSocket)
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

// Test_Inspect_LivenessComesFromTheLockNotTheRecord pins where a reader learns
// that a session is alive: the lock beside its record, never the status the
// record happens to carry.
//
// The held case also covers a holder that claimed under some other runtime
// root, which used to be a test of its own. Inspect takes no runtime root
// now, so there is nothing such a test could vary — a claim's runtime root
// cannot reach this function at all. Two *state* roots still make a
// difference, and Test_Inspect_DoesNotBorrowLivenessFromAnotherStateRoot is
// where that lives.
func Test_Inspect_LivenessComesFromTheLockNotTheRecord(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	ctx := context.Background()

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)

	rec, held, err := Inspect(ctx, stateRoot, "demo")
	require.NoError(t, err)
	require.True(t, held, "a name whose result lock is held is held, wherever it was claimed")
	require.NotNil(t, rec, "held implies a published record, since Claim publishes under the lock")
	require.Equal(t, StatusStarting, rec.Status)

	// A SIGKILL leaves the record saying whatever was last written, which may
	// well be "ready". Only the lock knows the process is gone.
	require.NoError(t, d.Update(func(r *Record) { r.Status = StatusReady }))
	require.NoError(t, d.releaseKeepingDir())

	rec, held, err = Inspect(ctx, stateRoot, "demo")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, StatusReady, rec.Status, "the stale record still claims ready")
	require.False(t, held, "liveness must come from the lock, not the record")

	rec, held, err = Inspect(ctx, stateRoot, "never-existed")
	require.NoError(t, err)
	require.False(t, held)
	require.Nil(t, rec, "a name that never existed yields no record, not an error")
}

func Test_Inspect_DoesNotBorrowLivenessFromAnotherStateRoot(t *testing.T) {
	// One runtime root, two state roots: what a second shell with a different
	// XDG_STATE_HOME gives on a machine where XDG_RUNTIME_DIR is per-user and
	// shared. The runtime lock says someone claimed this name here; only the
	// lock beside the record says who wrote that record.
	root := shortTempRoot(t)
	runtimeRoot := filepath.Join(root, "run")
	stateA := filepath.Join(root, "stateA")
	stateB := filepath.Join(root, "stateB")
	for _, dir := range []string{runtimeRoot, stateA, stateB} {
		require.NoError(t, os.MkdirAll(dir, 0700))
	}
	ctx := context.Background()

	// B reaches ready and is SIGKILLed: the record goes on saying ready, and
	// every lock the process held is dropped, which is all a crash leaves.
	b, err := claim(t, runtimeRoot, stateB, "demo")
	require.NoError(t, err)
	require.NoError(t, b.Update(func(r *Record) { r.Status = StatusReady }))
	require.NoError(t, b.releaseKeepingDir())

	// A claims the same name under the same runtime root, taking that runtime
	// lock — and nothing of B's.
	a, err := claim(t, runtimeRoot, stateA, "demo")
	require.NoError(t, err)
	defer func() { _ = a.Release(ctx) }()

	rec, held, err := Inspect(ctx, stateB, "demo")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, StatusReady, rec.Status, "B's record is stale, not rewritten")
	require.False(t, held, "an unrelated claim under this runtime root must not revive a dead session")

	rec, held, err = Inspect(ctx, stateA, "demo")
	require.NoError(t, err)
	require.True(t, held, "the live session is held under the root it publishes into")
	require.NotNil(t, rec)
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

// backdate republishes a record with an older UpdatedAt, through the same
// writer the session itself publishes with so the file keeps the shape Prune
// reads. Ageing a record is the only way to test retention without sleeping
// through it.
func backdate(t *testing.T, stateRoot, name string, age time.Duration) {
	t.Helper()

	rec, err := ReadRecord(stateRoot, name)
	require.NoError(t, err)
	rec.UpdatedAt = time.Now().UTC().Add(-age)
	require.NoError(t, writeJSONAtomic(filepath.Join(resultsRoot(stateRoot), name, recordFile), rec))
}

func Test_Prune_RemovesOnlyOldFreeRecords(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	ctx := context.Background()

	const past = RecordRetention + 24*time.Hour

	// Old and free: the only one retention is about.
	oldFree, err := claim(t, runtimeRoot, stateRoot, "old-free")
	require.NoError(t, err)
	require.NoError(t, oldFree.Release(ctx))
	backdate(t, stateRoot, "old-free", past)

	// Old and held. A session that has been up for longer than the retention
	// window is still a session, and its record is where it is publishing.
	oldHeld, err := claim(t, runtimeRoot, stateRoot, "old-held")
	require.NoError(t, err)
	defer func() { _ = oldHeld.Release(ctx) }()
	backdate(t, stateRoot, "old-held", past)

	// Recent and free: the ordinary finished session, still within history.
	recentFree, err := claim(t, runtimeRoot, stateRoot, "recent-free")
	require.NoError(t, err)
	require.NoError(t, recentFree.Release(ctx))

	// A record that cannot be dated is left alone rather than guessed at.
	unparsable := filepath.Join(resultsRoot(stateRoot), "unparsable")
	require.NoError(t, os.MkdirAll(unparsable, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(unparsable, recordFile), []byte("{not json"), 0600))

	require.NoError(t, Prune(ctx, stateRoot, RecordRetention))

	entries, err := os.ReadDir(resultsRoot(stateRoot))
	require.NoError(t, err)
	var survived []string
	for _, e := range entries {
		if e.IsDir() {
			survived = append(survived, e.Name())
		}
	}
	require.ElementsMatch(t, []string{"old-held", "recent-free", "unparsable"}, survived)
}
