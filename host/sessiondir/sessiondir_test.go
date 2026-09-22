package sessiondir

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shortTempRoot returns a temp directory short enough to hold a session's
// admin socket. t.TempDir() on macOS hands out a /var/folders/<hash>/T/
// <TestName> path already past the 103-byte unix socket limit once a session's
// own components are appended — the very limit Claim now enforces — so the
// temp root is used directly. Windows has no /tmp and its t.TempDir() is long
// for the same reason, so the temp root is used directly there too.
func shortTempRoot(t *testing.T) string {
	t.Helper()

	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	root, err := os.MkdirTemp(base, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

// roots returns runtime and state roots a session can actually be claimed in.
func roots(t *testing.T) (runtimeRoot, stateRoot string) {
	t.Helper()

	root := shortTempRoot(t)
	runtimeRoot = filepath.Join(root, "run")
	stateRoot = filepath.Join(root, "state")
	require.NoError(t, os.MkdirAll(runtimeRoot, 0700))
	require.NoError(t, os.MkdirAll(stateRoot, 0700))
	return runtimeRoot, stateRoot
}

// splitRoots returns two runtime roots over one state root: what a login
// session and a cron job see on the same Linux box, where XDG_RUNTIME_DIR
// differs between them and the state directory does not.
func splitRoots(t *testing.T) (runtimeA, runtimeB, stateRoot string) {
	t.Helper()

	root := shortTempRoot(t)
	runtimeA = filepath.Join(root, "runA")
	runtimeB = filepath.Join(root, "runB")
	stateRoot = filepath.Join(root, "state")
	for _, dir := range []string{runtimeA, runtimeB, stateRoot} {
		require.NoError(t, os.MkdirAll(dir, 0700))
	}
	return runtimeA, runtimeB, stateRoot
}

func claim(t *testing.T, runtimeRoot, stateRoot, name string) (*Dir, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Claim(ctx, ClaimOptions{
		RuntimeRoot: runtimeRoot,
		StateRoot:   stateRoot,
		Name:        name,
		Command:     []string{"bash"},
	})
}

func Test_ValidateName(t *testing.T) {
	for _, ok := range []string{"demo", "claude-9f2c", "a", "A1_b.c-d"} {
		require.NoError(t, ValidateName(ok), "name %q", ok)
	}
	for _, bad := range []string{
		"", ".", "..", "../evil", "a/b", `a\b`, ".hidden", ".registry.lock",
		"-leading-dash", "with space", "with\x00nul",
	} {
		require.ErrorIs(t, ValidateName(bad), ErrInvalidName, "name %q", bad)
	}

	// Bounded length.
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	err := ValidateName(string(long))
	require.ErrorIs(t, err, ErrInvalidName)
	require.ErrorContains(t, err, "longer than 64 bytes")

	// Windows' device names, whatever the case or extension, and a trailing
	// period: refused here on every platform, because a name that claims on
	// Linux and fails at Mkdir on Windows is not a name at all.
	for _, bad := range []string{"con", "NUL", "Com1", "lpt9", "con.log", "build."} {
		require.ErrorIs(t, ValidateName(bad), ErrInvalidName, "name %q", bad)
	}
	require.ErrorContains(t, ValidateName("con.log"), "device name")
	require.ErrorContains(t, ValidateName("build."), "ends in a period")

	// And only those: a device name is exactly three or four characters
	// before the first period, so a longer word, a shorter one, a two-digit
	// port or a suffix past the period is an ordinary name.
	for _, ok := range []string{"console", "com", "com10", "nul-1a2b", "build.1", "aux2"} {
		require.NoError(t, ValidateName(ok), "name %q", ok)
	}
}

func Test_Claim_RejectsTraversalWithoutTouchingAnything(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	// A sibling that must survive a traversal attempt.
	sibling := filepath.Join(filepath.Dir(runtimeRoot), "precious")
	require.NoError(t, os.MkdirAll(sibling, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(sibling, "keep"), []byte("x"), 0600))

	for _, bad := range []string{"..", "../precious", "../../"} {
		_, err := claim(t, runtimeRoot, stateRoot, bad)
		require.ErrorIs(t, err, ErrInvalidName, "name %q", bad)
	}

	_, err := os.Stat(filepath.Join(sibling, "keep"))
	require.NoError(t, err, "a rejected name must not touch the filesystem")
}

func Test_Claim_CreatesDistinctNamespaces(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	require.Equal(t, filepath.Join(runtimeRoot, "sessions", "demo", "admin.sock"), d.AdminSocket())
	require.Equal(t, filepath.Join(stateRoot, "results", "demo", "session.json"), d.RecordPath())
	require.NotEmpty(t, d.LaunchID())
}

func Test_Claim_PublishesUnknownResultImmediately(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	rec, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err, "the record must exist the moment the name is claimed")
	require.Equal(t, ReasonUnknown, rec.Reason)
	require.Equal(t, StatusStarting, rec.Status)
	require.Equal(t, d.LaunchID(), rec.LaunchID)
	require.Nil(t, rec.ExitCode)

	// Against the bytes, not the struct: a session that has not finished must
	// carry no finish time at all. Round-tripping through Record would hide
	// the failure this guards, which is finished_at published as the zero
	// time — "0001-01-01T00:00:00Z" is a date, and automation reading the key
	// rather than the value would take it for one.
	raw, err := os.ReadFile(d.RecordPath())
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.NotContains(t, fields, "finished_at",
		"an unfinished session must not publish a finish time")
	require.Contains(t, fields, "started_at", "the keys that are always present still are")
}

func TestRecordFirstGuestJoinedAtRoundTripsAndOmitsZero(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	dir, err := claim(t, runtimeRoot, stateRoot, "fgj")
	require.NoError(t, err)
	defer func() { _ = dir.Release(context.Background()) }()

	raw, err := os.ReadFile(dir.RecordPath())
	require.NoError(t, err)
	require.NotContains(t, string(raw), "first_guest_joined_at",
		"a session with no guest must not publish the field at all")

	joined := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, dir.Update(func(r *Record) { r.FirstGuestJoinedAt = joined }))

	got, err := ReadRecord(stateRoot, "fgj")
	require.NoError(t, err)
	require.True(t, got.FirstGuestJoinedAt.Equal(joined))
}

func Test_Claim_SupersedesAPreviousRunsResult(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	first, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	code := 0
	require.NoError(t, first.Update(func(r *Record) {
		r.Status = StatusEnding
		r.Reason = ReasonExited
		r.ExitCode = &code
	}))
	require.NoError(t, first.Release(context.Background()))

	second, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = second.Release(context.Background()) }()

	rec, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, ReasonUnknown, rec.Reason,
		"a new claim must not leave the previous run's success looking current")
	require.Equal(t, second.LaunchID(), rec.LaunchID)
	require.Nil(t, rec.ExitCode,
		"status and outcome move together or the tear is back")
}

func Test_Claim_RejectsLiveDuplicate(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()

	_, err = claim(t, runtimeRoot, stateRoot, "demo")
	require.ErrorIs(t, err, ErrNameInUse)
}

func Test_Claim_RefusesANameHeldUnderAnotherRuntimeRoot(t *testing.T) {
	// Ownership has to span both roots, because the record does. Two hosts
	// that disagree about the runtime root agree about results/demo, and the
	// second would publish over the first's outcome while it is still running.
	runtimeA, runtimeB, stateRoot := splitRoots(t)

	a, err := claim(t, runtimeA, stateRoot, "demo")
	require.NoError(t, err)
	defer func() { _ = a.Release(context.Background()) }()

	_, err = claim(t, runtimeB, stateRoot, "demo")
	require.ErrorIs(t, err, ErrNameInUse, "one state root means one owner, whatever the runtime root is")

	_, statErr := os.Stat(filepath.Join(sessionsRoot(runtimeB), "demo"))
	require.True(t, os.IsNotExist(statErr), "a refused claim must leave no runtime directory behind")

	rec, err := ReadRecord(stateRoot, "demo")
	require.NoError(t, err)
	require.Equal(t, a.LaunchID(), rec.LaunchID, "the holder's record must still be the holder's")
}

// Test_Claim_LeavesNothingBehindWhenTheResultsRegistryIsBusy covers the other
// way a claim can be refused after it has made its runtime directory. The
// results registry is reachable in production now that host.ClaimTimeout
// bounds the wait, and a claim that gives up there used to leave sessions/
// <name> for the next reaper to puzzle over.
func Test_Claim_LeavesNothingBehindWhenTheResultsRegistryIsBusy(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	// Held for the whole claim, so the wait can only end in the timeout.
	held, err := lockRegistry(context.Background(), resultsRoot(stateRoot))
	require.NoError(t, err)
	defer releaseRegistry(held)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = Claim(ctx, ClaimOptions{
		RuntimeRoot: runtimeRoot,
		StateRoot:   stateRoot,
		Name:        "demo",
		Command:     []string{"bash"},
	})
	require.Error(t, err, "a claim that cannot take the results registry must fail")
	require.Contains(t, err.Error(), filepath.Join(resultsRoot(stateRoot), registryLockFile))

	_, statErr := os.Stat(filepath.Join(sessionsRoot(runtimeRoot), "demo"))
	require.True(t, os.IsNotExist(statErr), "a refused claim must leave no runtime directory behind")
}

func Test_Release_FreesTheRecordSide(t *testing.T) {
	// The other half of ownership spanning both roots: a name given back has
	// to be claimable from anywhere, not just from the root that gave it back.
	runtimeA, runtimeB, stateRoot := splitRoots(t)
	ctx := context.Background()

	a, err := claim(t, runtimeA, stateRoot, "demo")
	require.NoError(t, err)
	require.NoError(t, a.Release(ctx))

	b, err := claim(t, runtimeB, stateRoot, "demo")
	require.NoError(t, err, "Release must free the name on both roots")
	require.NoError(t, b.Release(ctx))
}

func Test_Claim_RecoversStaleDirectory(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err)
	require.NoError(t, d.releaseKeepingDir()) // exactly what a crash leaves

	d2, err := claim(t, runtimeRoot, stateRoot, "demo")
	require.NoError(t, err, "a stale directory must be recovered, not reported in use")
	require.NoError(t, d2.Release(context.Background()))
}

func Test_Release_KeepsTheResultEvenWhenRootsCoincide(t *testing.T) {
	// The case that matters: on Windows and under the $HOME/.upterm fallback
	// the runtime and state roots are the same directory.
	root := shortTempRoot(t)
	require.NoError(t, os.MkdirAll(root, 0700))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := Claim(ctx, ClaimOptions{
		RuntimeRoot: root, StateRoot: root, Name: "demo", Command: []string{"bash"},
	})
	require.NoError(t, err)
	require.NoError(t, d.Release(context.Background()))

	_, err = ReadRecord(root, "demo")
	require.NoError(t, err, "cleanup must not delete the completion record")
}

func Test_Claim_ConcurrentClaimsYieldOneOwner(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	const n = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []*Dir
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := claim(t, runtimeRoot, stateRoot, "demo")
			if err != nil {
				return
			}
			mu.Lock()
			winners = append(winners, d)
			mu.Unlock()
		}()
	}
	wg.Wait()

	require.Len(t, winners, 1, "exactly one claimer may own a name")
	require.NoError(t, winners[0].Release(context.Background()))
}

func Test_Reap_RemovesOnlyFreeDirectories(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	live, err := claim(t, runtimeRoot, stateRoot, "live")
	require.NoError(t, err)
	defer func() { _ = live.Release(context.Background()) }()

	stale, err := claim(t, runtimeRoot, stateRoot, "stale")
	require.NoError(t, err)
	require.NoError(t, stale.releaseKeepingDir())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, Reap(ctx, runtimeRoot))

	_, err = os.Stat(filepath.Join(runtimeRoot, "sessions", "live"))
	require.NoError(t, err, "a held directory must survive a reap")

	_, err = os.Stat(filepath.Join(runtimeRoot, "sessions", "stale"))
	require.True(t, os.IsNotExist(err), "a free directory must be reaped")
}

func Test_LockRegistry_HonoursContext(t *testing.T) {
	runtimeRoot, _ := roots(t)
	sessionsRoot := filepath.Join(runtimeRoot, "sessions")

	held, err := lockRegistry(context.Background(), sessionsRoot)
	require.NoError(t, err)
	defer releaseRegistry(held)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = lockRegistry(ctx, sessionsRoot)
	require.Error(t, err, "contention must time out rather than spin forever")
	require.Less(t, time.Since(start), 5*time.Second)

	// lockRegistry now guards two different registries (sessions and
	// results); the error must say which one timed out rather than a fixed
	// "the session registry lock" that is wrong half the time.
	require.Contains(t, err.Error(), filepath.Join(sessionsRoot, registryLockFile))
}

func Test_GenerateName(t *testing.T) {
	require.Regexp(t, `^claude-[0-9a-f]{4}$`, GenerateName([]string{"/usr/local/bin/claude", "--x"}))
	require.Regexp(t, `^session-[0-9a-f]{4}$`, GenerateName(nil))

	// A command whose basename is not a legal name must still produce one.
	require.NoError(t, ValidateName(GenerateName([]string{"../weird"})))
	require.NoError(t, ValidateName(GenerateName([]string{".hidden"})))

	// A basename that is a Windows device name falls back the same way, to
	// the default rather than to some repaired form of nul.
	reserved := GenerateName([]string{"nul.exe"})
	require.NoError(t, ValidateName(reserved))
	require.Regexp(t, `^session-[0-9a-f]{4}$`, reserved)

	// A basename at the length limit must still leave room for the suffix —
	// and for the runtime root the name ends up under, which is why the cut is
	// well short of what ValidateName alone would accept.
	long := strings.Repeat("a", 64)
	name := GenerateName([]string{long})
	require.NoError(t, ValidateName(name))
	require.Regexp(t, `^a{20}-[0-9a-f]{4}$`, name)
}

func Test_Claim_RejectsANameWhoseSocketPathWouldNotFit(t *testing.T) {
	_, stateRoot := roots(t)

	// A runtime root deep enough that a perfectly legal 60-character name puts
	// <root>/sessions/<name>/admin.sock past the limit. The refusal has to
	// happen here: at bind time it would land after the tunnel is up, with the
	// name already claimed and the record already published.
	runtimeRoot := filepath.Join(t.TempDir(), strings.Repeat("d", 40))
	require.NoError(t, os.MkdirAll(runtimeRoot, 0700))

	_, err := claim(t, runtimeRoot, stateRoot, strings.Repeat("a", 60))
	require.ErrorIs(t, err, ErrSocketPathTooLong)
	require.ErrorContains(t, err, "limit 103")

	_, statErr := os.Stat(sessionsRoot(runtimeRoot))
	require.True(t, os.IsNotExist(statErr), "a refused claim must not create anything")
}

// Test_CheckSocketPath_BoundaryAtDarwinSunPathLimit pins the exact byte
// boundary a unix socket address can hold: darwin's sun_path is a 104-byte
// buffer that must also hold a trailing NUL, so 103 is the longest path that
// actually binds there. The padding is derived from filepath.Join's own
// output rather than a hard-coded root string, so the test does not depend on
// how long the temp dir prefix happens to be.
//
// The path measured is the attach socket's, the longest of the two a session
// binds in that directory. A check against the shorter one would accept the
// last runtime root here and then fail to bind attach.sock under it.
func Test_CheckSocketPath_BoundaryAtDarwinSunPathLimit(t *testing.T) {
	// shortTempRoot, not t.TempDir(): the latter hands out a
	// /var/folders/<hash>/T/<TestName> prefix that is already past the
	// boundary this test is trying to approach from below.
	base := shortTempRoot(t)
	name := "a"

	pathLen := func(runtimeRoot string) int {
		return len(filepath.Join(sessionsRoot(runtimeRoot), name, attachSocketFile))
	}

	// Grow the runtime root one byte at a time until the resulting attach
	// socket path is exactly 103 bytes.
	pad := 0
	for pathLen(filepath.Join(base, strings.Repeat("d", pad))) < 103 {
		pad++
	}

	runtimeRootAt103 := filepath.Join(base, strings.Repeat("d", pad))
	require.Equal(t, 103, pathLen(runtimeRootAt103), "test setup must hit the boundary exactly")
	require.NoError(t, CheckSocketPath(runtimeRootAt103, name))

	runtimeRootAt104 := filepath.Join(base, strings.Repeat("d", pad+1))
	require.Equal(t, 104, pathLen(runtimeRootAt104), "test setup must hit the boundary exactly")
	err := CheckSocketPath(runtimeRootAt104, name)
	require.ErrorIs(t, err, ErrSocketPathTooLong)
}

func Test_ListLive_ReturnsOnlyHeldNames(t *testing.T) {
	// Two runtime roots over one state root, because that is the split the
	// listing exists for: a host claimed from cron is live and has no
	// directory at all under the login session's runtime root.
	runtimeA, runtimeB, stateRoot := splitRoots(t)
	ctx := context.Background()

	a, err := claim(t, runtimeA, stateRoot, "alpha")
	require.NoError(t, err)
	defer func() { _ = a.Release(ctx) }()

	b, err := claim(t, runtimeB, stateRoot, "bravo")
	require.NoError(t, err)
	defer func() { _ = b.Release(ctx) }()
	require.NoError(t, b.Update(func(r *Record) {
		r.Status = StatusReady
		r.SessionID = "sid-b"
	}))

	// Ended: the record stays for `session info` to answer from, but nobody
	// holds the name, so it is not a session that exists right now.
	ended, err := claim(t, runtimeA, stateRoot, "ended")
	require.NoError(t, err)
	require.NoError(t, ended.Release(ctx))

	// Killed: the same free lock, with a record that still says ready. The
	// lock decides, not the record.
	killed, err := claim(t, runtimeA, stateRoot, "killed")
	require.NoError(t, err)
	require.NoError(t, killed.Update(func(r *Record) { r.Status = StatusReady }))
	require.NoError(t, killed.releaseKeepingDir())

	// Held, with a record this process cannot parse. One bad entry must cost
	// its own row and not the listing, the same way it does in Prune.
	corrupt, err := claim(t, runtimeA, stateRoot, "corrupt")
	require.NoError(t, err)
	defer func() { _ = corrupt.Release(ctx) }()
	require.NoError(t, os.WriteFile(corrupt.RecordPath(), []byte("{not json"), 0600))

	live, err := ListLive(ctx, stateRoot)
	require.NoError(t, err)

	var names []string
	for _, rec := range live {
		names = append(names, rec.Name)
	}
	require.Equal(t, []string{"alpha", "bravo"}, names,
		"the live set is what the results locks say, whatever runtime root each session claimed under")

	require.Equal(t, StatusStarting, live[0].Status)
	require.Equal(t, []string{"bash"}, live[0].Command)
	require.Equal(t, StatusReady, live[1].Status, "each record comes back as its owner published it")
	require.Equal(t, "sid-b", live[1].SessionID)
}
