package sessiondir

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

// Test_Record_HostKeysRoundTrip pins that HostKeys, unlike AdminSocket and
// AttachSocket, is not forced on every publish: Dir has no key of its own, so
// a record that never had one published stays empty, and one the daemon set
// survives an update that says nothing about it.
func Test_Record_HostKeysRoundTrip(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)

	d, err := claim(t, runtimeRoot, stateRoot, "host-keys")
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Release(context.Background()) })

	rec, err := ReadRecord(stateRoot, "host-keys")
	require.NoError(t, err)
	require.Empty(t, rec.HostKeys, "nothing has published a key yet")

	keys := []string{"ssh-ed25519 AAAA one", "ssh-rsa AAAA two"}
	require.NoError(t, d.Update(func(r *Record) { r.HostKeys = keys }))

	rec, err = ReadRecord(stateRoot, "host-keys")
	require.NoError(t, err)
	require.Equal(t, keys, rec.HostKeys)

	// An update that does not mention HostKeys leaves it as it was, the way
	// Update's read-modify-write leaves every field an earlier update set.
	require.NoError(t, d.Update(func(r *Record) { r.Status = StatusReady }))
	rec, err = ReadRecord(stateRoot, "host-keys")
	require.NoError(t, err)
	require.Equal(t, keys, rec.HostKeys, "an unrelated update must not drop the published keys")
}

func Test_Record_PublicationIsAtomicUnderAConcurrentReader(t *testing.T) {
	// Atomicity is only observable against someone reading while you write, so
	// this test has a concurrent reader; without one its name would promise
	// more than it checked.
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

func TestClaimRecordsTheClaimersPid(t *testing.T) {
	root := shortTempRoot(t)
	d, err := Claim(context.Background(), ClaimOptions{RuntimeRoot: root, StateRoot: root, Name: "pid-1", Command: []string{"sh"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Release(context.Background()) })

	rec, err := ReadRecord(root, "pid-1")
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), rec.Pid, "the claimer is the owner, and the record must say which process that is")

	// Survives every later Update, which forces the identity fields.
	require.NoError(t, d.Update(func(r *Record) { r.LogPath = "/var/log/upterm.log" }))
	rec, err = ReadRecord(root, "pid-1")
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), rec.Pid)
	require.Equal(t, "/var/log/upterm.log", rec.LogPath)
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

func TestRecordOriginatingSignalRoundTrip(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	d, err := claim(t, runtimeRoot, stateRoot, "signal")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()
	number := 7
	require.NoError(t, d.Update(func(r *Record) {
		r.Reason = ReasonSignaled
		r.Signal = "bus error"
		r.SignalNumber = &number
	}))
	rec, err := ReadRecord(stateRoot, "signal")
	require.NoError(t, err)
	require.Equal(t, &number, rec.SignalNumber)
	raw, err := os.ReadFile(d.RecordPath())
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, float64(7), fields["signal_number"])
	var legacy Record
	require.NoError(t, json.Unmarshal([]byte(`{"reason":"signaled","signal":"bus error"}`), &legacy))
	require.Nil(t, legacy.SignalNumber)
	raw, err = json.Marshal(legacy)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "signal_number")
}

// The tunnel fields are a contract for integrations that read the record, so
// their names are pinned, and they are absent from a record that never lost
// its tunnel rather than present with an empty or zero value.
func TestRecordJSONNames(t *testing.T) {
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(Record{
		Reconnect:     ReconnectSupported,
		TunnelLostAt:  at,
		TunnelReason:  TunnelReasonNetwork,
		TunnelError:   "EOF",
		NextAttemptAt: at.Add(time.Second),
	})
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, "supported", fields["reconnect"])
	require.Equal(t, "2026-10-03T12:00:00Z", fields["tunnel_lost_at"])
	require.Equal(t, "network", fields["tunnel_reason"])
	require.Equal(t, "EOF", fields["tunnel_error"])
	require.Equal(t, "2026-10-03T12:00:01Z", fields["next_attempt_at"])

	raw, err = json.Marshal(Record{})
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(raw, &fields))
	for _, name := range []string{"reconnect", "tunnel_lost_at", "tunnel_reason", "tunnel_error", "next_attempt_at", "delegation"} {
		require.NotContains(t, fields, name)
	}

	// A delegated session's record says, under delegation, everything its
	// placement said about it, each under its own name.
	raw, err = json.Marshal(Record{Delegation: &Delegation{
		DelegationAssociation: DelegationAssociation{Service: "https://authority.example", Account: "a", Login: "l", SupersededSessionID: "old"},
		DelegationDisplay: DelegationDisplay{
			Authority: "Example",
			Links:     []DelegationLink{{Label: "Dashboard", URL: "https://authority.example/s"}},
			Notes:     []string{"a note"},
		},
		ExternalSessionID: "s", RoutingID: "r", Relay: "relay.example:22", GuestAddress: "work", Decision: DecisionStopped,
	}})
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, map[string]any{
		"authority": "Example", "service": "https://authority.example", "account": "a", "login": "l",
		"external_session_id": "s", "routing_id": "r", "relay": "relay.example:22", "guest_address": "work",
		"links":                 []any{map[string]any{"label": "Dashboard", "url": "https://authority.example/s"}},
		"notes":                 []any{"a note"},
		"superseded_session_id": "old", "decision": "stopped",
	}, fields["delegation"])

	// Only the session it replaced and the decision are left out until
	// there is one; the authority's name is there even when it is empty.
	raw, err = json.Marshal(Delegation{DelegationDisplay: DelegationDisplay{Links: []DelegationLink{}, Notes: []string{}}})
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, map[string]any{
		"authority": "", "service": "", "account": "", "login": "", "external_session_id": "", "routing_id": "",
		"relay": "", "guest_address": "", "links": []any{}, "notes": []any{},
	}, fields)
	require.Equal(t, "stopped", DecisionStopped)
	require.Equal(t, "withdrawn", DecisionWithdrawn)
}

// masterRecord is Record as a build without delegations has it, copied from
// that build: what an upterm before them, or one without them, decodes a
// record into.
type masterRecord struct {
	Name               string        `json:"name"`
	LaunchID           string        `json:"launch_id"`
	AdminSocket        string        `json:"admin_socket,omitempty"`
	AttachSocket       string        `json:"attach_socket,omitempty"`
	HostKeys           []string      `json:"host_keys,omitempty"`
	SessionID          string        `json:"session_id,omitempty"`
	Command            []string      `json:"command,omitempty"`
	ForceCommand       []string      `json:"force_command,omitempty"`
	LoginCommand       []string      `json:"login_command,omitempty"`
	StartedAt          time.Time     `json:"started_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
	FinishedAt         time.Time     `json:"finished_at,omitzero"`
	FirstGuestJoinedAt time.Time     `json:"first_guest_joined_at,omitzero"`
	JoinTimeout        time.Duration `json:"join_timeout,omitempty"`
	JoinDeadline       time.Time     `json:"join_deadline,omitzero"`
	Status             string        `json:"status"`
	Reason             string        `json:"reason"`
	Reconnect          string        `json:"reconnect,omitempty"`
	TunnelLostAt       time.Time     `json:"tunnel_lost_at,omitzero"`
	TunnelReason       string        `json:"tunnel_reason,omitempty"`
	TunnelError        string        `json:"tunnel_error,omitempty"`
	NextAttemptAt      time.Time     `json:"next_attempt_at,omitzero"`
	ExitCode           *int          `json:"exit_code,omitempty"`
	Signal             string        `json:"signal,omitempty"`
	SignalNumber       *int          `json:"signal_number,omitempty"`
	Pid                int           `json:"pid,omitempty"`
	LogPath            string        `json:"log_path,omitempty"`
}

// A delegated session's record is one a build without delegations reads as
// it reads any other: its decoder isn't strict, so the delegation is passed
// over and every other field comes through as it was written.
func TestRecordWithDelegationReadsInABuildWithoutIt(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	d, err := claim(t, runtimeRoot, stateRoot, "work")
	require.NoError(t, err)
	defer func() { _ = d.Release(context.Background()) }()
	require.NoError(t, d.Update(func(r *Record) {
		r.Status = StatusDisconnected
		r.SessionID = "abcdefghijklmnopqrst"
		r.TunnelReason = TunnelReasonWithdrawn
		r.Delegation = &Delegation{
			DelegationAssociation: DelegationAssociation{Service: testDelegationService, Account: testDelegationAccount, Login: "l"},
			DelegationDisplay:     DelegationDisplay{Authority: "Example Authority", Links: []DelegationLink{{Label: "Dashboard", URL: "https://authority.example/s"}}, Notes: []string{"a note"}},
			ExternalSessionID:     "33333333-3333-4333-8333-333333333333", RoutingID: "abcdefghijklmnopqrst",
			Relay: "relay.example:22", GuestAddress: "claim-work", Decision: DecisionWithdrawn,
		}
	}))
	raw, err := os.ReadFile(d.RecordPath())
	require.NoError(t, err)
	require.Contains(t, string(raw), `"delegation"`)

	var old masterRecord
	require.NoError(t, json.Unmarshal(raw, &old))
	rec := d.Record()
	require.Equal(t, masterRecord{
		Name: rec.Name, LaunchID: rec.LaunchID, AdminSocket: rec.AdminSocket, AttachSocket: rec.AttachSocket,
		SessionID: rec.SessionID, Command: rec.Command, StartedAt: rec.StartedAt, UpdatedAt: rec.UpdatedAt,
		Status: StatusDisconnected, Reason: rec.Reason, TunnelReason: TunnelReasonWithdrawn, Pid: rec.Pid,
	}, old)
}

// The running delegated sessions are those whose results lock is held,
// whatever any record says: a session killed with its record saying ready,
// under a pid that is alive (this process's own), is not one, nor is one
// that ended, and a running session that isn't delegated is left out.
func TestLiveDelegatedSessionsAreTheHeldOnes(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	ctx := context.Background()
	publish := func(d *Dir, status string) {
		t.Helper()
		require.NoError(t, d.Update(func(r *Record) {
			r.Status = status
			r.Delegation = &Delegation{
				DelegationAssociation: DelegationAssociation{Service: testDelegationService, Account: testDelegationAccount},
				ExternalSessionID:     d.Name(),
				GuestAddress:          "claim-work",
			}
		}))
	}

	running, err := claim(t, runtimeRoot, stateRoot, "running")
	require.NoError(t, err)
	defer func() { _ = running.Release(ctx) }()
	publish(running, StatusReady)

	reconnecting, err := claim(t, runtimeRoot, stateRoot, "reconnecting")
	require.NoError(t, err)
	defer func() { _ = reconnecting.Release(ctx) }()
	publish(reconnecting, StatusReconnecting)

	standalone, err := claim(t, runtimeRoot, stateRoot, "standalone")
	require.NoError(t, err)
	defer func() { _ = standalone.Release(ctx) }()

	killed, err := claim(t, runtimeRoot, stateRoot, "killed")
	require.NoError(t, err)
	publish(killed, StatusReady)
	require.NoError(t, killed.releaseKeepingDir())

	ended, err := claim(t, runtimeRoot, stateRoot, "ended")
	require.NoError(t, err)
	publish(ended, StatusEnding)
	require.NoError(t, ended.Release(ctx))

	// Nobody holds it, so nothing about it is read: a record that can't be
	// parsed is a dead session's all the same.
	damaged, err := claim(t, runtimeRoot, stateRoot, "damaged")
	require.NoError(t, err)
	require.NoError(t, damaged.releaseKeepingDir())
	require.NoError(t, os.WriteFile(damaged.RecordPath(), []byte("{not json"), 0o600))

	live, err := LiveDelegatedSessions(ctx, stateRoot)
	require.NoError(t, err)
	var names []string
	for _, rec := range live {
		names = append(names, rec.Name)
		require.NotNil(t, rec.Delegation)
	}
	require.Equal(t, []string{"reconnecting", "running"}, names)
}

// A running session this can't read the record of, or whose lock it can't
// test, may be any name's, so the look fails and says which session it
// couldn't tell about, rather than leave it out.
func TestLiveDelegatedSessionsFailWhereTheyCantTell(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, d *Dir)
	}{
		{"a record that can't be parsed", func(t *testing.T, d *Dir) {
			require.NoError(t, os.WriteFile(d.RecordPath(), []byte("{not json"), 0o600))
		}},
		{"a record that is gone", func(t *testing.T, d *Dir) {
			require.NoError(t, os.Remove(d.RecordPath()))
		}},
		{"a lock that can't be opened", func(t *testing.T, d *Dir) {
			if runtime.GOOS == "windows" {
				t.Skip("file modes don't refuse an open on Windows")
			}
			lock := filepath.Join(filepath.Dir(d.RecordPath()), resultLockFile)
			require.NoError(t, os.Chmod(lock, 0))
			t.Cleanup(func() { _ = os.Chmod(lock, 0o600) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtimeRoot, stateRoot := roots(t)
			ctx := context.Background()
			d, err := claim(t, runtimeRoot, stateRoot, "unreadable")
			require.NoError(t, err)
			defer func() { _ = d.Release(ctx) }()
			tc.damage(t, d)

			live, err := LiveDelegatedSessions(ctx, stateRoot)
			require.Error(t, err)
			require.Contains(t, err.Error(), "unreadable")
			require.Nil(t, live)
		})
	}
}

// Dropping LoginCommand during record decoding or claim publication loses the
// private shell metadata once the daemon stops answering.
func TestLoginCommandSurvivesRecordRelease(t *testing.T) {
	runtimeRoot, stateRoot := roots(t)
	opts := ClaimOptions{LoginCommand: []string{"env", "-u", "HERDR_ENV", "herdr"}}
	opts.RuntimeRoot, opts.StateRoot, opts.Name = runtimeRoot, stateRoot, "login"
	d, err := Claim(context.Background(), opts)
	require.NoError(t, err)
	require.NoError(t, d.Release(context.Background()))
	rec, err := ReadRecord(stateRoot, "login")
	require.NoError(t, err)
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, []any{"env", "-u", "HERDR_ENV", "herdr"}, got["login_command"])
	for _, key := range []string{"guest_shell", "execution", "tcp_forwarding", "approval_method"} {
		require.NotContains(t, got, key)
	}
}
