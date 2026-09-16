package sessiondir

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Session status, published in the single session record.
//
// A held lock says a process owns the name; it says nothing about whether that
// process got anywhere, which is why this exists separately.
const (
	StatusStarting     = "starting"
	StatusReady        = "ready"
	StatusDisconnected = "disconnected"
	StatusEnding       = "ending"
)

// Outcome reasons, published in the single session record.
//
// ReasonUnknown is both the value written when a name is claimed and the value
// that survives a process which never replaced it. It is what lets a caller
// tell "we do not know how this ended" from "no such session", which is an
// absent record — and an absent record means only "not found within retained
// history", since Prune removes anything unheld and older than RecordRetention.
const (
	ReasonUnknown          = "unknown"
	ReasonExited           = "exited"
	ReasonSignaled         = "signaled"
	ReasonStopped          = "stopped"
	ReasonStartupFailed    = "startup_failed"
	ReasonStartupAbandoned = "startup_abandoned"
)

// Record is a session's status and outcome, in one file.
//
// One file, not two, because a reader takes no lock. Status and outcome in
// separate files could be read across a launch boundary — new status, previous
// run's exit code — and the combination "ready, exited 0" is both plausible and
// completely wrong. A single atomic rename makes that impossible instead of
// unlikely. LaunchID is what lets a caller confirm which run it is looking at.
type Record struct {
	Name     string `json:"name"`
	LaunchID string `json:"launch_id"`
	// AdminSocket is where the session's admin socket is bound, under the
	// runtime root it claimed its name with. A reader under another runtime
	// root — a login shell asking about a cron job's session — shares only
	// the record with it, and a path rebuilt under the reader's own root
	// names a socket nothing answers at. Forced on every publish, like Name
	// and LaunchID, so no caller can leave it out.
	AdminSocket string `json:"admin_socket,omitempty"`
	// AttachSocket is where the session's local terminal door is bound, beside
	// the admin socket and under the same runtime root, for the same reason
	// AdminSocket is recorded: `upterm attach` from a shell under a different
	// XDG_RUNTIME_DIR must dial the socket that exists, not one rebuilt under
	// its own root. Forced on every publish.
	AttachSocket string    `json:"attach_socket,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Command      []string  `json:"command,omitempty"`
	ForceCommand []string  `json:"force_command,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// omitzero, not omitempty: omitempty does nothing for a struct, so a
	// record that has not finished carried finished_at: "0001-01-01T00:00:00Z"
	// — a date, and one a reader could easily take for a real one.
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	Signal     string    `json:"signal,omitempty"`
}

// Update mutates the record and republishes it atomically.
//
// Read-modify-write happens against the in-memory copy under d.mu rather than
// against the file, so two concurrent updates cannot lose one another's fields.
func (d *Dir) Update(mutate func(*Record)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	mutate(&d.record)
	d.record.Name = d.name
	d.record.LaunchID = d.launchID
	d.record.AdminSocket = d.AdminSocket()
	d.record.AttachSocket = d.AttachSocket()
	d.record.UpdatedAt = time.Now().UTC()

	return writeJSONAtomic(d.RecordPath(), d.record)
}

// Record returns a copy of the current record.
func (d *Dir) Record() Record {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.record
}

// ReadRecord reads a session's record by name. It works after the session is
// gone, which is the point: an admin socket dies with its process, so polling
// it can never answer "did it finish".
//
// A record that exists says nothing about liveness — normal shutdown leaves
// "ending" behind and a SIGKILL leaves whatever was last written. Use Inspect,
// which reads the record and ownership together, before trusting Status.
func ReadRecord(stateRoot, name string) (*Record, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	return readRecordLocked(stateRoot, name)
}

// readRecordLocked is the body of ReadRecord without the name check, for
// callers that have already validated and are holding the registry lock.
func readRecordLocked(stateRoot, name string) (*Record, error) {
	raw, err := readFileShareDelete(filepath.Join(resultsRoot(stateRoot), name, recordFile))
	if err != nil {
		return nil, err
	}

	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RecordRetention is how long a record outlives the session that wrote it.
// Nothing sweeps in the background, so this is only as true as the next call
// to Prune.
const RecordRetention = 7 * 24 * time.Hour

// Prune removes records that nobody holds and that nothing has written to for
// olderThan.
//
// Under the results registry, so a directory cannot be removed out from under
// a Claim that is midway through taking it — the same reason Reap runs under
// the sessions registry. A held name is skipped whatever its record says: a
// session that has been up longer than the retention window is still publishing
// into that directory.
//
// One bad entry is not a failed prune. A record that cannot be read or parsed
// is left alone rather than dated by guesswork, and a removal that fails is
// left for the next call; only failing to take the registry or to list the
// directory at all is an error, since neither says anything about one entry.
func Prune(ctx context.Context, stateRoot string, olderThan time.Duration) error {
	resRoot := resultsRoot(stateRoot)
	reg, err := lockRegistry(ctx, resRoot)
	if err != nil {
		return err
	}
	defer releaseRegistry(reg)

	entries, err := os.ReadDir(resRoot)
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
		dir := filepath.Join(resRoot, e.Name())
		held, err := lockIsHeld(filepath.Join(dir, resultLockFile))
		if err != nil || held {
			continue
		}
		rec, err := readRecordLocked(stateRoot, e.Name())
		if err != nil {
			continue
		}
		if time.Since(rec.UpdatedAt) > olderThan {
			_ = os.RemoveAll(dir)
		}
	}

	return nil
}

// writeJSONAtomic publishes by rename, so a reader never sees a half-written
// record.
//
// replaceFile is per-platform because the rename is only atomic-in-front-of-a-
// reader on one of them for free: see rename_unix.go and rename_windows.go,
// and readFileShareDelete for the reader's half of the same problem.
func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}

	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
