package sessiondir

import (
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
// history", since records are pruned.
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
	Name         string    `json:"name"`
	LaunchID     string    `json:"launch_id"`
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

const (
	renameAttempts = 5
	renameBackoff  = 2 * time.Millisecond
)

// writeJSONAtomic publishes by rename, so a reader never sees a half-written
// record.
func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}

	// Retry the rename. On Windows a concurrent reader can block replacement
	// outright, and a reader's window is microseconds, so a few attempts turn
	// a lost final outcome into a slightly delayed one. See readFileShareDelete
	// for the other half of this.
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if err = os.Rename(tmp, path); err == nil {
			return nil
		}
		time.Sleep(renameBackoff)
	}

	_ = os.Remove(tmp)
	return err
}
