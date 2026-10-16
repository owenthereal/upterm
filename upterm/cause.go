package upterm

import "time"

// SessionEndRequestType is a global request the daemon sends a host-door
// client (the host's own terminal, upterm attach) when a session ends, just
// before that client's exit-status, with want-reply true. The daemon waits
// for the reply (bounded by SessionEndReplyBound) before sending the status,
// so a client that answers has the cause before the status arrives, whatever
// the status (0 included). A client from before this request replies false
// at once -- x/crypto's ssh.Client answers every global request it is sent
// that way (handleGlobalRequests) -- and sees only the status, as today.
// Guests are never sent it.
const SessionEndRequestType = "session-end@upterm.dev"

// SessionEndReplyBound is how long the daemon waits for the reply.
const SessionEndReplyBound = time.Second

// The payload, as ssh.Marshal encodes it. Fields are only ever appended to
// it, never reordered or removed, and a reader ignores whatever follows the
// fields it knows: x/crypto's Unmarshal refuses trailing data, so a reader
// decodes into its own struct with these fields first and a final
// `ssh:"rest"` field, not into this one.
type SessionEnd struct {
	Cause  string // one of the Cause* values
	Signal string // SSH signal name without "SIG" ("TERM") for CauseSignaled, else ""
}

const (
	CauseExited      = "exited"       // the command ended on its own; the status is its own
	CauseStopped     = "stopped"      // upterm session stop
	CauseSignaled    = "signaled"     // the daemon received a signal and shut down, or the command was killed by one on its own
	CauseCanceled    = "canceled"     // the daemon's run was cancelled
	CauseJoinTimeout = "join_timeout" // no guest joined within the join timeout; status 0
)
