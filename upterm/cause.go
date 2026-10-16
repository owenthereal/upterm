package upterm

import "time"

// SessionEndRequestType is a global request the daemon sends a host-door
// client (the host's own terminal, upterm attach) when a session ends, just
// before that client's exit-status, with want-reply true. The daemon waits
// for the reply (bounded by SessionEndReplyBound) before sending the status,
// so a client that answers has the cause before the status arrives, whatever
// the status (0 included). A client from before this request replies false
// at once (x/crypto's DiscardRequests) and sees only the status, as today.
// Guests are never sent it.
const SessionEndRequestType = "session-end@upterm.dev"

// SessionEndReplyBound is how long the daemon waits for the reply.
const SessionEndReplyBound = time.Second

// The payload, as ssh.Marshal encodes it.
type SessionEnd struct {
	Cause  string // one of the Cause* values
	Signal string // SSH signal name without "SIG" ("TERM") for CauseSignaled, else ""
}

const (
	CauseExited      = "exited"       // the command ended on its own; the status is its own
	CauseStopped     = "stopped"      // upterm session stop
	CauseSignaled    = "signaled"     // the daemon, or the command on its own, was killed by a signal
	CauseCanceled    = "canceled"     // the daemon's run was cancelled
	CauseJoinTimeout = "join_timeout" // no guest joined within the join timeout; status 0
)
