package host

import "github.com/owenthereal/upterm/host/sessiondir"

// statusOrder is the sequence a session's status moves through. Position is
// the whole of the meaning here: advanceStatus compares indices, so the order
// of this slice is the rule.
var statusOrder = []string{
	sessiondir.StatusStarting,
	sessiondir.StatusReady,
	sessiondir.StatusDisconnected,
	sessiondir.StatusEnding,
}

// advanceStatus sets r's status to `to`, unless that would move it backwards.
//
// The publishers are concurrent and unordered. A tunnel that dies publishes
// "disconnected" from the guest server's callback while the ready actor
// publishes "ready" as soon as the admin socket and the command report
// themselves, and nothing writes "disconnected" a second time. Written
// unconditionally, a tunnel lost during startup left "ready" standing for the
// rest of the session — `upterm session list` showing a session anyone could
// join, for a session nobody could reach.
//
// Ordering the two writes instead would mean making a fact about the network
// wait for a fact about the process, which is not an ordering either of them
// has. Refusing to move backwards needs no ordering at all: whichever writes
// second cannot undo the other.
//
// A status this version does not recognise — an empty one, or one a newer
// version wrote — ranks as the earliest, so the session's own progress is
// still publishable over it rather than frozen on a value nothing here
// understands.
func advanceStatus(r *sessiondir.Record, to string) {
	if statusRank(to) > statusRank(r.Status) {
		r.Status = to
	}
}

func statusRank(status string) int {
	for i, s := range statusOrder {
		if s == status {
			return i
		}
	}
	return 0
}
