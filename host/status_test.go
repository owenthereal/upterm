package host

import (
	"testing"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

// Test_advanceStatus_NeverMovesBackwards pins the rule rather than the race
// that motivates it. The publishers are concurrent by construction -- a lost
// tunnel and the ready actor race, and neither can be ordered against the
// other -- so a test of the race could only ever be a test of a scheduler.
// What can be pinned is that whichever of them writes second cannot undo the
// other, which is what the table below states for every ordered pair.
func Test_advanceStatus_NeverMovesBackwards(t *testing.T) {
	for _, tc := range []struct {
		from string
		to   string
		want string
	}{
		{from: sessiondir.StatusStarting, to: sessiondir.StatusStarting, want: sessiondir.StatusStarting},
		{from: sessiondir.StatusStarting, to: sessiondir.StatusReady, want: sessiondir.StatusReady},
		{from: sessiondir.StatusStarting, to: sessiondir.StatusDisconnected, want: sessiondir.StatusDisconnected},
		{from: sessiondir.StatusStarting, to: sessiondir.StatusEnding, want: sessiondir.StatusEnding},

		{from: sessiondir.StatusReady, to: sessiondir.StatusStarting, want: sessiondir.StatusReady},
		{from: sessiondir.StatusReady, to: sessiondir.StatusReady, want: sessiondir.StatusReady},
		{from: sessiondir.StatusReady, to: sessiondir.StatusDisconnected, want: sessiondir.StatusDisconnected},
		{from: sessiondir.StatusReady, to: sessiondir.StatusEnding, want: sessiondir.StatusEnding},

		// The pair the defect was made of: a tunnel that dies before the ready
		// actor runs must not be talked back into being ready.
		{from: sessiondir.StatusDisconnected, to: sessiondir.StatusStarting, want: sessiondir.StatusDisconnected},
		{from: sessiondir.StatusDisconnected, to: sessiondir.StatusReady, want: sessiondir.StatusDisconnected},
		{from: sessiondir.StatusDisconnected, to: sessiondir.StatusDisconnected, want: sessiondir.StatusDisconnected},
		{from: sessiondir.StatusDisconnected, to: sessiondir.StatusEnding, want: sessiondir.StatusEnding},

		{from: sessiondir.StatusEnding, to: sessiondir.StatusStarting, want: sessiondir.StatusEnding},
		{from: sessiondir.StatusEnding, to: sessiondir.StatusReady, want: sessiondir.StatusEnding},
		{from: sessiondir.StatusEnding, to: sessiondir.StatusDisconnected, want: sessiondir.StatusEnding},
		{from: sessiondir.StatusEnding, to: sessiondir.StatusEnding, want: sessiondir.StatusEnding},

		// A record written by a newer or a broken version carries a status
		// this one cannot place. Treating it as the earliest status keeps the
		// session's own progress publishable instead of freezing the record on
		// a value nothing here understands.
		{from: "", to: sessiondir.StatusReady, want: sessiondir.StatusReady},
		{from: "from-a-version-we-do-not-know", to: sessiondir.StatusEnding, want: sessiondir.StatusEnding},
	} {
		t.Run(tc.from+" to "+tc.to, func(t *testing.T) {
			r := &sessiondir.Record{Status: tc.from}
			advanceStatus(r, tc.to)
			require.Equal(t, tc.want, r.Status)
		})
	}
}
