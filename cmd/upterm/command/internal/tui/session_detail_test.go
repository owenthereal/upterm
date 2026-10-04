package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_wrapLines(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		width int
		want  []string
	}{
		{
			name:  "empty string",
			text:  "",
			width: 80,
			want:  []string{},
		},
		{
			name:  "single line",
			text:  "hello world",
			width: 80,
			want:  []string{"hello world"},
		},
		{
			name:  "multi-line with embedded newlines",
			text:  "owenthereal:\n- SHA256:abc123\n- SHA256:def456",
			width: 80,
			want:  []string{"owenthereal:", "- SHA256:abc123", "- SHA256:def456"},
		},
		{
			name:  "trailing newline",
			text:  "line1\nline2\n",
			width: 80,
			want:  []string{"line1", "line2", ""},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// wrapLines behavior depends on IsTTY(), but in test environment
			// it should be non-TTY, so we test the non-TTY path
			got := wrapLines(c.text, c.width)
			assert.Equal(t, c.want, got)
		})
	}
}

func Test_renderWrappedRow_multiline(t *testing.T) {
	// Test that multi-line values have continuation lines properly indented
	var b strings.Builder
	labelWidth := 18
	valueWidth := 60
	value := "owenthereal:\n- SHA256:abc123\n- SHA256:def456"

	renderWrappedRow(&b, "Authorized Keys:", value, labelWidth, valueWidth, ValueStyle)
	got := b.String()

	// Check that continuation lines are indented
	lines := strings.Split(got, "\n")
	require.GreaterOrEqual(t, len(lines), 3, "expected at least 3 lines, got: %q", got)

	// First line should have the label
	assert.True(t, strings.HasPrefix(lines[0], "Authorized Keys:"), "first line should start with label, got: %q", lines[0])

	// Continuation lines should be indented (start with spaces)
	indent := strings.Repeat(" ", labelWidth)
	for i := 1; i < len(lines)-1; i++ { // -1 to skip trailing empty line
		assert.True(t, strings.HasPrefix(lines[i], indent), "line %d should be indented with %d spaces, got: %q", i, labelWidth, lines[i])
	}
}

func Test_FormatSessionDetail_authorizedKeys(t *testing.T) {
	detail := SessionDetail{
		SessionID:      "test123",
		Command:        "bash",
		Host:           "ssh://example.com:22",
		SSHCommand:     "ssh test123@example.com",
		AuthorizedKeys: "user1:\n- SHA256:key1\nuser2:\n- SHA256:key2",
	}

	output := FormatSessionDetail(detail)

	// Verify the output contains properly formatted authorized keys
	assert.Contains(t, output, "Authorized Keys:")

	// Check that key fingerprints are indented (appear after spaces)
	lines := strings.Split(output, "\n")
	foundIndentedKey := false
	for _, line := range lines {
		// Look for lines that start with spaces followed by "- SHA256:"
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "- SHA256:") && strings.HasPrefix(line, "  ") {
			foundIndentedKey = true
			break
		}
	}
	assert.True(t, foundIndentedKey, "key fingerprints should be indented in output")
}

func Test_FormatSessionDetail_name(t *testing.T) {
	withName := SessionDetail{
		Name:      "demo",
		SessionID: "abc",
		Command:   "bash",
		Host:      "ssh://example.com:22",
	}
	output := FormatSessionDetail(withName)
	assert.Contains(t, output, "demo")
	assert.Contains(t, output, "Name:")

	withoutName := SessionDetail{
		SessionID: "abc",
		Command:   "bash",
		Host:      "ssh://example.com:22",
	}
	output = FormatSessionDetail(withoutName)
	assert.NotContains(t, output, "Name:")
}

// Test_FormatSessionDetail_withoutALiveAnswer renders what `upterm session
// list` hands this view for a session whose admin socket belongs to another
// environment: a name, a status and a command, and nothing else.
//
// Everything such a session cannot fill in has to be absent rather than blank.
// A title with no session ID after it, a "Host:" with nothing after it and an
// "➤ SSH:" heading over an empty line read as a session that is broken, when
// what it is is a session running somewhere this shell cannot reach.
func Test_FormatSessionDetail_withoutALiveAnswer(t *testing.T) {
	output := FormatSessionDetail(SessionDetail{
		Name:    "build-shell",
		Status:  "starting",
		Command: "bash",
	})

	assert.Contains(t, output, "Status:")
	assert.Contains(t, output, "starting")
	assert.Contains(t, output, "Session: build-shell",
		"with no session ID, the title carries the name the session was looked up by")
	assert.NotContains(t, output, "Host:")
	assert.NotContains(t, output, "SSH:")
	assert.NotContains(t, output, "SFTP:")

	for _, line := range strings.Split(output, "\n") {
		assert.NotRegexp(t, `:\s*$`, line, "a label with no value must not be printed at all")
	}

	// And nothing above was bought by dropping a row a live session does fill
	// in: the status joins those rather than replacing them.
	live := FormatSessionDetail(SessionDetail{
		Name:       "build-shell",
		Status:     "ready",
		SessionID:  "sid-1",
		Command:    "bash",
		Host:       "ssh://example.com:22",
		SSHCommand: "ssh sid-1@example.com",
	})
	assert.Contains(t, live, "Session: sid-1")
	assert.Contains(t, live, "Status:")
	assert.Contains(t, live, "ready")
	assert.Contains(t, live, "Host:")
	assert.Contains(t, live, "SSH:")
}

// pinClock fixes what the status row calls "now", so whether a next attempt is
// still ahead does not depend on when the test runs.
func pinClock(t *testing.T, at time.Time) {
	t.Helper()
	orig := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = orig })
}

// clock is a time as the status row prints it: local, to the second.
func clock(t time.Time) string { return t.Local().Format("15:04:05") }

// row is one labelled line of the detail view, label padded to its column.
func row(label, value string) string { return fmt.Sprintf("%-18s%s\n", label, value) }

// Hints are quoted from the contract in full: the wording is what a user acts
// on, so a reworded hint is a change to review, not a refactor.
var wantHints = []struct{ reason, hint string }{
	{"network", "upterm can't reach the relay; it keeps retrying."},
	{"relay_error", "the relay was reached but couldn't register the session; upterm keeps retrying."},
	{"agent_unavailable", "the SSH agent can't be reached (not running, or restarting); upterm keeps retrying."},
	{"agent_refused", "the SSH agent didn't sign: approve or unlock it, or restart the session with a key file (--private-key)."},
	{"auth_refused", "the relay refused every identity offered; if its --authorized-keys changed, add your key back."},
	{"relay_key_changed", "the relay's key differs from the one this session started with; not accepted. If the change is legitimate, restart the session."},
	{"relay_unsupported", "the relay node reached doesn't support reconnecting (as during a rollback); upterm keeps retrying."},
	{"proof_refused", "the relay refused this session's proof of its key; upterm keeps retrying."},
	{"reconnect_unsupported", "this relay doesn't support reconnecting, so guests can't reach this session again. Restart it for a new connect string."},
}

// Test_renderSessionDetail_Reconnecting is the whole view of a session whose
// tunnel is down and being redialled: the connect string stays, because the
// session comes back under it, and the status row says why and when.
func Test_renderSessionDetail_Reconnecting(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	next := lost.Add(30 * time.Second)
	pinClock(t, lost.Add(5*time.Second))

	got := renderSessionDetail(SessionDetail{
		Name:          "demo",
		Status:        "reconnecting",
		SessionID:     "sid-1",
		Command:       "bash",
		Host:          "ssh://example.com:22",
		SSHCommand:    "ssh sid-1@example.com",
		Reconnect:     "supported",
		TunnelReason:  "relay_key_changed",
		TunnelLostAt:  lost,
		NextAttemptAt: next,
	}, 80)

	want := "Session: sid-1\n\n" +
		row("Name:", "demo") +
		row("Status:", "reconnecting — relay_key_changed since "+clock(lost)+", next attempt "+clock(next)) +
		row("Hint:", "the relay's key differs from the one this session started with; not accepted. If the change is legitimate, restart the session.") +
		row("Command:", "bash") +
		row("Host:", "ssh://example.com:22") +
		"\n➤ SSH:\n    ssh sid-1@example.com\n"
	assert.Equal(t, want, got)
}

// Test_renderSessionDetail_DisconnectedByAnUnsupportedRelay: the status is the
// plain word, and what a user needs instead of a countdown is the hint and the
// reason the relay can't help.
func Test_renderSessionDetail_DisconnectedByAnUnsupportedRelay(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	pinClock(t, lost.Add(time.Minute))

	got := renderSessionDetail(SessionDetail{
		Name:         "demo",
		Status:       "disconnected",
		SessionID:    "sid-1",
		Command:      "bash",
		Reconnect:    "unsupported",
		TunnelReason: "reconnect_unsupported",
		TunnelLostAt: lost,
	}, 80)

	want := "Session: sid-1\n\n" +
		row("Name:", "demo") +
		row("Status:", "disconnected") +
		row("Hint:", "this relay doesn't support reconnecting, so guests can't reach this session again. Restart it for a new connect string.") +
		row("Reconnect:", "unsupported by this relay") +
		row("Command:", "bash")
	assert.Equal(t, want, got)
}

func Test_StatusHint_OnePerReason(t *testing.T) {
	for _, tc := range wantHints {
		t.Run(tc.reason, func(t *testing.T) {
			for _, status := range []string{"reconnecting", "disconnected"} {
				assert.Equal(t, tc.hint, StatusHint(SessionDetail{Status: status, TunnelReason: tc.reason}), status)
			}
		})
	}
}

// Test_StatusHint_OnlyWhereItHelps: a hint explains an outage, so a status
// without one prints none, whatever the record still says about the last
// outage; and a reason this version doesn't know is not guessed at.
func Test_StatusHint_OnlyWhereItHelps(t *testing.T) {
	for _, status := range []string{"ready", "starting", "ending", "ended", ""} {
		assert.Empty(t, StatusHint(SessionDetail{Status: status, TunnelReason: "network"}), status)
	}
	for _, reason := range []string{"", "from_the_future"} {
		assert.Empty(t, StatusHint(SessionDetail{Status: "reconnecting", TunnelReason: reason}), reason)
		assert.Empty(t, StatusHint(SessionDetail{Status: "disconnected", TunnelReason: reason}), reason)
	}
}

func Test_StatusText(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	next := lost.Add(30 * time.Second)
	pinClock(t, lost.Add(5*time.Second))

	cases := []struct {
		name   string
		detail SessionDetail
		want   string
	}{
		{"reason, since and next", SessionDetail{Status: "reconnecting", TunnelReason: "network", TunnelLostAt: lost, NextAttemptAt: next},
			"reconnecting — network since " + clock(lost) + ", next attempt " + clock(next)},
		{"no next attempt known", SessionDetail{Status: "reconnecting", TunnelReason: "network", TunnelLostAt: lost},
			"reconnecting — network since " + clock(lost)},
		{"no lost-at drops since", SessionDetail{Status: "reconnecting", TunnelReason: "network", NextAttemptAt: next},
			"reconnecting — network, next attempt " + clock(next)},
		{"no reason", SessionDetail{Status: "reconnecting", TunnelLostAt: lost, NextAttemptAt: next},
			"reconnecting — since " + clock(lost) + ", next attempt " + clock(next)},
		{"nothing known", SessionDetail{Status: "reconnecting"}, "reconnecting"},
		{"disconnected is the plain word", SessionDetail{Status: "disconnected", TunnelReason: "reconnect_unsupported", TunnelLostAt: lost}, "disconnected"},
		{"ready", SessionDetail{Status: "ready", TunnelReason: "network", TunnelLostAt: lost, NextAttemptAt: next}, "ready"},
		{"ended keeps no detail", SessionDetail{Status: "ended", TunnelReason: "network", TunnelLostAt: lost, NextAttemptAt: next}, "ended"},
		{"ending", SessionDetail{Status: "ending", TunnelReason: "network", TunnelLostAt: lost}, "ending"},
		{"starting", SessionDetail{Status: "starting", TunnelReason: "network"}, "starting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StatusText(tc.detail))
		})
	}
}

// Test_StatusText_NextAttemptAlreadyPast: the next attempt is stamped as each
// wait starts, so it is already behind the clock during every attempt and
// after a sleeping laptop wakes mid-wait. Printing "next attempt 10:00:30" at
// 10:00:45 would promise something that has not happened, so the row stops
// saying it. JSON keeps the raw value; only this text hides it.
func Test_StatusText_NextAttemptAlreadyPast(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	next := lost.Add(30 * time.Second)
	detail := SessionDetail{Status: "reconnecting", TunnelReason: "network", TunnelLostAt: lost, NextAttemptAt: next}
	withoutNext := "reconnecting — network since " + clock(lost)

	pinClock(t, next.Add(-time.Second))
	assert.Equal(t, withoutNext+", next attempt "+clock(next), StatusText(detail), "still ahead")

	pinClock(t, next)
	assert.Equal(t, withoutNext, StatusText(detail), "due this instant is not ahead")

	pinClock(t, next.Add(15*time.Second))
	assert.Equal(t, withoutNext, StatusText(detail), "behind")
}

// Test_ReconnectNote: the one fact about the relay that holds at every status,
// from the first connection on, since it is why guests will never get back in.
func Test_ReconnectNote(t *testing.T) {
	for _, status := range []string{"starting", "ready", "reconnecting", "disconnected", "ending", "ended"} {
		assert.Equal(t, "unsupported by this relay", ReconnectNote(SessionDetail{Status: status, Reconnect: "unsupported"}), status)
	}
	assert.Empty(t, ReconnectNote(SessionDetail{Status: "ready", Reconnect: "supported"}))
	assert.Empty(t, ReconnectNote(SessionDetail{Status: "ready"}), "unknown until the first connection shows it")
}

// Test_FormatSessionDetail_RowsByStatus: which of the two extra rows each
// status prints, in a view that has everything else a live session has.
func Test_FormatSessionDetail_RowsByStatus(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	pinClock(t, lost.Add(time.Second))

	render := func(status, reconnect string) string {
		return renderSessionDetail(SessionDetail{
			Name: "demo", Status: status, SessionID: "sid-1", Command: "bash",
			Host: "ssh://example.com:22", SSHCommand: "ssh sid-1@example.com",
			Reconnect: reconnect, TunnelReason: "network", TunnelLostAt: lost,
		}, 80)
	}

	ready := render("ready", "supported")
	assert.NotContains(t, ready, "Hint:")
	assert.NotContains(t, ready, "Reconnect:")
	assert.Contains(t, ready, row("Status:", "ready"))

	readyUnsupported := render("ready", "unsupported")
	assert.NotContains(t, readyUnsupported, "Hint:", "no outage to explain")
	assert.Contains(t, readyUnsupported, row("Reconnect:", "unsupported by this relay"),
		"but the relay's limit is true from the first connection on")

	for _, status := range []string{"starting", "ending", "ended"} {
		out := render(status, "supported")
		assert.NotContains(t, out, "Hint:", status)
		assert.NotContains(t, out, "since", status)
	}

	reconnecting := render("reconnecting", "supported")
	assert.Contains(t, reconnecting, row("Hint:", "upterm can't reach the relay; it keeps retrying."))
	assert.NotContains(t, reconnecting, "Reconnect:", "a relay that supports it has nothing to add")
}
