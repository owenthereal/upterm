package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/owenthereal/upterm/host/sessiondir"
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
			// wrapLines depends on IsTTY(), which TestMain pins to false, so
			// this is the non-TTY path.
			got := wrapLines(c.text, c.width)
			assert.Equal(t, c.want, got)
		})
	}
}

// Test_wordWrapLines: a sentence breaks at spaces, never inside a word it can
// keep whole, and the status row and every hint are the sentences it is for.
// A hyphen is not a place to break: a hint names flags like --authorized-keys,
// which reflow would otherwise cut after a hyphen. A word longer than the
// width has nowhere to break, so it is cut. It is tested directly because the
// terminal check in front of wrapProseLines leaves text alone, and the tests
// pin stdout to not being a terminal.
func Test_wordWrapLines(t *testing.T) {
	const width = 60

	texts := map[string]string{
		"status row": "reconnecting — relay_key_changed since 12:03:04, next attempt 12:08:10",
	}
	require.NotEmpty(t, tunnelHints)
	for reason, hint := range tunnelHints {
		texts["hint "+reason] = hint
	}

	// The no-split check holds only where the width can hold every word: a
	// token wider than the width, like a path or a URL, is cut by design. The
	// widest width must hold each text's longest word, so the check runs for
	// every text at least there, whatever subtest filter is in force.
	widths := []int{30, 40, 60, 80, 100}
	for name, text := range texts {
		longest := 0
		for _, word := range strings.Fields(text) {
			longest = max(longest, utf8.RuneCountInString(word))
		}
		require.LessOrEqual(t, longest, widths[len(widths)-1],
			"%s: no width holds its longest word, so the word-split check would never run", name)

		for _, w := range widths {
			t.Run(fmt.Sprintf("%s at width %d breaks only at spaces", name, w), func(t *testing.T) {
				lines := wordWrapLines(text, w)

				for _, line := range lines {
					assert.LessOrEqual(t, utf8.RuneCountInString(line), w, "%s at width %d: line too long: %q", name, w, line)
				}
				if utf8.RuneCountInString(text) > w {
					assert.Greater(t, len(lines), 1, "%s at width %d should wrap", name, w)
				}

				if longest <= w {
					assert.Equal(t, strings.Fields(text), strings.Fields(strings.Join(lines, " ")),
						"%s at width %d: a word was split; lines: %q", name, w, lines)
				}
			})
		}
	}

	t.Run("a word longer than the width is cut at it", func(t *testing.T) {
		word := strings.Repeat("x", 70)

		assert.Equal(t, []string{strings.Repeat("x", 60), strings.Repeat("x", 10)}, wordWrapLines(word, width))
	})

	t.Run("a short line is left alone", func(t *testing.T) {
		assert.Equal(t, []string{"reconnecting"}, wordWrapLines("reconnecting", width))
	})
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
// A title with no session ID after it, a "Relay:" with nothing after it and an
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
	assert.NotContains(t, output, "Relay:")
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
	assert.Contains(t, live, "Relay:")
	assert.Contains(t, live, "SSH:")
}

// The join line is the front door, so it comes first, and the ssh line under it
// serves guests without upterm. A join line alone still opens the commands
// with a blank line.
func TestJoinLinePrintsAboveSSH(t *testing.T) {
	detail := SessionDetail{
		SessionID:   "abc",
		Host:        "ssh://h:22",
		JoinCommand: "upterm join ssh://abc@h",
		SSHCommand:  "ssh abc@h",
	}
	assert.Equal(t, "Session: abc\n\n"+
		row("Relay:", "ssh://h:22")+
		"\n➤ Join:\n    upterm join ssh://abc@h\n"+
		"➤ SSH:\n    ssh abc@h\n",
		renderSessionDetail(detail, 80))

	detail.SSHCommand = ""
	assert.Equal(t, "Session: abc\n\n"+
		row("Relay:", "ssh://h:22")+
		"\n➤ Join:\n    upterm join ssh://abc@h\n",
		renderSessionDetail(detail, 80))
}

// clock is a time as the status row prints it: local, to the second.
func clock(t time.Time) string { return t.Local().Format("15:04:05") }

// row is one labelled line of the detail view, label padded to its column.
func row(label, value string) string { return fmt.Sprintf("%-18s%s\n", label, value) }

// Every hint is quoted here in full, so rewording one fails a test: the wording
// is what a user acts on, so a reworded hint is a change to review, not a
// refactor.
var wantHints = []struct{ reason, hint string }{
	{"network", "upterm can't reach the relay; it keeps retrying."},
	{"relay_error", "the relay was reached but couldn't register the session; upterm keeps retrying."},
	{"agent_unavailable", "the SSH agent can't be reached (not running, or restarting); upterm keeps retrying."},
	{"agent_refused", "the SSH agent didn't sign: approve or unlock it, or restart the session with a key file (--private-key)."},
	{"auth_refused", "the relay refused every identity offered; if its --authorized-keys changed, add your key back."},
	{"relay_key_changed", "the relay's key differs from the one this session started with; not accepted. If the change is legitimate, restart the session."},
	{"relay_unsupported", "the relay node reached can't take this session back (as during a rollback), or answered with characters upterm won't put in a command; upterm keeps retrying."},
	{"proof_refused", "the relay refused this session's proof of its key; upterm keeps retrying."},
	{"reconnect_unsupported", "this relay doesn't support reconnecting, so guests can't reach this session again. Restart it for a new connect string."},
}

// Test_renderSessionDetail_Reconnecting is the whole view of a session whose
// tunnel is down and being redialled: the connect string stays, because the
// session comes back under it, and the status row says why and when.
func Test_renderSessionDetail_Reconnecting(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	next := lost.Add(30 * time.Second)
	at := lost.Add(5 * time.Second)

	got := renderSessionDetailAt(SessionDetail{
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
	}, 80, at)

	want := "Session: sid-1\n\n" +
		row("Name:", "demo") +
		row("Status:", "reconnecting — relay_key_changed since "+clock(lost)+", next attempt "+clock(next)) +
		row("Hint:", "the relay's key differs from the one this session started with; not accepted. If the change is legitimate, restart the session.") +
		row("Command:", "bash") +
		row("Relay:", "ssh://example.com:22") +
		"\n➤ SSH:\n    ssh sid-1@example.com\n"
	assert.Equal(t, want, got)
}

// Test_renderSessionDetail_DisconnectedByAnUnsupportedRelay: the status is the
// plain word, and what a user needs instead of a countdown is the hint and the
// reason the relay can't help.
func Test_renderSessionDetail_DisconnectedByAnUnsupportedRelay(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	at := lost.Add(time.Minute)

	got := renderSessionDetailAt(SessionDetail{
		Name:         "demo",
		Status:       "disconnected",
		SessionID:    "sid-1",
		Command:      "bash",
		Reconnect:    "unsupported",
		TunnelReason: "reconnect_unsupported",
		TunnelLostAt: lost,
	}, 80, at)

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
	at := lost.Add(5 * time.Second)

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
			assert.Equal(t, tc.want, statusTextAt(tc.detail, at))
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

	before := next.Add(-time.Nanosecond)
	withNext := withoutNext + ", next attempt " + clock(next)
	assert.Equal(t, withNext, statusTextAt(detail, before), "still ahead by one nanosecond")
	assert.Equal(t, withoutNext, statusTextAt(detail, next), "due this instant is not ahead")
	assert.Equal(t, withoutNext, statusTextAt(detail, next.Add(time.Nanosecond)), "behind by one nanosecond")
	assert.Equal(t, withNext, statusTextAt(detail, before), "a later instant did not change the earlier status")

	wantBefore := "Session: \n\n" + row("Status:", withNext) + row("Hint:", "upterm can't reach the relay; it keeps retrying.")
	wantDue := "Session: \n\n" + row("Status:", withoutNext) + row("Hint:", "upterm can't reach the relay; it keeps retrying.")
	assert.Equal(t, wantBefore, renderSessionDetailAt(detail, 80, before))
	assert.Equal(t, wantDue, renderSessionDetailAt(detail, 80, next))
	assert.Equal(t, wantBefore, renderSessionDetailAt(detail, 80, before), "a later instant did not change the earlier view")
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

// Test_renderSessionDetail_RowsByStatus: which of the two extra rows each
// status prints, in a view that has everything else a live session has.
func Test_renderSessionDetail_RowsByStatus(t *testing.T) {
	lost := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	at := lost.Add(time.Second)

	render := func(status, reconnect string) string {
		return renderSessionDetailAt(SessionDetail{
			Name: "demo", Status: status, SessionID: "sid-1", Command: "bash",
			Host: "ssh://example.com:22", SSHCommand: "ssh sid-1@example.com",
			Reconnect: reconnect, TunnelReason: "network", TunnelLostAt: lost,
		}, 80, at)
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

// A session with no allowlist says so wherever its detail is shown: the banner
// at start and every `session info` after. Whether the host was asked about
// the start does not change who can join, so it does not gate the row.
func Test_FormatSessionDetail_open(t *testing.T) {
	detail := SessionDetail{
		SessionID:  "test123",
		Command:    "bash",
		Host:       "ssh://example.com:22",
		SSHCommand: "ssh test123@example.com",
	}

	assert.NotContains(t, FormatSessionDetail(detail), "Access:", "access not known")

	detail.Access = AccessAllowlist
	assert.NotContains(t, FormatSessionDetail(detail), "Access:", "an allowlist says who can join in Authorized Keys")

	for _, open := range []bool{false, true} {
		detail.Access = AccessAnyone
		detail.Open = open
		assert.Contains(t, FormatSessionDetail(detail), row("Access:", "open: anyone with the session ID can join"), "open=%t", open)
	}

	detail.Access = ""
	detail.Open = true
	assert.NotContains(t, FormatSessionDetail(detail), "Access:", "the legacy flag alone is not the row's source")
}

func TestAccessShowsWheneverAnyoneCanJoin(t *testing.T) {
	d := SessionDetail{SessionID: "id", Access: "anyone"}
	require.Contains(t, FormatSessionDetail(d), row("Access:", "open: anyone with the session ID can join"))
	d.Access = "allowlist"
	require.NotContains(t, FormatSessionDetail(d), "Access:")
}

func TestGuestsRow(t *testing.T) {
	require.Equal(t, "can type; files: primary terminal approval required; no port forwarding",
		guestsRow(GuestPermissions{FileTransfer: "all", ApprovalRequired: true}))
	require.Equal(t, "watch only; files: downloads only, primary terminal approval required; no port forwarding",
		guestsRow(GuestPermissions{ReadOnly: true, FileTransfer: "downloads", ApprovalRequired: true}))
	require.Equal(t, "can type; files: allowed without asking; port forwarding allowed",
		guestsRow(GuestPermissions{FileTransfer: "all", LocalForwarding: true}))
	require.Equal(t, "can type; files: off; no port forwarding",
		guestsRow(GuestPermissions{FileTransfer: "off"}))
}

// A file transfer value the view doesn't know is said to be unknown, never
// read as transfers allowed without asking. guestPermissions passes only the
// three it knows, so this is the row's own guard.
func TestGuestsRowReadsNoUnknownTransferAsAllowed(t *testing.T) {
	for _, v := range []string{"", "uploads"} {
		require.Equal(t, "can type; files: unknown; no port forwarding", guestsRow(GuestPermissions{FileTransfer: v}), "%q", v)
	}
}

// Test_guestsRow_EveryCombination: each of the four settings changes its own
// clause and no other, so a guest reading the row is told about each of them.
// Forwarding is a setting of its own, so every row ends with its clause,
// watch-only or not.
func Test_guestsRow_EveryCombination(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		for _, transfer := range []string{FileTransferOff, FileTransferDownloads, FileTransferAll} {
			for _, approval := range []bool{false, true} {
				for _, forwarding := range []bool{false, true} {
					p := GuestPermissions{ReadOnly: readOnly, FileTransfer: transfer, ApprovalRequired: approval, LocalForwarding: forwarding}
					parts := strings.Split(guestsRow(p), "; ")
					require.Len(t, parts, 3, "%+v: %q", p, guestsRow(p))

					wantTyping := "can type"
					if readOnly {
						wantTyping = "watch only"
					}
					assert.Equal(t, wantTyping, parts[0], "%+v", p)

					waits := "allowed without asking"
					if approval {
						waits = "primary terminal approval required"
					}
					wantFiles := map[string]string{
						FileTransferOff:       "files: off",
						FileTransferDownloads: "files: downloads only, " + waits,
						FileTransferAll:       "files: " + waits,
					}[transfer]
					assert.Equal(t, wantFiles, parts[1], "%+v", p)

					wantForwarding := "no port forwarding"
					if forwarding {
						wantForwarding = "port forwarding allowed"
					}
					assert.Equal(t, wantForwarding, parts[2], "%+v", p)
				}
			}
		}
	}
}

// The Guests row sits after the access it qualifies and before the commands
// that let guests in, and exists only for a daemon that reported permissions.
func Test_renderSessionDetail_GuestsRowPosition(t *testing.T) {
	detail := SessionDetail{
		Name:           "demo",
		Status:         "ready",
		SessionID:      "sid-1",
		Command:        "bash",
		ForceCommand:   "tmux attach",
		Host:           "ssh://example.com",
		AuthorizedKeys: "alice:\n- SHA256:abc",
		Access:         AccessAnyone,
		SSHCommand:     "ssh sid-1@example.com",
		Guests:         &GuestPermissions{FileTransfer: FileTransferAll, ApprovalRequired: true},
	}

	want := "Session: sid-1\n\n" +
		row("Name:", "demo") +
		row("Status:", "ready") +
		row("Command:", "bash") +
		row("Force Command:", "tmux attach") +
		row("Relay:", "ssh://example.com") +
		row("Authorized Keys:", "alice:") +
		row("", "- SHA256:abc") +
		row("Access:", "open: anyone with the session ID can join") +
		row("Guests:", "can type; files: primary terminal approval required; no port forwarding") +
		"\n➤ SSH:\n    ssh sid-1@example.com\n"
	assert.Equal(t, want, renderSessionDetail(detail, 80))

	detail.Guests = nil
	assert.NotContains(t, renderSessionDetail(detail, 80), "Guests:", "a daemon that did not report permissions gets no row")
}

// The join timeout is a row of its own, in the labels' column with the rows
// that describe the session, so it sits above the commands and the connected
// guests instead of under the last of them. The caller words it; a view with
// nothing to say about it has no row.
func Test_renderSessionDetail_JoinRow(t *testing.T) {
	detail := SessionDetail{
		Name:             "demo",
		Status:           "ready",
		SessionID:        "sid-1",
		Command:          "bash",
		Host:             "ssh://example.com",
		Access:           AccessAnyone,
		SSHCommand:       "ssh sid-1@example.com",
		ConnectedClients: []string{"guest 203.0.113.7:51234 SSH-2.0-OpenSSH_9.6"},
		JoinLabel:        "Join deadline:",
		JoinValue:        "2026-10-12 22:31:02 PDT (from the record; the session did not answer)",
	}

	want := "Session: sid-1\n\n" +
		row("Name:", "demo") +
		row("Status:", "ready") +
		row("Command:", "bash") +
		row("Relay:", "ssh://example.com") +
		row("Access:", "open: anyone with the session ID can join") +
		row("Join deadline:", "2026-10-12 22:31:02 PDT (from the record; the session did not answer)") +
		"\n➤ SSH:\n    ssh sid-1@example.com\n" +
		"\nConnected:\n  guest 203.0.113.7:51234 SSH-2.0-OpenSSH_9.6\n"
	assert.Equal(t, want, renderSessionDetail(detail, 80))

	detail.JoinLabel, detail.JoinValue = "", ""
	assert.NotContains(t, renderSessionDetail(detail, 80), "Join", "nothing to say, no row")
}

// The summary lines its rows up with the view's, so the two read as one
// layout: the label column is the view's.
func TestLabelWidthIsTheViewsLabelColumn(t *testing.T) {
	out := renderSessionDetail(SessionDetail{SessionID: "id", Name: "demo"}, 80)
	assert.Contains(t, out, fmt.Sprintf("%-*s%s\n", LabelWidth, "Name:", "demo"))
}

// pinTerminal makes the view think stdout is a terminal, which is when it wraps.
func pinTerminal(t *testing.T) {
	t.Helper()
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = func() bool { return false } })
}

func TestCommandsAreNeverHardWrapped(t *testing.T) {
	pinTerminal(t)
	long := "ssh -o ProxyCommand='upterm proxy '\\''wss://id:bm9kZQ==@relay.example.com'\\''' id:bm9kZQ==@relay.example.com:443"
	out := renderSessionDetail(SessionDetail{SessionID: "id", SSHCommand: long}, 80)
	require.Contains(t, out, "    "+long+"\n")
}

// Commands and connected clients are what a person copies out of the view, so
// they are never cut: each is one line, and a terminal narrower than it
// soft-wraps it where a copy still gets it whole.
func TestEveryCommandAndClientPrintsWhole(t *testing.T) {
	pinTerminal(t)

	long := func(s string) string { return s + " " + strings.Repeat("x", 120) }
	detail := SessionDetail{
		SessionID:   "id",
		JoinCommand: long("upterm join"),
		SSHCommand:  long("ssh"),
		SFTPEnabled: true,
		SFTPCommand: long("sftp"),
		SCPUpload:   long("scp <local>"),
		SCPDownload: long("scp <remote>"),
		ConnectedClients: []string{
			long("guest 203.0.113.7:51234 SSH-2.0-OpenSSH_9.6"),
			long("forward 203.0.113.8:51235 SSH-2.0-OpenSSH_9.6"),
		},
	}

	want := "Session: id\n\n" +
		"\n➤ Join:\n    " + detail.JoinCommand + "\n" +
		"➤ SSH:\n    " + detail.SSHCommand + "\n" +
		"➤ SFTP:\n    " + detail.SFTPCommand + "\n" +
		"➤ SCP:\n    " + detail.SCPUpload + "\n    " + detail.SCPDownload + "\n" +
		"\nConnected:\n  " + detail.ConnectedClients[0] + "\n  " + detail.ConnectedClients[1] + "\n"
	assert.Equal(t, want, renderSessionDetail(detail, 80))
}

// The ssh config block is two files' lines a person pastes, so it prints
// last among the commands, each of its lines whole and indented as they
// are, its own indentation kept.
func TestSSHConfigPrintsWholeUnderTheCommands(t *testing.T) {
	pinTerminal(t)
	block := "# ~/.ssh/config\nHost home\n  HostName uptermd.upterm.dev\n  User " + strings.Repeat("x", 120) + "\n" +
		"# ~/.ssh/known_hosts, once per device\nuptermd.upterm.dev ssh-ed25519 AAAA\n"
	detail := SessionDetail{SessionID: "id", SSHCommand: "ssh id@h", SSHConfig: block}
	assert.Equal(t, "Session: id\n\n"+
		"\n➤ SSH:\n    ssh id@h\n"+
		"➤ SSH config:\n"+
		"    # ~/.ssh/config\n"+
		"    Host home\n"+
		"      HostName uptermd.upterm.dev\n"+
		"      User "+strings.Repeat("x", 120)+"\n"+
		"    # ~/.ssh/known_hosts, once per device\n"+
		"    uptermd.upterm.dev ssh-ed25519 AAAA\n",
		renderSessionDetail(detail, 80))

	// It is a way in of its own, so the commands' section opens for it.
	detail.SSHCommand = ""
	require.True(t, strings.HasPrefix(renderSessionDetail(detail, 80), "Session: id\n\n\n➤ SSH config:\n"))
}

// A guest's version string is theirs to choose, and the view prints it as
// text: an escape sequence or a control character in it comes out as '?',
// the way ~? prints it, rather than reaching the terminal reading the view.
func TestConnectedRowsPrintAGuestsVersionAsText(t *testing.T) {
	detail := SessionDetail{
		SessionID: "id",
		ConnectedClients: []string{
			"guest 203.0.113.7:51234 SSH-2.0-\x1b]0;owned\x07\x1b[2J\x9b1m\u009b2m\x00\x7f\r SHA256:def",
		},
	}

	out := FormatSessionDetail(detail)
	assert.Equal(t, "Session: id\n\n"+
		"\nConnected:\n"+
		"  guest 203.0.113.7:51234 SSH-2.0-?]0;owned??[2J?1m?2m??? SHA256:def\n", out)
	for _, r := range out {
		if r != '\n' {
			require.False(t, unicode.IsControl(r), "%q in %q", r, out)
		}
	}
}

func Test_renderSessionDetail_ConnectedRow(t *testing.T) {
	detail := SessionDetail{
		SessionID:        "id",
		ConnectedClients: []string{"host local SSH-2.0-upterm-attach SHA256:abc", "guest 203.0.113.7:51234 SSH-2.0-OpenSSH_9.6 SHA256:def"},
	}

	out := renderSessionDetail(detail, 80)
	assert.Equal(t, "Session: id\n\n"+
		"\nConnected:\n"+
		"  host local SSH-2.0-upterm-attach SHA256:abc\n"+
		"  guest 203.0.113.7:51234 SSH-2.0-OpenSSH_9.6 SHA256:def\n", out)

	detail.ConnectedClients = nil
	assert.NotContains(t, renderSessionDetail(detail, 80), "Connected")
}

// Losing any new policy field, or coercing absent policy to off, changes what
// the view tells guests. The legacy row remains usable with absent pointers.
func TestGuestToolPolicyRows(t *testing.T) {
	for _, shell := range []string{"shared", "login", "forced"} {
		for _, exec := range []string{"off", "approval", "granted", "forced"} {
			for _, forward := range []string{"off", "loopback-approval", "loopback", "all"} {
				for _, method := range []string{"terminal", "custom", "unavailable"} {
					p := GuestPermissions{FileTransfer: FileTransferAll, GuestShell: &shell, Execution: &exec, TCPForwarding: &forward, ApprovalMethod: &method}
					row := guestsRow(p)
					for _, text := range []string{"shell: " + shell, "exec: " + exec, "forwarding: " + forward, "approval: " + method} {
						require.Contains(t, row, text)
					}
				}
			}
		}
	}
	detail := SessionDetail{LoginCommand: "herdr", Guests: &GuestPermissions{ReadOnly: true, FileTransfer: FileTransferDownloads}}
	got := renderSessionDetail(detail, 120)
	require.Contains(t, got, "Login Command:")
	require.Contains(t, got, "herdr")
	require.NotContains(t, got, "exec: off")
	require.NotContains(t, got, "shell: shared")
	require.NotContains(t, got, "approval:")
}

// testDelegation is a delegated session's record as its host writes it.
func testDelegation(authority string) *sessiondir.Delegation {
	return &sessiondir.Delegation{
		DelegationAssociation: sessiondir.DelegationAssociation{Service: "https://authority.example", Account: "a", Login: "l"},
		DelegationDisplay: sessiondir.DelegationDisplay{
			Authority: authority,
			Links:     []sessiondir.DelegationLink{{Label: "Dashboard", URL: "https://authority.example/s"}, {Label: "Help", URL: "https://authority.example/help"}},
			Notes:     []string{"Verify the relay key before connecting.", "Guests sign in first."},
		},
		ExternalSessionID: "33333333-3333-4333-8333-333333333333",
		RoutingID:         "abcdefghijklmnopqrst",
		Relay:             "relay.example.com:22",
		GuestAddress:      "claim-work",
	}
}

// A delegated session's view is titled with its guest address, says its
// authority decides who joins, and offers the ssh command and URI alone,
// then the authority's links and notes: no join line, no SFTP or SCP, no
// ssh config, and nothing that says anyone with an ID can join.
func TestDelegatedDetailRows(t *testing.T) {
	detail := SessionDetail{
		Name:             "work",
		SessionID:        "abcdefghijklmnopqrst",
		Command:          "bash",
		Host:             "ssh://relay.example.com",
		JoinCommand:      "upterm join ssh://claim-work@relay.example.com",
		SSHCommand:       "ssh claim-work@relay.example.com",
		URI:              "ssh://claim-work@relay.example.com",
		SFTPEnabled:      true,
		SFTPCommand:      "sftp claim-work@relay.example.com",
		SCPUpload:        "scp <local> claim-work@relay.example.com:<remote>",
		SSHConfig:        "Host work\n",
		Access:           AccessDelegated,
		ConnectedClients: []string{"guest 192.0.2.1 SSH-2.0-OpenSSH_9.9 SHA256:abc"},
		Delegation:       testDelegation("Example Authority"),
	}
	assert.Equal(t, "Session: claim-work\n\n"+
		row("Name:", "work")+
		row("Command:", "bash")+
		row("Relay:", "ssh://relay.example.com")+
		row("Access:", "decided by Example Authority")+
		"\n➤ SSH:\n    ssh claim-work@relay.example.com\n"+
		"➤ URI:\n    ssh://claim-work@relay.example.com\n"+
		"➤ Dashboard: https://authority.example/s\n"+
		"➤ Help: https://authority.example/help\n"+
		"Verify the relay key before connecting.\n"+
		"Guests sign in first.\n"+
		"\nConnected:\n  guest 192.0.2.1 SSH-2.0-OpenSSH_9.9 SHA256:abc\n",
		renderSessionDetail(detail, 80))

	// The authority's name may be empty: the view names it all the same.
	detail.Delegation = testDelegation("")
	assert.Contains(t, renderSessionDetail(detail, 80), row("Access:", "decided by the session's authority"))

	// Not answering: no way in is offered, while the links and notes, which
	// the record holds, still are.
	detail.SSHCommand, detail.URI, detail.ConnectedClients = "", "", nil
	got := renderSessionDetail(detail, 80)
	assert.NotContains(t, got, "➤ SSH:")
	assert.NotContains(t, got, "➤ URI:")
	assert.Contains(t, got, "\n➤ Dashboard: https://authority.example/s\n")
	assert.NotContains(t, got, "abcdefghijklmnopqrst", "the routing ID is in no line")
}

// Whatever a record from elsewhere holds, the authority's words are each one
// line, with nothing in them that acts on a terminal.
func TestDelegatedDetailKeepsTheAuthoritysWordsToALine(t *testing.T) {
	d := testDelegation("Example\nAuthority\x1b[2J")
	d.Links = []sessiondir.DelegationLink{{Label: "Dash\nboard", URL: "https://authority.example/\ns"}}
	d.Notes = []string{"one\ntwo"}
	got := renderSessionDetail(SessionDetail{Name: "work", Access: AccessDelegated, Delegation: d}, 80)
	assert.Contains(t, got, row("Access:", "decided by Example�Authority�[2J"))
	assert.Contains(t, got, "➤ Dash�board: https://authority.example/�s\n")
	assert.Contains(t, got, "one�two\n")
	assert.NotContains(t, got, "\x1b")
}

// The hints of the reasons an authority gives name it, with the session's
// name where there is one; with no name for the authority, the phrase that
// stands for it.
func TestDelegatedStatusHints(t *testing.T) {
	for _, tc := range []struct{ authority, mid, start string }{
		{"Example Authority", "Example Authority", "Example Authority"},
		{"", "the session's authority", "The session's authority"},
	} {
		d := testDelegation(tc.authority)
		assert.Equal(t, "the relay refused this session's registration with "+tc.mid+"; upterm keeps retrying, slowly.",
			StatusHint(SessionDetail{Status: "reconnecting", TunnelReason: "authority_refused", Delegation: d}))
		assert.Equal(t, tc.start+" withdrew remote access. The command is still running locally.",
			StatusHint(SessionDetail{Status: "disconnected", TunnelReason: "withdrawn", Delegation: d}))
		assert.Equal(t, tc.start+" withdrew remote access. The command is still running locally as work. "+
			"Use upterm attach work to return, or upterm session stop work to stop it.",
			StatusHint(SessionDetail{Name: "work", Status: "disconnected", TunnelReason: "withdrawn", Delegation: d}))
	}
	// A reader without the record still names who decided, as the phrase.
	assert.Equal(t, "the relay refused this session's registration with the session's authority; upterm keeps retrying, slowly.",
		StatusHint(SessionDetail{Status: "reconnecting", TunnelReason: "authority_refused"}))
	// Reserved, with no hint yet: none is guessed.
	assert.Empty(t, StatusHint(SessionDetail{Status: "reconnecting", TunnelReason: "trust_lapsed", Delegation: testDelegation("")}))
}
