package tui

import (
	"strings"
	"testing"

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
