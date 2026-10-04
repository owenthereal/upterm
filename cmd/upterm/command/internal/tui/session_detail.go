package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
	"github.com/muesli/reflow/wrap"
	"github.com/owenthereal/upterm/host/sessiondir"
	"golang.org/x/term"
)

// stdoutIsTerminal and getTermWidth read stdout. They are variables so the
// package's tests can pin them: what a test sees must not depend on whether
// `go test` was run from a terminal.
var (
	stdoutIsTerminal = func() bool {
		return term.IsTerminal(int(os.Stdout.Fd()))
	}

	// getTermWidth returns the terminal width, defaulting to 80 if unavailable
	getTermWidth = func() int {
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return 80
		}
		return width
	}
)

// IsTTY returns whether stdout is a terminal
func IsTTY() bool {
	return stdoutIsTerminal()
}

// RunModel runs a bubbletea model with automatic TTY detection.
// For non-TTY environments, just prints View() once and returns.
func RunModel(model tea.Model) (tea.Model, error) {
	if !IsTTY() {
		// Non-TTY: print View() once (lipgloss auto-strips colors)
		fmt.Print(model.View())
		return model, nil
	}
	p := tea.NewProgram(model, tea.WithAltScreen())
	return p.Run()
}

// SessionDetail holds session information for display
type SessionDetail struct {
	IsCurrent        bool
	AdminSocket      string
	Name             string
	Status           string
	SessionID        string
	Command          string
	ForceCommand     string
	Host             string
	SSHCommand       string
	SFTPEnabled      bool   // Whether SFTP/SCP is enabled
	SFTPCommand      string // SFTP command
	SCPUpload        string // SCP upload example
	SCPDownload      string // SCP download example
	AuthorizedKeys   string
	ConnectedClients []string

	// Reconnect is "supported" or "unsupported" once the first connection has
	// shown whether the relay lets a dropped session come back under the same
	// connect string. The tunnel fields describe the latest outage: why the
	// latest attempt failed (one of sessiondir's TunnelReason values), when
	// the outage began, and when the next attempt is due. A live session
	// clears them when its tunnel comes back; only an ended session's record
	// keeps its last outage. They are zero when there has been none or the
	// caller has no record to read them from.
	Reconnect     string
	TunnelReason  string
	TunnelLostAt  time.Time
	NextAttemptAt time.Time
}

// now is the clock the status text compares a next attempt against. A variable
// so a test can pin it instead of sleeping.
var now = time.Now

// tunnelHints say what to do, or what to expect, for each reason a tunnel
// went down. The values of sessiondir's TunnelReason are a stable contract, so
// a reason this version doesn't know has no entry and gets no hint rather than
// a guess.
var tunnelHints = map[string]string{
	sessiondir.TunnelReasonNetwork:              "upterm can't reach the relay; it keeps retrying.",
	sessiondir.TunnelReasonRelayError:           "the relay was reached but couldn't register the session; upterm keeps retrying.",
	sessiondir.TunnelReasonAgentUnavailable:     "the SSH agent can't be reached (not running, or restarting); upterm keeps retrying.",
	sessiondir.TunnelReasonAgentRefused:         "the SSH agent didn't sign: approve or unlock it, or restart the session with a key file (--private-key).",
	sessiondir.TunnelReasonAuthRefused:          "the relay refused every identity offered; if its --authorized-keys changed, add your key back.",
	sessiondir.TunnelReasonRelayKeyChanged:      "the relay's key differs from the one this session started with; not accepted. If the change is legitimate, restart the session.",
	sessiondir.TunnelReasonRelayUnsupported:     "the relay node reached doesn't support reconnecting (as during a rollback); upterm keeps retrying.",
	sessiondir.TunnelReasonProofRefused:         "the relay refused this session's proof of its key; upterm keeps retrying.",
	sessiondir.TunnelReasonReconnectUnsupported: "this relay doesn't support reconnecting, so guests can't reach this session again. Restart it for a new connect string.",
}

// StatusText is the status row's value. A reconnecting session says why it is
// down, since when, and when it tries next; every other status is its plain
// word. A disconnected session's hint row says why, and the outage an ended
// session's record keeps is not something to act on. Times are local, to the
// second.
//
// Each piece is left out when it isn't known. A next attempt that is not
// ahead of the clock is left out too: it is stamped as each wait starts, so
// it is already past during every attempt and after a sleeping machine wakes
// mid-wait, and printing it would promise a retry that has already happened.
func StatusText(detail SessionDetail) string {
	if detail.Status != sessiondir.StatusReconnecting {
		return detail.Status
	}

	var parts []string
	if detail.TunnelReason != "" {
		parts = append(parts, detail.TunnelReason)
	}
	if !detail.TunnelLostAt.IsZero() {
		parts = append(parts, "since "+clockTime(detail.TunnelLostAt))
	}
	text := strings.Join(parts, " ")
	if detail.NextAttemptAt.After(now()) {
		if text != "" {
			text += ", "
		}
		text += "next attempt " + clockTime(detail.NextAttemptAt)
	}
	if text == "" {
		return detail.Status
	}
	return detail.Status + " — " + text
}

func clockTime(t time.Time) string { return t.Local().Format("15:04:05") }

// StatusHint is what the user can do about the outage, for the statuses that
// have one: a reconnecting session, and a disconnected one, whose reason says
// why it will not come back. Empty for every other status and for a reason
// without a hint.
func StatusHint(detail SessionDetail) string {
	switch detail.Status {
	case sessiondir.StatusReconnecting, sessiondir.StatusDisconnected:
		return tunnelHints[detail.TunnelReason]
	}
	return ""
}

// ReconnectNote says the relay can't bring a dropped session back, from the
// first connection on and at every status, since it stays true until the
// session ends. Empty when the relay can, or isn't known to yet.
func ReconnectNote(detail SessionDetail) string {
	if detail.Reconnect == sessiondir.ReconnectUnsupported {
		return "unsupported by this relay"
	}
	return ""
}

// FormatSessionDetail renders a SessionDetail to a string using terminal width
func FormatSessionDetail(detail SessionDetail) string {
	return renderSessionDetail(detail, getTermWidth())
}

// PrintSessionDetail prints session detail to stdout
func PrintSessionDetail(detail SessionDetail) {
	fmt.Print(FormatSessionDetail(detail))
}

// wrapLines wraps text to width and returns lines.
// For non-TTY output, skips wrapping since output may be piped to other tools,
// but still respects embedded newlines for proper layout.
func wrapLines(text string, width int) []string {
	if text == "" {
		return []string{}
	}
	if !IsTTY() {
		return strings.Split(text, "\n") // No wrapping, but respect newlines
	}
	wrapped := wrap.String(text, max(width, 10))
	return strings.Split(wrapped, "\n")
}

// wordWrapLines wraps prose to width at spaces and returns lines. A hyphen is
// not a place to break, so a flag like --authorized-keys stays whole. A single
// word longer than width is still cut at width, so no line exceeds it.
// Embedded newlines are kept. It does not look at the terminal; wrapProseLines
// decides whether to call it.
func wordWrapLines(text string, width int) []string {
	width = max(width, 10)
	// reflow's default breakpoint is '-', which it writes without counting it
	// toward the line, so a hyphenated word can be cut mid-word.
	w := wordwrap.NewWriter(width)
	w.Breakpoints = []rune{}
	_, _ = w.Write([]byte(text))
	_ = w.Close()
	return strings.Split(wrap.String(string(w.Bytes()), width), "\n")
}

// wrapProseLines is wrapLines for sentences (the status detail and the hint),
// which break at spaces instead of mid-word. Like wrapLines it leaves the text
// alone when stdout isn't a terminal.
func wrapProseLines(text string, width int) []string {
	if text == "" {
		return []string{}
	}
	if !IsTTY() {
		return strings.Split(text, "\n")
	}
	return wordWrapLines(text, width)
}

// renderWrappedRow renders a label: value row with wrapping, continuation lines indented
func renderWrappedRow(b *strings.Builder, label string, value string, labelWidth int, valueWidth int, style lipgloss.Style) {
	renderRow(b, label, wrapLines(value, valueWidth), labelWidth, style)
}

// renderProseRow is renderWrappedRow for a sentence: it breaks at spaces.
func renderProseRow(b *strings.Builder, label string, value string, labelWidth int, valueWidth int, style lipgloss.Style) {
	renderRow(b, label, wrapProseLines(value, valueWidth), labelWidth, style)
}

func renderRow(b *strings.Builder, label string, lines []string, labelWidth int, style lipgloss.Style) {
	l := LabelStyle.Width(labelWidth).Render(label)
	if len(lines) == 0 {
		b.WriteString(l + "\n")
		return
	}
	for i, line := range lines {
		if i == 0 {
			b.WriteString(l + style.Render(line) + "\n")
		} else {
			b.WriteString(strings.Repeat(" ", labelWidth) + style.Render(line) + "\n")
		}
	}
}

// renderSessionDetail generates the session detail content for the given width
func renderSessionDetail(detail SessionDetail, width int) string {
	var b strings.Builder

	// Layout constants
	labelWidth := 18
	valueWidth := max(width-labelWidth-2, 20)

	// Title. A session that has not reached ready has no session ID yet, and a
	// heading with nothing after it says less than nothing — so it falls back
	// to the name, which is what such a session was looked up by in the first
	// place.
	title := detail.SessionID
	if title == "" {
		title = detail.Name
	}
	b.WriteString(TitleStyle.Render(fmt.Sprintf("Session: %s", title)))
	b.WriteString("\n\n")

	// Name, if the session has one, is the first thing a user looks for when
	// they came here from 'upterm session list' or set --name themselves — so
	// it leads the labelled rows, under the title rather than above it. Above
	// it, the row sat outside the block it belongs to and read like a heading
	// for the heading.
	if detail.Name != "" {
		renderWrappedRow(&b, "Name:", detail.Name, labelWidth, valueWidth, ValueStyle)
	}

	// Status, where the caller knows one. For a session whose admin socket
	// this environment cannot reach it is the only thing below that is not
	// blank, and it is what distinguishes a session still starting, or running
	// under another XDG_RUNTIME_DIR, from one that is broken.
	if detail.Status != "" {
		renderProseRow(&b, "Status:", StatusText(detail), labelWidth, valueWidth, ValueStyle)
	}
	if hint := StatusHint(detail); hint != "" {
		renderProseRow(&b, "Hint:", hint, labelWidth, valueWidth, ValueStyle)
	}
	if note := ReconnectNote(detail); note != "" {
		renderWrappedRow(&b, "Reconnect:", note, labelWidth, valueWidth, ValueStyle)
	}

	// Basic fields (skip empty fields to reduce noise)
	if detail.Command != "" {
		renderWrappedRow(&b, "Command:", detail.Command, labelWidth, valueWidth, ValueStyle)
	}
	if detail.ForceCommand != "" {
		renderWrappedRow(&b, "Force Command:", detail.ForceCommand, labelWidth, valueWidth, ValueStyle)
	}
	if detail.Host != "" {
		renderWrappedRow(&b, "Host:", detail.Host, labelWidth, valueWidth, ValueStyle)
	}
	if detail.AuthorizedKeys != "" {
		renderWrappedRow(&b, "Authorized Keys:", detail.AuthorizedKeys, labelWidth, valueWidth, ValueStyle)
	}

	// Commands section - each command on its own line for readability
	// Use wrapping to prevent truncation on narrow terminals
	cmdIndent := 4
	cmdWidth := max(width-cmdIndent-2, 20)

	writeCommand := func(label, command string) {
		// Every block is gated on the command it would print. Only a session
		// that answered for itself has one, and a "➤ SSH:" heading over a
		// single empty line offers a way to join that does not exist.
		if command == "" {
			return
		}
		b.WriteString(LabelStyle.Render(label) + "\n")
		for _, line := range wrapLines(command, cmdWidth) {
			b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
		}
	}

	// SFTP and SCP commands (only shown if SFTP is enabled)
	sftp := detail.SFTPEnabled && detail.SFTPCommand != ""
	if detail.SSHCommand != "" || sftp {
		b.WriteString("\n")
	}

	writeCommand("➤ SSH:", detail.SSHCommand)
	if sftp {
		writeCommand("➤ SFTP:", detail.SFTPCommand)
		if detail.SCPUpload != "" || detail.SCPDownload != "" {
			b.WriteString(LabelStyle.Render("➤ SCP:") + "\n")
			for _, cmd := range []string{detail.SCPUpload, detail.SCPDownload} {
				for _, line := range wrapLines(cmd, cmdWidth) {
					b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
				}
			}
		}
	}

	// Connected clients
	if len(detail.ConnectedClients) > 0 {
		b.WriteString("\n")
		b.WriteString(LabelStyle.Render("Connected Clients:") + "\n")
		for _, client := range detail.ConnectedClients {
			for i, line := range wrapLines(client, width-4) {
				indent := 2
				if i > 0 {
					indent = 4
				}
				b.WriteString(strings.Repeat(" ", indent) + ValueStyle.Render(line) + "\n")
			}
		}
	}

	return b.String()
}
