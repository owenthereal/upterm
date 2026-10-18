package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
	"github.com/muesli/reflow/wrap"
	"github.com/owenthereal/upterm/host/sessiondir"
	uio "github.com/owenthereal/upterm/io"
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

// TermWidth returns the terminal width, defaulting to 80 if unavailable
func TermWidth() int {
	return getTermWidth()
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
	JoinCommand      string // upterm join, for guests who have upterm
	SSHCommand       string
	SFTPEnabled      bool   // Whether SFTP/SCP is enabled
	SFTPCommand      string // SFTP command
	SCPUpload        string // SCP upload example
	SCPDownload      string // SCP download example
	AuthorizedKeys   string
	ConnectedClients []string
	// Open is true when anyone with the session ID can join and nobody was
	// asked: no allowlist, and started with --accept. It is what the JSON's
	// open field reports; the view reads Access, which doesn't depend on
	// whether anyone was asked.
	Open bool

	// Access is AccessAnyone (no allowlist) or AccessAllowlist; "" when
	// unknown.
	Access string
	// Guests is what guests may do; nil when the daemon doesn't report it.
	Guests *GuestPermissions

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

	// JoinLabel and JoinValue are the join timeout's row: its label ("Join
	// timeout:" or "Join deadline:") and what it says, which the caller words
	// since it depends on where the state came from. Both are empty when
	// there is nothing to say, and the view then has no row.
	JoinLabel string
	JoinValue string
}

// LabelWidth is the width of the label column, in the view and in any text
// that lines its rows up with it.
const LabelWidth = 18

// The values of SessionDetail.Access.
const (
	AccessAnyone    = "anyone"
	AccessAllowlist = "allowlist"
)

// The values of GuestPermissions.FileTransfer, as the admin API reports them.
const (
	FileTransferOff       = "off"
	FileTransferDownloads = "downloads"
	FileTransferAll       = "all"
)

// GuestPermissions is what the host lets guests do, as the daemon reports it.
type GuestPermissions struct {
	ReadOnly         bool
	FileTransfer     string // FileTransferOff, FileTransferDownloads or FileTransferAll
	ApprovalRequired bool   // false whenever FileTransfer is FileTransferOff
	LocalForwarding  bool
}

// guestsRow is the Guests row's value: whether guests can type, what they may
// do with files, and whether they may forward ports, in that order. The last
// clause is always there, read-only or not: forwarding is a setting of its own
// that the daemon reports, so a watch-only row says it too rather than leaving
// a guest to infer it.
func guestsRow(p GuestPermissions) string {
	typing := "can type"
	if p.ReadOnly {
		typing = "watch only"
	}

	approval := "allowed without asking"
	if p.ApprovalRequired {
		approval = "approval required"
	}
	var files string
	switch p.FileTransfer {
	case FileTransferOff:
		files = "files: off"
	case FileTransferDownloads:
		files = "files: downloads only, " + approval
	case FileTransferAll:
		files = "files: " + approval
	default:
		// guestPermissions passes only the three values above. One this view
		// doesn't know is not read as any of them, least of all as transfers
		// allowed without asking.
		files = "files: unknown"
	}

	forwarding := "no port forwarding"
	if p.LocalForwarding {
		forwarding = "port forwarding allowed"
	}

	return strings.Join([]string{typing, files, forwarding}, "; ")
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
		parts = append(parts, "since "+ClockTime(detail.TunnelLostAt))
	}
	text := strings.Join(parts, " ")
	if detail.NextAttemptAt.After(now()) {
		if text != "" {
			text += ", "
		}
		text += "next attempt " + ClockTime(detail.NextAttemptAt)
	}
	if text == "" {
		return detail.Status
	}
	return detail.Status + " — " + text
}

// ClockTime is t as the status text gives a time: local, to the second.
func ClockTime(t time.Time) string { return t.Local().Format("15:04:05") }

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

// WrapProse wraps a sentence to width at spaces, as the detail view does for
// its status and hint rows. Unlike the view it does not look at the terminal:
// the caller decides whether to wrap at all. Empty text comes back as one empty
// line, so a row with no value still has a line to print.
func WrapProse(text string, width int) []string {
	return wordWrapLines(text, width)
}

// writeWhole writes text indented, with no line of it cut. It is for what a
// person copies out of the view, a command or a connected client's line: a
// newline in the middle of a command would paste as two commands. A terminal
// narrower than the line soft-wraps it, which a copy still reads as one line.
// An embedded newline still starts a new line. Empty text writes nothing.
func writeWhole(b *strings.Builder, indent int, style lipgloss.Style, text string) {
	if text == "" {
		return
	}
	for _, line := range strings.Split(text, "\n") {
		b.WriteString(strings.Repeat(" ", indent) + style.Render(line) + "\n")
	}
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
	labelWidth := LabelWidth
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
		renderWrappedRow(&b, "Relay:", detail.Host, labelWidth, valueWidth, ValueStyle)
	}
	if detail.AuthorizedKeys != "" {
		renderWrappedRow(&b, "Authorized Keys:", detail.AuthorizedKeys, labelWidth, valueWidth, ValueStyle)
	}
	// Where the allowlist would be: its absence is what makes the session
	// open, and nothing else on the screen says so. Whether the host was asked
	// about the start doesn't change who can join, so it doesn't gate the row.
	if detail.Access == AccessAnyone {
		renderProseRow(&b, "Access:", "open: anyone with the session ID can join", labelWidth, valueWidth, ValueStyle)
	}
	// What those who can join may do. A daemon that doesn't report it has no
	// row rather than one that guesses.
	if detail.Guests != nil {
		renderProseRow(&b, "Guests:", guestsRow(*detail.Guests), labelWidth, valueWidth, ValueStyle)
	}
	// The join timeout is a setting of the session like the rows above, so it
	// sits with them in the labels' column. After the last client it ran
	// under the guests, out of line with everything else.
	if detail.JoinLabel != "" {
		renderProseRow(&b, detail.JoinLabel, detail.JoinValue, labelWidth, valueWidth, ValueStyle)
	}

	// Commands section - each command on its own line for readability.
	const cmdIndent = 4

	writeCommand := func(label, command string) {
		// Every block is gated on the command it would print. Only a session
		// that answered for itself has one, and a "➤ SSH:" heading over a
		// single empty line offers a way to join that does not exist.
		if command == "" {
			return
		}
		b.WriteString(LabelStyle.Render(label) + "\n")
		writeWhole(&b, cmdIndent, CommandStyle, command)
	}

	// SFTP and SCP commands (only shown if SFTP is enabled)
	sftp := detail.SFTPEnabled && detail.SFTPCommand != ""
	if detail.JoinCommand != "" || detail.SSHCommand != "" || sftp {
		b.WriteString("\n")
	}

	// Join first: it's the front door, and the ssh line under it serves
	// guests without upterm.
	writeCommand("➤ Join:", detail.JoinCommand)
	writeCommand("➤ SSH:", detail.SSHCommand)
	if sftp {
		writeCommand("➤ SFTP:", detail.SFTPCommand)
		if detail.SCPUpload != "" || detail.SCPDownload != "" {
			b.WriteString(LabelStyle.Render("➤ SCP:") + "\n")
			for _, cmd := range []string{detail.SCPUpload, detail.SCPDownload} {
				writeWhole(&b, cmdIndent, CommandStyle, cmd)
			}
		}
	}

	// Connected clients, one per line. Each is printed as text: a guest's
	// version string is theirs to choose, and their client sends whatever it
	// likes there, escape sequences included. The view prints it the way ~?
	// does; the JSON keeps it as the daemon reported it.
	if len(detail.ConnectedClients) > 0 {
		b.WriteString("\n")
		b.WriteString(LabelStyle.Render("Connected:") + "\n")
		for _, client := range detail.ConnectedClients {
			writeWhole(&b, 2, ValueStyle, uio.PlainText(client))
		}
	}

	return b.String()
}
