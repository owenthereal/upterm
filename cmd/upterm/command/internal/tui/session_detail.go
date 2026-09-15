package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wrap"
	"golang.org/x/term"
)

// IsTTY returns whether stdout is a terminal
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// getTermWidth returns the terminal width, defaulting to 80 if unavailable
func getTermWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80
	}
	return width
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

// renderWrappedRow renders a label: value row with wrapping, continuation lines indented
func renderWrappedRow(b *strings.Builder, label string, value string, labelWidth int, valueWidth int, style lipgloss.Style) {
	l := LabelStyle.Width(labelWidth).Render(label)
	lines := wrapLines(value, valueWidth)
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
		renderWrappedRow(&b, "Status:", detail.Status, labelWidth, valueWidth, ValueStyle)
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
