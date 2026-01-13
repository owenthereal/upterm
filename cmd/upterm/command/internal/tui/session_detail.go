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

	// Title
	b.WriteString(TitleStyle.Render(fmt.Sprintf("Session: %s", detail.SessionID)))
	b.WriteString("\n\n")

	// Layout constants
	labelWidth := 18
	valueWidth := max(width-labelWidth-2, 20)

	// Basic fields (skip empty fields to reduce noise)
	renderWrappedRow(&b, "Command:", detail.Command, labelWidth, valueWidth, ValueStyle)
	if detail.ForceCommand != "" {
		renderWrappedRow(&b, "Force Command:", detail.ForceCommand, labelWidth, valueWidth, ValueStyle)
	}
	renderWrappedRow(&b, "Host:", detail.Host, labelWidth, valueWidth, ValueStyle)
	if detail.AuthorizedKeys != "" {
		renderWrappedRow(&b, "Authorized Keys:", detail.AuthorizedKeys, labelWidth, valueWidth, ValueStyle)
	}

	// Commands section - each command on its own line for readability
	// Use wrapping to prevent truncation on narrow terminals
	cmdIndent := 4
	cmdWidth := max(width-cmdIndent-2, 20)

	b.WriteString("\n")
	b.WriteString(LabelStyle.Render("➤ SSH:") + "\n")
	for _, line := range wrapLines(detail.SSHCommand, cmdWidth) {
		b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
	}

	// SFTP and SCP commands (only shown if SFTP is enabled)
	if detail.SFTPEnabled {
		b.WriteString(LabelStyle.Render("➤ SFTP:") + "\n")
		for _, line := range wrapLines(detail.SFTPCommand, cmdWidth) {
			b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
		}
		b.WriteString(LabelStyle.Render("➤ SCP:") + "\n")
		for _, line := range wrapLines(detail.SCPUpload, cmdWidth) {
			b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
		}
		for _, line := range wrapLines(detail.SCPDownload, cmdWidth) {
			b.WriteString(strings.Repeat(" ", cmdIndent) + CommandStyle.Render(line) + "\n")
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
