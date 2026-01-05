package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SessionListModel provides an interactive session list using bubbles/table
type SessionListModel struct {
	table      table.Model
	sessions   []SessionDetail
	detailView *SessionDetail // nil when showing list, non-nil when showing detail
	quitting   bool
	width      int
}

// List-specific styles (extend base styles)
var (
	listHeaderStyle = TitleStyle.MarginBottom(1)
	listFooterStyle = FooterStyle.MarginTop(1)
)

// calculateColumns returns table columns sized for the given terminal width
func calculateColumns(width int) []table.Column {
	// Fixed column
	const markerWidth = 2
	// Table adds ~3 chars padding per column (borders + spacing)
	const columnPadding = 12 // 4 columns * 3

	available := width - markerWidth - columnPadding
	if available <= 0 {
		available = 40 // fallback minimum
	}

	// Proportional distribution: sessionID 35%, command 25%, host 40%
	sessionIDWidth := max(available*35/100, 10)
	commandWidth := max(available*25/100, 8)
	hostWidth := max(available-sessionIDWidth-commandWidth, 15)

	return []table.Column{
		{Title: "", Width: markerWidth},
		{Title: "SESSION ID", Width: sessionIDWidth},
		{Title: "COMMAND", Width: commandWidth},
		{Title: "HOST", Width: hostWidth},
	}
}

// NewSessionListModel creates a new interactive session list
func NewSessionListModel(sessions []SessionDetail) SessionListModel {
	width := getTermWidth()

	columns := calculateColumns(width)

	rows := make([]table.Row, len(sessions))
	cursorIdx := 0
	for i, s := range sessions {
		marker := ""
		if s.IsCurrent {
			marker = "*"
			cursorIdx = i
		}
		rows[i] = table.Row{marker, s.SessionID, s.Command, s.Host}
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(min(len(sessions)+1, 10)),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("236")).
		Bold(true)
	t.SetStyles(s)

	// Set cursor to current session
	t.SetCursor(cursorIdx)

	return SessionListModel{
		table:    t,
		sessions: sessions,
		width:    width,
	}
}

func (m SessionListModel) Init() tea.Cmd {
	return nil
}

func (m SessionListModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// If showing detail view, delegate to it
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		if m.detailView == nil {
			m.table.SetColumns(calculateColumns(msg.Width))
		}

	case tea.KeyMsg:
		// Handle detail view keys
		if m.detailView != nil {
			switch msg.String() {
			case "q", "esc", "enter", " ":
				m.detailView = nil
				return m, tea.ClearScreen
			case "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}

		// Handle list view keys
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if len(m.sessions) > 0 {
				selected := m.sessions[m.table.Cursor()]
				m.detailView = &selected
				return m, tea.ClearScreen
			}
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m SessionListModel) View() string {
	if m.quitting {
		return ""
	}

	// Show detail view if active
	if m.detailView != nil {
		content := renderSessionDetail(*m.detailView, m.width)
		footer := FooterStyle.Render("Press q or enter to go back")
		return content + "\n" + footer
	}

	if len(m.sessions) == 0 {
		header := listHeaderStyle.Render("Active Sessions (0)")
		empty := EmptyStyle.Render("  No active sessions found")
		if !IsTTY() {
			return fmt.Sprintf("%s\n%s\n", header, empty)
		}
		hint := listFooterStyle.Render("  Run 'upterm host' to share your terminal")
		return fmt.Sprintf("%s\n%s\n\n%s\n", header, empty, hint)
	}

	header := listHeaderStyle.Render(fmt.Sprintf("Active Sessions (%d)", len(m.sessions)))
	if !IsTTY() {
		return fmt.Sprintf("%s\n%s\n", header, m.table.View())
	}

	footer := listFooterStyle.Render("↑/↓: navigate • enter: view details • q: quit")
	return fmt.Sprintf("%s\n%s\n%s\n", header, m.table.View(), footer)
}
