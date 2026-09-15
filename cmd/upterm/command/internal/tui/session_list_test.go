package tui

import (
	"testing"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"
)

// Test_NewSessionListModel_RowsCarryStatus pins the column that makes a
// session no admin socket answered for legible. The listing now includes
// sessions this environment cannot reach, and without a status such a row is a
// name followed by empty cells — indistinguishable from a broken entry, when
// what it means is "starting" or "running somewhere you cannot see from here".
func Test_NewSessionListModel_RowsCarryStatus(t *testing.T) {
	m := NewSessionListModel([]SessionDetail{
		{Name: "live", Status: "ready", SessionID: "sid-1", Command: "bash", Host: "ssh://example.com:22"},
		{Name: "elsewhere", Status: "disconnected", SessionID: "sid-2", Command: "bash"},
	})

	require.Equal(t, []table.Row{
		{"", "live", "ready", "sid-1", "bash", "ssh://example.com:22"},
		{"", "elsewhere", "disconnected", "sid-2", "bash", ""},
	}, m.table.Rows())

	columns := calculateColumns(80)
	require.Equal(t, "STATUS", columns[2].Title, "the status belongs beside the name it qualifies")
	require.GreaterOrEqual(t, columns[2].Width, len("disconnected"),
		"the longest status a session publishes has to fit without being cut")
}

// Test_SessionListModel_FitsAnEightyColumnTerminal guards the budget the
// STATUS column is taken from. Eighty is both the conventional width and what
// getTermWidth falls back to when stdout is not a terminal, so a table that
// overflows it wraps every row in the output a pipe gets.
func Test_SessionListModel_FitsAnEightyColumnTerminal(t *testing.T) {
	// Measured, not modelled: how far bubbles pads a cell is bubbles' business,
	// and a change to it is exactly what this is here to catch. The width is
	// delivered as a resize because the one NewSessionListModel starts from is
	// whatever terminal the test happens to run under.
	m := NewSessionListModel([]SessionDetail{{
		Name:      "build-shell",
		Status:    "disconnected",
		SessionID: "0dc0b3ce-8f4f-4a2b-9d12-1f9b1c2d3e4f",
		Command:   "bash -lc 'make test'",
		Host:      "ssh://uptermd.upterm.dev:22",
	}})
	resized, _ := m.Update(tea.WindowSizeMsg{Width: 80})

	require.LessOrEqual(t, lipgloss.Width(resized.(SessionListModel).table.View()), 80,
		"the rendered table must fit the width it was sized for")
}
