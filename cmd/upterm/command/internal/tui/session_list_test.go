package tui

import (
	"testing"

	"github.com/charmbracelet/bubbles/table"
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

// Test_calculateColumns_FitsAnEightyColumnTerminal guards the budget the
// STATUS column is taken from. Eighty is both the conventional width and what
// getTermWidth falls back to when stdout is not a terminal, so a table that
// overflows it wraps every row in the output a pipe gets.
func Test_calculateColumns_FitsAnEightyColumnTerminal(t *testing.T) {
	// bubbles pads each cell by one column on each side; the budget reserves
	// three per column, which is why taking twelve of them still fits.
	total := 0
	for _, c := range calculateColumns(80) {
		total += c.Width + 2
	}
	require.LessOrEqual(t, total, 80, "the rendered table must fit the width it was sized for")
}
