package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host/sessiondir"
)

// sessionRow is one line of the session table.
type sessionRow struct {
	Current                                 bool
	Name, Status, SessionID, Command, Relay string
}

// sessionRows are the rows of the listing's sessions, in its order. A
// reconnecting session's status is its word alone: why and since when is what
// `session info` is for.
func sessionRows(sessions []tui.SessionDetail) []sessionRow {
	rows := make([]sessionRow, len(sessions))
	for i, s := range sessions {
		rows[i] = sessionRow{
			Current:   s.IsCurrent,
			Name:      s.Name,
			Status:    s.Status,
			SessionID: s.SessionID,
			Command:   s.Command,
			Relay:     s.Host,
		}
	}
	return rows
}

// The columns of the session table. The first holds the mark of the current
// session ahead of its name, so a name starts where the header's does for
// every row.
const (
	columnCommand = 3
	columnRelay   = 4

	// columnGap is the padding between columns.
	columnGap = 2

	currentMark = "* "
	noMark      = "  "
)

var sessionTableHeader = []string{noMark + "NAME", "STATUS", "SESSION ID", "COMMAND", "RELAY"}

// writeSessionTable prints the header and every row. width > 0 (a terminal)
// shortens COMMAND and RELAY cells with "…" to fit; NAME and SESSION ID are
// never cut; width 0 (not a terminal) shortens nothing.
//
// A name and an ID are what a person copies out of the table and what the next
// command is given, so a terminal too narrow for them is a table that runs
// past its edge, not one that names a session wrongly. Whatever width is left
// after them goes to COMMAND and RELAY, and when none is, they are "…".
func writeSessionTable(w io.Writer, rows []sessionRow, width int) {
	lines := make([][]string, 0, len(rows)+1)
	lines = append(lines, sessionTableHeader)
	for _, r := range rows {
		mark := noMark
		if r.Current {
			mark = currentMark
		}
		lines = append(lines, []string{
			mark + oneLine(r.Name), oneLine(r.Status), oneLine(r.SessionID), oneLine(r.Command), oneLine(r.Relay),
		})
	}
	if width > 0 {
		fitToWidth(lines, width)
	}

	// Padded by hand, to each column's width in terminal columns: tabwriter
	// pads by characters, which leaves the columns after a cell holding a wide
	// character or a combining mark out of line.
	widths := make([]int, len(sessionTableHeader))
	for c := range widths {
		widths[c] = columnWidth(lines, c)
	}
	for _, cells := range lines {
		var line strings.Builder
		for c, cell := range cells {
			line.WriteString(cell)
			if c < len(cells)-1 {
				line.WriteString(strings.Repeat(" ", widths[c]-ansi.StringWidth(cell)+columnGap))
			}
		}
		// A row with no relay would end in the padding of the cell before it.
		_, _ = fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
	}
}

// oneLine makes a cell safe to print on one row: a command can hold a newline
// or a tab, which would split its row or push the columns after it out of
// line, and an escape sequence, which a terminal would act on. It runs before a
// cell is measured, because the width functions skip an escape sequence: a cell
// still holding one would be measured as less than it prints.
func oneLine(cell string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, cell)
}

// fitToWidth shortens the COMMAND and RELAY cells of the rows (every line but
// the header's) so a line is no wider than width, where the cells before them
// leave room for that. The header is not cut: it names the column.
//
// What the two columns have is shared so that neither is squeezed while the
// other has room it is not using: a column that fits in half keeps its whole
// width and the other takes the rest.
//
// Neither goes below its header's width. A column is never narrower than its
// header, so a cell cut to less would leave the column as wide as it was and
// the rows past the edge for nothing. When the room is less than the two
// headers together, that is the width they get, and the table is as wide as
// its header line.
func fitToWidth(lines [][]string, width int) {
	before := 0
	for c := range columnCommand {
		before += columnWidth(lines, c) + columnGap
	}
	command, relay := columnWidth(lines, columnCommand), columnWidth(lines, columnRelay)
	room := width - before - columnGap
	if command+relay <= room {
		return
	}

	commandMin := ansi.StringWidth(sessionTableHeader[columnCommand])
	relayMin := ansi.StringWidth(sessionTableHeader[columnRelay])
	room = max(room, commandMin+relayMin)
	half := room / 2
	var commandLimit, relayLimit int
	switch {
	case command <= half:
		commandLimit, relayLimit = command, room-command
	case relay <= half:
		commandLimit, relayLimit = room-relay, relay
	default:
		commandLimit, relayLimit = room-half, half
	}
	// The side below its header takes what it lacks from the other, which has
	// it: the room is at least both headers.
	switch {
	case commandLimit < commandMin:
		commandLimit, relayLimit = commandMin, room-commandMin
	case relayLimit < relayMin:
		commandLimit, relayLimit = room-relayMin, relayMin
	}
	for _, line := range lines[1:] {
		line[columnCommand] = shorten(line[columnCommand], commandLimit)
		line[columnRelay] = shorten(line[columnRelay], relayLimit)
	}
}

// columnWidth is the width of the widest cell of column c, in terminal
// columns.
func columnWidth(lines [][]string, c int) int {
	w := 0
	for _, line := range lines {
		w = max(w, ansi.StringWidth(line[c]))
	}
	return w
}

// shorten cuts cell to limit terminal columns, the last of them "…", when it
// is wider. The cut falls between the characters as they are drawn, never
// inside one, so a wide character that would straddle the limit is dropped
// whole and the cell comes out a column short.
func shorten(cell string, limit int) string {
	return ansi.Truncate(cell, limit, "…")
}

// listInfos is listSessions for `-o json`: the `session info` object of every
// session that exists right now. Each is built as `session info` builds it,
// from the record and then from the daemon's answer where the session
// answers in time, so a script reads the same fields from either command.
func listInfos(ctx context.Context, runtimeRoot, stateRoot string) ([]sessionInfo, error) {
	// Bounded on its own, as listSessions' is: the registry and each socket
	// are separate things a stopped process can hold.
	listCtx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	records, err := sessiondir.ListLive(listCtx, stateRoot)
	if err != nil {
		return nil, err
	}

	// Never nil: no sessions is an empty array to a script, not null.
	infos := make([]sessionInfo, 0, len(records))
	for i := range records {
		infos = append(infos, listedInfo(ctx, runtimeRoot, &records[i]))
	}
	return infos, nil
}

// listedInfo is the object for one listed session. Per socket, so that one
// that never answers costs the listing its own wait and no other session's.
func listedInfo(ctx context.Context, runtimeRoot string, rec *sessiondir.Record) sessionInfo {
	ctx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	info, _, err := heldInfo(ctx, runtimeRoot, rec)
	if err != nil {
		// No path to dial is a reason to report the record, not to leave the
		// session out of a listing of what exists.
		return infoFromRecord(rec, rec.Status)
	}
	return info
}

// writeSessionsJSON writes the objects as one array, indented as `session
// info` indents its object.
func writeSessionsJSON(w io.Writer, infos []sessionInfo) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(infos)
}
