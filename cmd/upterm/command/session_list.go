package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

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

	var table bytes.Buffer
	tw := tabwriter.NewWriter(&table, 0, 0, columnGap, ' ', 0)
	for _, line := range lines {
		_, _ = fmt.Fprintln(tw, strings.Join(line, "\t"))
	}
	_ = tw.Flush()

	// A row with no relay would end in the padding of the cell before it.
	for _, line := range strings.Split(strings.TrimSuffix(table.String(), "\n"), "\n") {
		_, _ = fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

// oneLine makes a cell safe to print on one row: a command can hold a newline
// or a tab, which would split its row or push the columns after it out of
// line, and an escape sequence, which a terminal would act on.
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

	// At least one character each, for the "…", however little is left.
	room = max(room, 2)
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
	for _, line := range lines[1:] {
		line[columnCommand] = shorten(line[columnCommand], commandLimit)
		line[columnRelay] = shorten(line[columnRelay], relayLimit)
	}
}

// columnWidth is the width of the widest cell of column c, in characters, as
// tabwriter counts them.
func columnWidth(lines [][]string, c int) int {
	w := 0
	for _, line := range lines {
		w = max(w, utf8.RuneCountInString(line[c]))
	}
	return w
}

// shorten cuts cell to limit characters, the last of them "…", when it is
// longer.
func shorten(cell string, limit int) string {
	if utf8.RuneCountInString(cell) <= limit {
		return cell
	}
	return string([]rune(cell)[:limit-1]) + "…"
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
