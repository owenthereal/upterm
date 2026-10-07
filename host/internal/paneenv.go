package internal

import (
	"slices"
	"strings"
)

// paneIdentityVars are the variables a terminal multiplexer sets in each of its
// panes to say which pane a program is in: tmux's, screen's, zellij's and
// Herdr's. The commands a session runs are on upterm's pty, not in the pane
// upterm was started from, so they are not told they are. Herdr refuses to
// start in what HERDR_ENV says is one of its own panes, so a door started from
// a Herdr pane turned every guest away; and a program that reads these takes
// the host's pane for its own -- Claude Code, told it was in tmux, gave guests
// advice for a terminal they were not in.
//
// Which server is another matter from which pane: HERDR_SOCKET_PATH and
// HERDR_BIN_PATH stay, so a guest's herdr reaches the server the door was
// started from. The terminal emulator's own identity, TERM_PROGRAM and the
// like, stays too.
var paneIdentityVars = []string{
	"TMUX", "TMUX_PANE",
	"STY",
	"ZELLIJ", "ZELLIJ_SESSION_NAME", "ZELLIJ_PANE_ID",
	"HERDR_ENV", "HERDR_PANE_ID", "HERDR_TAB_ID", "HERDR_WORKSPACE_ID",
}

// withoutPaneIdentity returns a copy of env with paneIdentityVars taken out.
func withoutPaneIdentity(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(paneIdentityVars, name)
	})
}
