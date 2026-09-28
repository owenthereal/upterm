//go:build !windows

package command

import (
	"os"
	"reflect"
	"testing"

	ptylib "github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// TestSuspendLocalTerminal pins both halves of the ~^Z hook without staging
// real job control — which an in-process test cannot do, for the same reason
// Test_Command_RestoresTheTerminalOnlyWhenStillOwned injects ownership rather
// than relying on tty.Owned: a pty pair opened here is the controlling
// terminal of no session.
//
// Ownership is asked again inside stop, not fixed for the whole call: ~^Z can
// only be typed while this process is the foreground, so it is true when
// suspendLocalTerminal is entered — that is what makes the give-it-back half
// observable at all — and the case under test is what the user chooses while
// the process is stopped, which is what stop flips before returning. That
// mirrors suspendLocalTerminal asking raw.owned again after stop rather than
// remembering the answer from before it.
func TestSuspendLocalTerminal(t *testing.T) {
	for _, tc := range []struct {
		name         string
		stillOwned   bool // what raw.owned answers once stop has run: fg (true) or bg (false)
		wantRawAtEnd bool
	}{
		{name: "fg while stopped: re-enters raw mode", stillOwned: true, wantRawAtEnd: true},
		{name: "bg while stopped: left cooked, not written over", stillOwned: false, wantRawAtEnd: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptmx, tty, err := ptylib.Open()
			require.NoError(t, err)
			defer func() { _ = ptmx.Close() }()
			defer func() { _ = tty.Close() }()

			fd := int(tty.Fd())
			cooked, err := term.GetState(fd)
			require.NoError(t, err)

			// What raw looks like on this pty, taken from MakeRaw itself and
			// then undone — the same technique
			// Test_Command_RestoresTheTerminalOnlyWhenStillOwned uses, so this
			// asserts against the fact under test rather than a copy of
			// golang.org/x/term's flag choices.
			previous, err := term.MakeRaw(fd)
			require.NoError(t, err)
			raw, err := term.GetState(fd)
			require.NoError(t, err)
			require.NoError(t, term.Restore(fd, previous))

			// Owned when suspendLocalTerminal is entered: ~^Z was just typed at
			// this process's own prompt, so it is the foreground.
			foreground := true
			r := &rawTerminal{f: tty, owned: func(*os.File) bool { return foreground }}
			require.NoError(t, r.enter())

			var stateAtStop *term.State
			stop := func() error {
				st, err := term.GetState(fd)
				require.NoError(t, err)
				stateAtStop = st
				// What the user chose while this process was stopped, observed
				// by raw.owned the next time suspendLocalTerminal asks it —
				// exactly as tty.Owned would answer differently after fg
				// versus bg in production.
				foreground = tc.stillOwned
				return nil
			}

			suspendLocalTerminal(r, tty, stop)

			require.NotNil(t, stateAtStop, "stop was never called")
			require.True(t, reflect.DeepEqual(cooked, stateAtStop),
				"the terminal must be cooked -- echoing -- for the instant it is stopped, whoever is watching it then")

			got, err := term.GetState(fd)
			require.NoError(t, err)
			if tc.wantRawAtEnd {
				require.True(t, reflect.DeepEqual(raw, got), "still the foreground: must re-enter raw mode on the way out")
			} else {
				require.True(t, reflect.DeepEqual(cooked, got),
					"backgrounded: must not write raw termios over a terminal it no longer owns")
			}
		})
	}
}
