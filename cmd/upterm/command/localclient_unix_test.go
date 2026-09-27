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
// Ownership is asked again after every stop, not fixed for the whole call:
// ~^Z can only be typed while this process is the foreground, so it is true
// when suspendLocalTerminal is entered — that is what makes the give-it-back
// half observable at all — and the case under test is what the user chooses
// while the process is stopped, which is what each stop flips before
// returning. That mirrors suspendLocalTerminal asking raw.owned again after
// each stop rather than remembering the answer from before it.
//
// bg is the case that stops more than once. Continued without the terminal,
// the process stops again, as SIGTTOU would have stopped it had it not been
// ignored and as ssh's ~^Z does, until fg hands the terminal back — unless
// the stop is discarded, which is a process group with no job control left
// to continue it, or fg has already handed the terminal back by the time the
// stop is raised: bg; fg typed together can land between the check that
// found the process in the background and the stop that follows it, and a
// foreground job stopped for nothing needs a second fg.
func TestSuspendLocalTerminal(t *testing.T) {
	type stopResult struct {
		fgBeforeRaise bool // fg lands after the process last found itself in the background, before this stop is raised
		continued     bool // what stop reports: the continue arrived, or the stop never landed
		foreground    bool // what raw.owned answers after it: fg (true) or bg (false)
	}
	for _, tc := range []struct {
		name         string
		stops        []stopResult // one per stop the hook is expected to make, in order
		wantRawAtEnd bool
	}{
		{
			name:         "fg while stopped: re-enters raw mode",
			stops:        []stopResult{{continued: true, foreground: true}},
			wantRawAtEnd: true,
		},
		{
			name:         "stop discarded, still the foreground: re-enters raw mode",
			stops:        []stopResult{{continued: false, foreground: true}},
			wantRawAtEnd: true,
		},
		{
			name:         "bg, then fg: stops again, and re-enters raw mode once it is the foreground",
			stops:        []stopResult{{continued: true, foreground: false}, {continued: true, foreground: true}},
			wantRawAtEnd: true,
		},
		{
			name:         "bg, then the stop again is discarded: left cooked, not written over",
			stops:        []stopResult{{continued: true, foreground: false}, {continued: false, foreground: false}},
			wantRawAtEnd: false,
		},
		{
			name:         "bg, then fg before the stop again is raised: not stopped again",
			stops:        []stopResult{{continued: true, foreground: false}, {fgBeforeRaise: true}},
			wantRawAtEnd: true,
		},
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

			// The fake keeps stopSelf's contract: unless is asked just
			// before the raise, and when it holds nothing is raised and a
			// continue is reported, there being nothing to wait for.
			calls := 0
			var statesAtStop []*term.State // one per stop actually raised
			stop := func(unless func() bool) bool {
				calls++
				if calls > len(tc.stops) {
					// Not Fatal: this runs on the goroutine under test, and
					// an unexpected stop must end the loop, not hang it.
					t.Errorf("stopped %d times; want %d", calls, len(tc.stops))
					return false
				}
				step := tc.stops[calls-1]
				if step.fgBeforeRaise {
					foreground = true
				}
				if unless != nil && unless() {
					return true
				}
				st, err := term.GetState(fd)
				require.NoError(t, err)
				statesAtStop = append(statesAtStop, st)
				// What the user chose while this process was stopped, observed
				// by raw.owned the next time suspendLocalTerminal asks it —
				// exactly as tty.Owned would answer differently after fg
				// versus bg in production.
				foreground = step.foreground
				return step.continued
			}

			_, owned := suspendLocalTerminal(r, tty, stop)

			require.Equal(t, len(tc.stops), calls, "stop attempts")
			raised := 0
			for _, step := range tc.stops {
				if !step.fgBeforeRaise {
					raised++
				}
			}
			require.Len(t, statesAtStop, raised, "stops raised: none once fg has handed the terminal back, and never the ~^Z one skipped")
			for i, st := range statesAtStop {
				require.True(t, reflect.DeepEqual(cooked, st),
					"stop %d: the terminal must be cooked -- echoing -- for the instant it is stopped, whoever is watching it then", i+1)
			}

			got, err := term.GetState(fd)
			require.NoError(t, err)
			require.Equal(t, tc.wantRawAtEnd, owned,
				"reports the terminal as its own again exactly when it took it back: the session's modes go back on with raw mode, or not at all")
			if tc.wantRawAtEnd {
				require.True(t, reflect.DeepEqual(raw, got), "the foreground: must re-enter raw mode on the way out")
			} else {
				require.True(t, reflect.DeepEqual(cooked, got),
					"backgrounded: must not write raw termios over a terminal it no longer owns")
			}
		})
	}
}
