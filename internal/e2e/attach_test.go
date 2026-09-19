package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/tmux"
	"github.com/stretchr/testify/require"
)

// A host started in the background gets a terminal from upterm attach, loses
// it on ~., and gets it back — with the screen replayed — on the next attach.
func TestAttachDetachReattach(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))

	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo DETACH_STATUS=$?"))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second), "attach did not reach the session's prompt")

	// Input from the attached terminal reaches the command, and the
	// backgrounded host — a pty viewer now — shows the result too.
	first := fmt.Sprintf("FIRST_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "FIR""%s"`, strings.TrimPrefix(first, "FIR"))))
	require.NoError(t, h.waitForText(term, first, 10*time.Second))
	require.NoError(t, h.waitForText(h.host, first, 10*time.Second), "the backgrounded host's terminal did not show what the attached one typed")

	// ~. at the start of a line detaches; the shell in the pane comes back.
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "detached from session "+name, 10*time.Second))
	require.NoError(t, h.waitForText(term, "DETACH_STATUS=0", 10*time.Second), "a detach must exit 0")

	// The session survived the detach: the attach terminal can come back and
	// finds the earlier output in the replay. The screen is cleared first —
	// and the clear is confirmed — so that the marker found after the second
	// attach can only have been painted by the replay.
	require.NoError(t, term.SendLine(h.ctx, "clear"))
	require.Eventually(t, func() bool {
		content, err := term.Capture(h.ctx)
		return err == nil && !strings.Contains(content, first)
	}, 2*time.Second, 50*time.Millisecond, "the screen was not cleared, so the replay assertion below would prove nothing")
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo STATUS=$?"))
	require.NoError(t, h.waitForText(term, first, 30*time.Second), "the replay did not carry the earlier output")
	second := fmt.Sprintf("SECOND_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "SEC""%s"`, strings.TrimPrefix(second, "SEC"))))
	require.NoError(t, h.waitForText(term, second, 10*time.Second))

	// The command's exit ends the session and the attach exits with it. The
	// status is printed by the pane's own shell, from the line that started
	// the attach: nothing is typed into the handover, where an input read
	// abandoned by the exiting attach could still swallow it.
	require.NoError(t, term.SendLine(h.ctx, "exit 3"))
	require.NoError(t, h.waitForText(term, "command exited (status 3)", 10*time.Second))
	require.NoError(t, h.waitForText(term, "STATUS=3", 10*time.Second))

	// And the host says only that. A command's exit status arrives as an
	// ordinary error from RunE, which cobra answers with the whole usage
	// block unless it is told otherwise — thirty lines of flags after
	// `exit 3`, as if the user had mistyped something.
	hostOut, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.NotContains(t, hostOut, "Usage:", "a command that exited is not a usage error")
}

// A name nobody holds is a failure to attach, which is 255 — not a crash, and
// not the 254 a session reserves for disconnecting a terminal it had.
func TestAttachRefusesAnUnknownSession(t *testing.T) {
	h := newTestHarness(t, 200)

	require.NoError(t, h.host.SendLine(h.ctx, "upterm attach no-such-session-here; echo NOSUCH_STATUS=$?"))
	require.NoError(t, h.waitForText(h.host, "NOSUCH_STATUS=255", 20*time.Second))

	out, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.Contains(t, out, "no session named", "and it says which name it could not find")
}

// The terminal comes back the way it was found, on both of the ways a client
// leaves that the user chooses: the escape key, and a signal. stty -g is the
// whole of the terminal's settings, so comparing it before and after is the
// strongest form of "my shell still works" there is.
func TestAttachLeavesTheTerminalAsItFoundIt(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-stty-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))

	// The comparison lives in a script rather than on the command line: a
	// pane is narrower than the line this would otherwise be, and a marker
	// split across a wrap is one no assertion can find.
	//
	// It compares the modes raw mode turns off, not `stty -g`. That blob
	// carries PENDIN too — a kernel state bit meaning "input is pending",
	// set by the very keystrokes that start this script — so comparing it
	// whole reports a difference that has nothing to do with whether the
	// terminal was restored.
	check := filepath.Join(h.tmpDir, "check-stty.sh")
	require.NoError(t, os.WriteFile(check, []byte(
		"modes() { stty -a | tr ' ,' '\\n\\n' | grep -E '^-?(echo|icanon|isig|iexten|icrnl|opost)$' | sort | tr '\\n' ' '; }\n"+
			"before=$(modes)\nupterm attach \"$1\"\nafter=$(modes)\n"+
			"if [ \"$before\" = \"$after\" ]; then echo \"$2=same\"; else echo \"$2=CHANGED [$before] [$after]\"; fi\n"), 0755))

	term := h.splitPane(h.host)

	// Left with the escape key.
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf("sh %s %s STTY_ESCAPE", check, name)))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second))
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "STTY_ESCAPE=same", 15*time.Second))

	// Left by a signal, sent from a third terminal so that the client is
	// still the foreground of its own. The pattern names the client's own
	// argv, which the script wrapping it does not share.
	killer := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf("sh %s %s STTY_SIGNAL", check, name)))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second))
	require.NoError(t, killer.SendLine(h.ctx, fmt.Sprintf("pkill -f 'upterm attach %s'", name)))
	require.NoError(t, h.waitForText(term, "STTY_SIGNAL=same", 15*time.Second))
}

// Detaching from a full-screen session hands the terminal back usable.
//
// A session's terminal modes are the session's, and they outlive the
// attachment: the client restores the termios settings it changed, and those
// say nothing about the alternate screen a program is drawing on, the cursor
// it hid, or the mouse reporting it turned on. A terminal left on the
// alternate screen is one whose shell has lost everything printed before the
// attach, draws over a program's screen, and has no cursor to show for it.
//
// Asserted through what the user would see: capture-pane reads the screen the
// pane is showing, so a marker printed before the attach is readable
// afterwards only if the pane is back on the normal screen. The check before
// the detach is what makes that mean something — without it, a session that
// never reached the alternate screen would pass this test.
func TestDetachingFromAFullScreenSessionRestoresTheTerminal(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-alt-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))

	term := h.splitPane(h.host)
	marker := fmt.Sprintf("NORMAL_SCREEN_%d", time.Now().UnixNano()%1_000_000)
	require.NoError(t, term.SendLine(h.ctx, "echo "+marker))
	require.NoError(t, h.waitForText(term, marker, 10*time.Second))

	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second), "attach did not reach the session's prompt")

	// A full-screen program's opening, and nothing that puts it back: the
	// program is still running when its viewer leaves, which is the case
	// where the terminal cannot restore itself.
	require.NoError(t, term.SendLine(h.ctx, `printf '\033[?1049h\033[?25l\033[?1000hFULL_SCREEN\n'`))
	require.NoError(t, h.waitForText(term, "FULL_SCREEN", 10*time.Second))
	onAlt, err := term.Capture(h.ctx)
	require.NoError(t, err)
	require.NotContains(t, onAlt, marker,
		"the session never reached the alternate screen, so what follows would prove nothing")

	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "detached from session "+name, 10*time.Second))

	require.Eventually(t, func() bool {
		content, err := term.Capture(h.ctx)
		return err == nil && strings.Contains(content, marker)
	}, 10*time.Second, 100*time.Millisecond,
		"the terminal was handed back on the session's alternate screen, with everything before the attach out of sight")
}

// TestAttachSuspendsAndResumes drives ~^Z through a real terminal, because
// nothing smaller can: job control needs a shell that owns the pty, and
// in-process tests cannot be the foreground of a pty pair they opened.
func TestAttachSuspendsAndResumes(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-suspend-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))

	term := h.splitPane(h.host)
	// No trailing "; echo STATUS=$?" here, unlike the plain detach tests: bash
	// treats a job stopping mid-list as that command completing with status
	// 128+SIGTSTP and runs straight on to what follows the semicolon, so a
	// combined line would print a stop status long before fg ever runs. The
	// eventual detach's own status is read separately, after fg returns.
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second), "attach did not reach the session's prompt")

	// ~^Z at the start of a line suspends: the escape byte, then the literal
	// control byte raw mode would otherwise hand straight to the session.
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~"))
	require.NoError(t, term.SendKeys(h.ctx, "C-z"))
	require.NoError(t, h.waitForText(term, "Stopped", 15*time.Second), "the attach process did not stop")

	// fg hands the terminal back to the attach client, which re-enters raw
	// mode and resumes forwarding.
	require.NoError(t, term.SendLine(h.ctx, "fg"))

	// A shell prompt repaints on Enter; the WINCH nudge this resume sends is
	// what repaints a full-screen program, which this plain shell is not.
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, h.waitForText(term, uptermPrompt, 15*time.Second), "the session's prompt did not reappear after fg")

	marker := fmt.Sprintf("RESUMED_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "RES""%s"`, strings.TrimPrefix(marker, "RES"))))
	require.NoError(t, h.waitForText(term, marker, 10*time.Second), "input typed after resume did not reach the session")

	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "detached from session "+name, 10*time.Second))

	// fg's own exit status is the resumed attach's, once it returns.
	require.NoError(t, term.SendLine(h.ctx, "echo FG_STATUS=$?"))
	require.NoError(t, h.waitForText(term, "FG_STATUS=0", 10*time.Second), "a detach must exit 0")
}

// The pty is sized to the smallest terminal watching it, and gives the size
// back when that terminal leaves. Two panes of different heights are enough:
// the session takes the shorter one while both are attached, and returns to
// the taller one's height when the shorter detaches.
//
// The command reports its size on SIGWINCH rather than on demand, because
// every attach and every resize sends one, and a command that had to be
// typed at would not be reporting the size the test is asking about.
func TestTheSessionFollowsTheSmallestAttachedTerminal(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-size-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	sizeCmd := filepath.Join(h.tmpDir, "size.sh")
	require.NoError(t, os.WriteFile(sizeCmd, []byte(
		"stty -echo -opost\ntrap 'stty size' WINCH\nprintf 'SIZE_READY\\n'\nwhile :; do sleep 0.1; done\n"), 0755))

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- sh %s &",
		h.serverURL, h.keyFile, name, sizeCmd)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))
	require.NoError(t, h.waitForText(h.host, "SIZE_READY", 20*time.Second))

	// The first terminal, in this harness's own 200-column window. Widths
	// rather than heights, because a split puts panes side by side: the two
	// terminals differ in columns, and the numbers stay far enough apart to
	// mean something.
	wide := h.splitPane(h.host)
	require.NoError(t, wide.SendLine(h.ctx, "upterm attach "+name))
	var wideCols int
	require.Eventually(t, func() bool {
		cols, ok := lastReportedCols(t, h, wide)
		wideCols = cols
		return ok && cols > 60
	}, 30*time.Second, 200*time.Millisecond, "the session never reported a width to the first terminal")

	// A second terminal, in a window of its own that is narrower than
	// anything a split of this one could produce.
	tm, err := tmux.Default()
	require.NoError(t, err)
	narrowSession, err := tm.NewSession(h.ctx, &tmux.SessionOptions{
		Name:         fmt.Sprintf("upterm-e2e-narrow-%d", time.Now().UnixNano()),
		Width:        40,
		Height:       24,
		ShellCommand: "bash --norc --noprofile",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = narrowSession.Kill(h.ctx) })
	narrowWindows, err := narrowSession.ListWindows(h.ctx)
	require.NoError(t, err)
	require.NotEmpty(t, narrowWindows)
	narrowPanes, err := narrowWindows[0].ListPanes(h.ctx)
	require.NoError(t, err)
	require.NotEmpty(t, narrowPanes)
	narrow := narrowPanes[0]

	require.NoError(t, narrow.SendLine(h.ctx, "upterm attach "+name))
	require.Eventually(t, func() bool {
		cols, ok := lastReportedCols(t, h, wide)
		return ok && cols == 40
	}, 30*time.Second, 200*time.Millisecond,
		"the session did not shrink to the narrowest attached terminal (40 columns); the first terminal had %d", wideCols)

	// And when the narrow one leaves, the wide one gets its width back.
	require.NoError(t, narrow.SendKeys(h.ctx, "Enter"))
	require.NoError(t, narrow.SendKeys(h.ctx, "~."))
	require.Eventually(t, func() bool {
		cols, ok := lastReportedCols(t, h, wide)
		return ok && cols == wideCols
	}, 30*time.Second, 200*time.Millisecond,
		"the session did not go back to %d columns when the narrow terminal left", wideCols)
}

// sizeLine matches what `stty size` prints: rows then columns, alone on a line.
var sizeLine = regexp.MustCompile(`(?m)^\s*(\d+)\s+(\d+)\s*$`)

// lastReportedCols is the column count from the most recent size the session
// printed into this pane.
func lastReportedCols(t *testing.T, h *testHarness, p *tmux.Pane) (int, bool) {
	t.Helper()
	content, err := p.Capture(h.ctx)
	if err != nil {
		return 0, false
	}
	matches := sizeLine.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return 0, false
	}
	cols, err := strconv.Atoi(matches[len(matches)-1][2])
	if err != nil {
		return 0, false
	}
	return cols, true
}

// A host whose stdout is a file still puts the command's output there: the
// pipe viewer is what a redirected stdout was before the split.
func TestRedirectedHostOutputReachesTheFile(t *testing.T) {
	h := newTestHarness(t, 200)
	out := filepath.Join(h.tmpDir, "out.txt")
	marker := fmt.Sprintf("PIPE_%d", time.Now().UnixNano())
	// The hosted command exits on its own, so this session ends without
	// being told to; registering it anyway is what keeps the rule simple —
	// every session this suite starts is named and stopped, and stopping one
	// that is already over is not an error.
	name := fmt.Sprintf("e2e-pipe-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)
	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- sh -c 'echo \"PIP\"\"%s\"' > %s 2>&1; echo HOST_EXIT=$?",
		h.serverURL, h.keyFile, name, strings.TrimPrefix(marker, "PIP"), out)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "HOST_EXIT=0", 30*time.Second))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), marker, "the command's output must reach a redirected stdout")
}
