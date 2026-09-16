package command

import (
	"io"
	"os"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
	"golang.org/x/term"
)

// localTerminal is how the local terminal can be attached to a session.
//
// Three shapes, decided by what stdin and stdout are. Interactive: stdout is
// a terminal and stdin is a terminal this process is in the foreground of —
// a pty request sized from stdout, raw mode, input forwarded, resizes
// followed. A pty viewer: stdout is a terminal but stdin is not ours, which
// is `upterm host … &` — the terminal shows the session and follows its
// size, and nothing reads keystrokes that belong to the foreground shell. A
// pipe viewer: stdout is a pipe or a file — no pty request, so the daemon
// treats it as an asynchronous, droppable sink, exactly what a non-terminal
// stdout was before the local terminal became a client.
type localTerminal struct {
	pty     *attach.Pty // nil: no pty request — an output-only viewer
	stdin   io.Reader   // nil: input is not forwarded
	rawMode bool        // put stdin into raw mode while attached
	sizeOf  *os.File    // follow this file's size; nil: no resize requests
}

// classifyTerminal decides the shape. owned is tty.Owned in production and
// injected in tests, because foreground ownership cannot be staged in-process.
func classifyTerminal(stdin, stdout *os.File, owned func(*os.File) bool, termName string) localTerminal {
	var lt localTerminal
	if stdout != nil && term.IsTerminal(int(stdout.Fd())) {
		size, err := tty.Size(stdout)
		if err != nil {
			size = termsize.Default
		}
		lt.pty = &attach.Pty{Term: termName, Size: size}
		lt.sizeOf = stdout
	}
	if owned(stdin) {
		lt.stdin = stdin
		lt.rawMode = true
	}
	return lt
}

// withRawTerminal runs fn with f in raw mode, restoring it afterwards only if
// this process still owns it.
//
// Asked again rather than remembered, because the answer can change while fn
// runs: ^Z then bg, or a shell that moved on, leaves this process in the
// background of a terminal somebody else is now using. SIGTTOU is ignored
// (host.InstallSignalPolicy), so nothing would stop the restoring tcsetattr
// from succeeding — it would write this session's stale termios over theirs,
// and the usual symptom is a shell that has lost its echo. If this process
// is ever foregrounded again, the shell's job control puts the settings back
// as part of resuming it.
func withRawTerminal(f *os.File, owned func(*os.File) bool, fn func() error) error {
	oldState, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return err
	}
	defer func() {
		if !owned(f) {
			return
		}
		_ = term.Restore(int(f.Fd()), oldState)
	}()
	return fn()
}
