//go:build !windows

package command

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// suspendSupported says whether this platform can stop a process the way a
// job-control shell expects. InstallSignalPolicy ignores only SIGTTIN and
// SIGTTOU, so SIGTSTP keeps whatever disposition this process inherited.
const suspendSupported = true

// suspendContWait bounds stopSelf's wait for the continue. A package var so a
// test can shorten it.
var suspendContWait = 2 * time.Second

// suspendContGrace is how much longer stopSelf waits for a continue once
// suspendContWait has expired; see stopSelf. A package var so a test can
// lengthen it.
var suspendContGrace = 250 * time.Millisecond

// tstpIgnored reports whether SIGTSTP is ignored through os/signal.
// Injectable so the guard's wiring can be tested without changing the
// process's real disposition, which os/signal cannot undo.
var tstpIgnored = func() bool { return signal.Ignored(syscall.SIGTSTP) }

// suspendAvailable reports whether the ~^Z hook should be offered. It
// withholds it when *this* process has ignored SIGTSTP through os/signal,
// which is the whole of what signal.Ignored can tell us here: Go's
// runtime.initsig skips every signal whose table entry carries _SigDefault —
// SIGTSTP is one — so sigInitIgnored never runs for it and
// signal.Ignored(SIGTSTP) stays false whatever disposition was inherited. An
// inherited SIG_IGN, the child-of-a-non-interactive-shell case, is therefore
// invisible to this guard; that one, like an orphaned process group, is
// caught downstream by stopSelf's bounded wait. Decided once, when the hook
// is installed: with no hook, ~^Z is not offered and both bytes reach the
// session, exactly as on a platform without job control.
func suspendAvailable() bool { return !tstpIgnored() }

// stopSelf stops this process and returns once it has been continued — or
// once suspendContWait has gone by without the stop ever landing — and
// reports which.
//
// unless, when not nil, is asked once the continue is being watched and just
// before the raise; when it holds, nothing is raised and a continue is
// reported, there being nothing to wait for. It is how a stop again after bg
// avoids stopping a job that fg has already put back in the foreground:
// bg; fg typed together can land between the caller's own check and this
// raise. Asked after the watch is armed, fg is either seen by it — fg hands
// the terminal over before it sends SIGCONT — or its SIGCONT comes after the
// raise, where POSIX has it discard a stop still pending or continue one that
// has landed. Only a SIGCONT in the instant between the question and the
// raise is mistaken for the stop's own: raw mode is re-entered, the stop
// lands after it, and the fg that follows resumes the process in whatever
// modes the shell puts back.
//
// The signal goes to this pid, not the group, exactly as ssh's ~^Z does: the
// shell that started us reports "Stopped" and fg is what comes back. Unlike
// ssh's, this waits for SIGCONT, because kill(2) to ourselves returns before
// the group stop lands: the kernel stops the group from whichever thread
// dequeues the signal, and in a multithreaded process that is rarely the
// raising thread. Measured on Linux — the thread that raised SIGTSTP
// re-entered raw mode in the same millisecond, the process stopped afterwards
// in raw mode, the shell put its own cooked modes back, and fg brought it
// back cooked. SIGCONT is registered for before the raise so a continue
// cannot be missed, and the kernel resumes a stopped process on SIGCONT
// whether or not anything handles it.
//
// The wait is bounded because kill(2) reports success for a SIGTSTP the
// kernel then discards, and two real cases do exactly that:
//
//   - An orphaned process group: Linux's get_signal throws a job-control stop
//     away when is_current_pgrp_orphaned() — every process in the group has
//     its parent either in the same group or in a different session — and
//     POSIX specifies the same discard. "ssh -t host upterm attach",
//     "docker run -it ... upterm attach" and "alacritty -e upterm attach" all
//     produce precisely that: a client that is its own session and group
//     leader, with no parent inside its session.
//   - SIGTSTP inherited as SIG_IGN, which suspendAvailable cannot see (its
//     own comment says why).
//
// Unbounded, either case wedged the user's terminal rather than merely
// missing a suspend: suspendLocalTerminal has already handed the terminal
// back, so the client sat there in cooked mode with its input actor parked
// forever, and since run.Group.Run waits for every actor, SIGINT and SIGTERM
// only cancelled the context and never returned — a SIGKILL from another
// terminal was the only way out.
//
// The timer cannot take the select during a genuine stop: no Go code runs
// while the process is stopped, so that branch is only reachable once the
// process is running again. Being stopped for longer than the bound is
// therefore not a misfire, but it does come back with the timer expired and
// the continue arriving at the same instant — ready beside it in a select
// that may pick either, or still on its way through os/signal. So an expired
// bound waits suspendContGrace more before reporting that no continue came:
// the caller stops again when continued in the background, and a long stop
// mistaken for a discarded one would have it give up and detach instead.
// Nothing is printed when the bound expires: the client is holding a
// terminal the session is drawing on, and ssh's ~^Z is just as silent when
// its own stop is discarded.
func stopSelf(unless func() bool) bool {
	cont := make(chan os.Signal, 1)
	signal.Notify(cont, syscall.SIGCONT)
	defer signal.Stop(cont)
	if unless != nil && unless() {
		return true
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTSTP); err != nil {
		return false
	}
	timer := time.NewTimer(suspendContWait)
	defer timer.Stop()
	select {
	case <-cont:
		return true
	case <-timer.C:
	}
	grace := time.NewTimer(suspendContGrace)
	defer grace.Stop()
	select {
	case <-cont:
		return true
	case <-grace.C:
		return false
	}
}
