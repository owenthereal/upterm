package internal

import (
	"log/slog"
	"sync"
)

// terminalWindows keeps a pty at the size of the smallest terminal attached to
// it: a session has one geometry, and every terminal watching it has to fit
// inside that.
//
// The map is the authority for that geometry, and both updates run in the
// caller's own goroutine under mu. They used to be events, announced on the
// host's emitter and applied by a handler goroutine subscribed with
// emitter.Skip — which drops an event outright whenever the listener's
// one-deep channel is still full from the last one. Dropping a resize leaves
// the pty at a stale size until some terminal happens to resize again.
// Dropping a detach is worse: the departed terminal stays in the minimum for
// the rest of the session, because the event that was dropped is the only
// thing that would have removed it. Neither is hypothetical for a door that
// can see two clients leave in the same instant, and the second is exactly the
// failure the detach is there to prevent.
//
// Nothing here can block for long — the whole of an update is a map write and
// one ioctl — so the callers give up nothing by waiting for it, and in return
// a door that has seen a client leave knows the size was recomputed before it
// moves on.
type terminalWindows struct {
	logger *slog.Logger

	mu sync.Mutex
	// Keyed by pty and then by terminal id. A session has one pty; the outer
	// key is what keeps two of them — a forced command's, a second session in
	// a test — from sharing a minimum.
	m map[PTY]map[string]window
}

type window struct {
	Width  int
	Height int
}

func newTerminalWindows(logger *slog.Logger) *terminalWindows {
	return &terminalWindows{
		logger: logger,
		m:      make(map[PTY]map[string]window),
	}
}

// changed records a terminal's geometry and applies the new minimum.
//
// A handler built without a pty — a test's — is left alone, as it is by the
// redraw nudge on the same path.
func (t *terminalWindows) changed(ptmx PTY, id string, w, h int) {
	if ptmx == nil {
		return
	}

	t.mu.Lock()
	ts, ok := t.m[ptmx]
	if !ok {
		ts = make(map[string]window)
		t.m[ptmx] = ts
	}
	ts[id] = window{Width: w, Height: h}
	err := resizeWindow(ptmx, ts)
	t.mu.Unlock()

	// Outside the lock: the logger writes to the host's own terminal, which a
	// stopped terminal blocks, and holding the geometry of every other client
	// behind that is the kind of thing this package spends its comments on.
	if err != nil {
		t.logger.Error("error resizing terminal window", "terminal-id", id, "error", err)
	}
}

// detached forgets a terminal and applies the minimum across the ones left.
//
// Idempotent, because a client's departure reaches this from two places: the
// connection actor, as soon as the connection ends, and the pty actor's
// interrupt, whenever the handler finally returns — which a write parked in
// ptmx.Write can delay for as long as the session lives.
func (t *terminalWindows) detached(ptmx PTY, id string) {
	if ptmx == nil {
		return
	}

	t.mu.Lock()
	ts, ok := t.m[ptmx]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(ts, id)
	if len(ts) == 0 {
		// Nothing left to take a minimum across, and 0x0 is what computing
		// one over nothing would ask for.
		delete(t.m, ptmx)
		t.mu.Unlock()
		return
	}
	// A terminal leaving can only raise the survivors' minimum, never lower
	// it, but nothing applies that automatically: without this, the pty stays
	// at whatever the departed terminal constrained it to until a survivor
	// happens to resize on its own.
	err := resizeWindow(ptmx, ts)
	t.mu.Unlock()

	if err != nil {
		t.logger.Error("error resizing terminal window", "terminal-id", id, "error", err)
	}
}

func resizeWindow(ptmx PTY, ts map[string]window) error {
	var w, h int

	for _, t := range ts {
		if w == 0 || w > t.Width {
			w = t.Width
		}

		if h == 0 || h > t.Height {
			h = t.Height
		}
	}

	return ptmx.Setsize(h, w)
}
