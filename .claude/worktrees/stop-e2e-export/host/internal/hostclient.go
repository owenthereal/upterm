package internal

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	uio "github.com/owenthereal/upterm/io"
)

// The stall bound and the chunk it measures progress in. Provisional per the
// design; vars so a test can shorten them. 4 KiB is one ring chunk and about
// a screenful, so a healthy terminal completes one in milliseconds.
var (
	primaryStallTimeout = 5 * time.Second
	primaryChunkSize    = 4096
	// promoteFlushTimeout bounds how long promotion waits for a candidate's
	// queued output to drain. It is the same bound as guestFlushTimeout and
	// for the same reason: a client that cannot take a second's worth of
	// backlog is not one to hand the pacing to.
	promoteFlushTimeout = time.Second
)

// hostSink is a host client's writer on the fan-out. It has two modes.
//
// As a secondary it is the shape of a guest's sink: an AsyncWriter in front of
// a TerminalQueryFilter in front of the channel, independently droppable and
// filtered. As the primary it writes synchronously through a StallWriter
// straight to the channel, unfiltered: the command cannot outrun the
// terminal, and OSC 10/11/12 and CSI 5n/6n reach a real terminal whose
// replies reach the pty.
//
// There is no demotion. MultiWriter.Write holds writeMu across the fan-out,
// so while the primary's write is blocked that lock is held, and swapping the
// writer would need it: the swap would deadlock. A primary leaves by being
// disconnected — the watchdog closes the connection, which is the one thing
// that fails a write parked in SSH — and the next candidate is promoted.
type hostSink struct {
	disconnect func()

	// mu is held for the whole of Write, including a primary's blocking write,
	// so that promote cannot interleave with one: the flip lands between two
	// writes, with nothing queued. primary is also readable without mu, for
	// Flush, which must not wait behind a blocked primary.
	mu      sync.Mutex
	primary atomic.Bool
	async   *uio.AsyncWriter
	filter  *uio.TerminalQueryFilter
	direct  *uio.StallWriter

	// attached is set once the fan-out has accepted this sink, and is what
	// Close consults before disconnecting; see the comment there.
	attached atomic.Bool
}

// newHostSink builds a secondary sink for a session channel. disconnect is
// what the watchdog and the overflow path call — in production it closes the
// *ssh.ServerConn — and may be nil in tests.
func newHostSink(ch io.Writer, disconnect func(), sessionID string, logger *slog.Logger) *hostSink {
	s := &hostSink{disconnect: disconnect}
	s.filter = uio.NewTerminalQueryFilter(ch)
	s.async = uio.NewAsyncWriter(s.filter, uio.DefaultGuestBufferSize, func(err error) {
		// A guest's channel is closed and uptermd's watchdog collects the
		// rest. There is no watchdog on a unix socket, so the connection is
		// closed outright, which is what ends mux.loop and releases a drain
		// goroutine parked in the write.
		//
		// Close first, log second, here and below: the close is the
		// recovery, and a logger blocked on a stopped terminal must not
		// stand between a stalled fan-out and its release.
		s.closeConn()
		logger.Warn("disconnected local client: too far behind to keep up with output",
			"session-id", sessionID, "buffer-bytes", uio.DefaultGuestBufferSize, "error", err)
	})
	// The bound this watchdog is armed with, read once here rather than again
	// when it fires: the callback runs on the watchdog's own goroutine, where
	// reading the package var would race the test that restores it — and the
	// value worth reporting is the one the writer was actually built with.
	stall := primaryStallTimeout
	s.direct = uio.NewStallWriter(ch, primaryChunkSize, stall, func() {
		// Never under writeMu: the lock is held by the write this releases.
		// And the close before the log: with a blocked logger the other
		// order leaves the primary holding the fan-out for exactly as long
		// as the watchdog was meant to bound. Stage 1 tests this failure
		// mode on the command's exit (TestCommandRunDoesNotHangOnABlockedLogger);
		// TestHostSinkStallDisconnectsBeforeLogging tests it here.
		s.closeConn()
		logger.Warn("disconnected primary client: no output delivered within the stall timeout",
			"session-id", sessionID, "timeout", stall)
	})
	return s
}

func (s *hostSink) closeConn() {
	if s.disconnect != nil {
		s.disconnect()
	}
}

// markAttached records that the fan-out has taken this sink, which is what
// makes the disconnect in Close meaningful rather than destructive.
func (s *hostSink) markAttached() { s.attached.Store(true) }

func (s *hostSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary.Load() {
		return s.direct.Write(p)
	}
	return s.async.Write(p)
}

// Flush implements uio.Flusher for MultiWriter.Shutdown. A primary is
// delivered by definition.
func (s *hostSink) Flush(ctx context.Context) error {
	if s.primary.Load() {
		return nil
	}
	return s.async.Flush(ctx)
}

// Close releases the sink's goroutines. Nothing in the fan-out ever closes an
// attached writer — MultiWriter.Remove and its drop-on-error only splice — so
// every detach path has to reach this, or each attachment leaks a drain
// goroutine and a watchdog ticker.
func (s *hostSink) Close() error {
	_ = s.async.Close()
	// The disconnect before the watchdog stops, not after: a primary write
	// parked in SSH holds writeMu, stopping the watchdog first would leave it
	// parked with nothing left to release it, and this runs after sess.Exit on
	// every path, so the connection is going away regardless.
	//
	// Only once the fan-out has taken the sink, though. The write that needs
	// releasing can only exist while something is writing to us, and the one
	// path that closes a sink the fan-out refused — attachGuestOutput's
	// release after ErrClosed — goes on to tell the client so with Exit(0). A
	// disconnect there would kill the connection out from under that.
	if s.attached.Load() {
		s.closeConn()
	}
	_ = s.direct.Close()
	return nil
}

func (s *hostSink) isPrimary() bool { return s.primary.Load() }

// promote flips the sink to primary once its queue has drained. Holding mu
// blocks the fan-out meanwhile — bounded by ctx — so that the flip lands at a
// write boundary: otherwise the drain goroutine and the direct path would
// interleave halves of two writes on one channel. A sink that cannot drain in
// time stays secondary and reports false.
func (s *hostSink) promote(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary.Load() {
		return true
	}
	if err := s.async.Flush(ctx); err != nil {
		return false
	}
	// Flush reports nil for a sink that has failed, and for one that has been
	// closed, as readily as for one that has caught up — and those are nothing
	// alike: in either of the first two the drain goroutine may still be
	// inside the filter's write, so reading the filter below would race it and
	// whatever that write is carrying would land on the channel after the
	// flip. Neither is a candidate: a client whose delivery has failed has
	// been disconnected already, and a closed sink's handler is on its way
	// out. Asked here rather than assumed from the order of the handler's
	// defers, so the invariant is this function's own.
	//
	// What is left is the success path, where the filter is ours to read:
	// Flush returns nil there only with the queue empty and no write in
	// flight, and mu keeps new writes out for the rest of this function.
	if s.async.Err() != nil || s.async.Closed() {
		return false
	}
	// The filter may be holding the lead-in of a sequence it has not yet
	// classified. Live output for the primary is unfiltered, so hand it over
	// raw: if it is a query, the primary is exactly who should answer it.
	//
	// Through the stall writer, never straight to the channel: the queue
	// being empty says nothing about the channel's window, and a write that
	// parks here with mu held would park the whole fan-out with it. Under
	// the watchdog it is bounded the way every primary write is — by a
	// disconnect — which fails this write and this promotion.
	if pending := s.filter.Pending(); len(pending) > 0 {
		if _, err := s.direct.Write(pending); err != nil {
			return false
		}
	}
	_ = s.async.Close()
	s.primary.Store(true)
	return true
}

// drained reports when this sink's queue next catches up, and false if it
// never will. A candidate skipped by an election for being behind is watched
// on this: see hostClients.watchForDrain.
func (s *hostSink) drained() (<-chan struct{}, bool) { return s.async.Drained() }

// hostClient is one attached client on the host door.
type hostClient struct {
	id   string
	sink *hostSink

	// gone is set by remove and refused by add: the elector's own invariant
	// that a removed client is never re-added. Nothing today removes a
	// client before it is added — the handler's connection actor and its
	// defer both run after add — but the elector does not depend on its
	// callers' ordering to hold that invariant.
	gone atomic.Bool

	// watching is set while a goroutine is waiting for this client's queue to
	// catch up so that it can run another election; one at a time is enough,
	// and successive failed elections would otherwise pile them up.
	watching atomic.Bool
}

// hostClients keeps the host door's clients in attach order and elects the
// primary: the earliest attached host client that can be promoted. There is
// no primary when no host client is attached; a guest is never eligible.
type hostClients struct {
	mu      sync.Mutex
	order   []*hostClient
	primary *hostClient

	// electMu serialises elections, which block for up to
	// promoteFlushTimeout per candidate and must not run concurrently.
	electMu sync.Mutex
	logger  *slog.Logger
}

func (h *hostClients) add(c *hostClient) {
	h.mu.Lock()
	if c.gone.Load() {
		// Removed before it was ever registered: its connection is already
		// closed, and nothing that is closed is a candidate.
		h.mu.Unlock()
		return
	}
	h.order = append(h.order, c)
	h.mu.Unlock()
	h.elect()
}

// remove is idempotent: it is reached from the handler's connection actor
// and from its defer, and the second has nothing left to do.
func (h *hostClients) remove(c *hostClient) {
	c.gone.Store(true)
	h.mu.Lock()
	if i := slices.Index(h.order, c); i >= 0 {
		h.order = slices.Delete(h.order, i, i+1)
	}
	if h.primary == c {
		h.primary = nil
	}
	h.mu.Unlock()
	h.elect()
}

func (h *hostClients) primaryID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.primary == nil {
		return ""
	}
	return h.primary.id
}

// elect promotes the earliest candidate that drains in time. A candidate that
// leaves while being promoted is skipped; one that cannot drain stays a
// candidate for the next election, which the next add or remove runs — or,
// when a sweep promotes nobody at all, which its own catching up runs. See
// watchForDrain.
//
// This may run on the handler's connection actor, the goroutine that removes
// a client whose connection ended — whether that end was the watchdog's
// close, the overflow path's, or the client's own hang-up. Safe there: an
// election takes electMu and the candidates' own sink locks, never the
// fan-out's writeMu — which is the lock a parked primary is holding, and
// closing the connection is what releases it — and elect runs after the
// connection has ended, so a candidate whose promotion parks is released by
// its own watchdog rather than waiting on this one.
//
// The diagnostic is written off the election path entirely — outside electMu
// and on a goroutine of its own. An election usually runs on the attaching or
// detaching client's own handler, so a logger blocked on a stopped terminal
// would otherwise hold that handler, and every other client's attach and
// detach behind it: the detaching one would never reach sink.Close(), which is
// the one thing that releases a write parked in SSH. Unlike the command's exit
// path, nothing here is about to end the process, so the line still lands.
func (h *hostClients) elect() {
	if elected := h.electOne(); elected != "" {
		go h.logger.Info("primary client elected", "client", elected)
	}
}

// electOne is elect's body, returning the id of whoever it promoted so that
// the logging happens outside the lock.
func (h *hostClients) electOne() string {
	h.electMu.Lock()
	defer h.electMu.Unlock()

	for {
		h.mu.Lock()
		if h.primary != nil || len(h.order) == 0 {
			h.mu.Unlock()
			return ""
		}
		candidates := slices.Clone(h.order)
		h.mu.Unlock()

		retry := false
		var behind []drainWatch
		for _, c := range candidates {
			// Taken before the attempt rather than after it. This is the
			// signal the sink publishes the next time it catches up, and a
			// sink that catches up while its promotion is timing out
			// publishes it during the attempt: asking afterwards would be
			// handed the one after that instead, and leave a candidate that
			// is ready now waiting for output that may never come.
			drained, watchable := c.sink.drained()

			ctx, cancel := context.WithTimeout(context.Background(), promoteFlushTimeout)
			ok := c.sink.promote(ctx)
			cancel()
			if !ok {
				if watchable {
					behind = append(behind, drainWatch{client: c, drained: drained})
				}
				continue
			}
			h.mu.Lock()
			if h.primary == nil && slices.Contains(h.order, c) {
				h.primary = c
				h.mu.Unlock()
				return c.id
			}
			h.mu.Unlock()
			// Promoted a client that has since left; its sink goes with it.
			retry = true
			break
		}
		if !retry {
			for _, w := range behind {
				h.watchForDrain(w)
			}
			return ""
		}
	}
}

// drainWatch is a candidate an election skipped, with the signal its sink
// publishes the next time its queue catches up.
type drainWatch struct {
	client  *hostClient
	drained <-chan struct{}
}

// watchForDrain runs another election when w's queue catches up.
//
// A candidate that cannot drain within promoteFlushTimeout is skipped, and
// nothing brought it back: elections run from add and remove only. So a
// primary that leaves while every client left is more than a second behind —
// which is what a burst of output and a stopped terminal or two look like —
// ends with nobody promoted, and the session stays that way until the next
// attach or detach happens to run another election. Nobody paces the command
// meanwhile and no terminal is sent the queries a full-screen program asks,
// which is the whole of what a primary is for.
//
// Waiting on the queue rather than polling it keeps the cost where the fault
// is: a session with a primary arms nothing, and a client that never catches
// up is woken by its own sink failing or closing, both of which publish this
// same signal. A sink that had already finished is not watched at all — the
// sweep above has no signal to hand over for one, and its client's removal is
// an election in itself — while one that is merely stuck with its output
// undelivered holds this goroutine until the session ends, alongside the
// handler it is already holding.
func (h *hostClients) watchForDrain(w drainWatch) {
	c := w.client
	if !c.watching.CompareAndSwap(false, true) {
		return
	}
	go func() {
		<-w.drained
		// Cleared before the election rather than after it. The election
		// about to run may well skip this candidate again — output that
		// arrived while it was catching up puts it behind again — and it is
		// that election which arms the next watcher. Clearing afterwards
		// would make the arming a no-op against this goroutine's own flag,
		// which is to say the first failed retry would be the last.
		c.watching.Store(false)
		h.elect()
	}()
}
