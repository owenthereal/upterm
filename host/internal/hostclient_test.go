package internal

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// slowChannel is a session channel that takes a while per write, so bytes are
// provably queued in the async path when promotion runs.
type slowChannel struct {
	delay time.Duration
	rec   recordingWriter
}

func (s *slowChannel) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.rec.Write(p)
}

// newBlockingHandler is the blocked-logger handler fanout_test.go builds inline
// for TestCommandRunDoesNotHangOnABlockedLogger: a text handler whose writer
// delivers nothing until its gate is closed.
func newBlockingHandler(gate <-chan struct{}) slog.Handler {
	return slog.NewTextHandler(&gatedWriter{gate: gate, rec: &recordingWriter{}}, nil)
}

func TestHostSinkPromoteFlushesQueuedBytesBeforeFlipping(t *testing.T) {
	ch := &slowChannel{delay: 20 * time.Millisecond}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close() }()

	for _, s := range []string{"one ", "two ", "three "} {
		_, err := sink.Write([]byte(s))
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx))
	require.True(t, sink.isPrimary())

	_, err := sink.Write([]byte("four"))
	require.NoError(t, err)
	// Everything in order, nothing interleaved: the flip waited for the queue.
	require.Equal(t, "one two three four", string(ch.rec.bytes()))
}

func TestHostSinkPromoteHandsOverThePendingPartialRaw(t *testing.T) {
	ch := &slowChannel{}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close() }()

	// The filter holds the lead-in of what may be a query.
	_, err := sink.Write([]byte("text\x1b[6"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx))
	// Live output for the primary is unfiltered: the query must arrive whole.
	_, err = sink.Write([]byte("n"))
	require.NoError(t, err)
	require.Equal(t, "text\x1b[6n", string(ch.rec.bytes()))
}

// Promotion hands the filter's Pending to the new primary raw, ahead of the
// live bytes it now takes unfiltered, so the primary's terminal sees what the
// host wrote, byte for byte, whatever the filter was in the middle of when the
// flip came: a sequence it was deciding, one it had passed on with a close
// owed, or a string it had passed and was holding an ESC of. What it must not
// see is a byte twice -- a C0 the filter already forwarded stays forwarded
// once, and is no part of Pending.
func TestHostSinkPromoteInEveryHeldState(t *testing.T) {
	for _, tc := range []struct {
		name         string
		prefix, rest string
		want         string // "" is the raw input, prefix and rest as written
	}{
		{name: "a CSI held behind a passed DCS", prefix: "\x1bPq#0\x1b[6", rest: "nhello"},
		{name: "an over-bound CSI", prefix: "\x1b[" + strings.Repeat("0", 31), rest: "mX"},
		{name: "an OSC being held", prefix: "\x1b]0;t", rest: "\x07X"},
		{name: "a CSI and a C0 the filter forwarded", prefix: "\x1b[6\r", rest: "n", want: "\r\x1b[6n"},
		{name: "an ESC-intermediate head", prefix: "\x1b(", rest: "B"},
		{name: "an ESC held after a passed DCS", prefix: "\x1bPq#0\x1b", rest: "\\X"},
		{name: "an ESC held inside an OSC", prefix: "\x1b]0;t\x1b", rest: "\\X"},
		// The inner SGR passes the wrapper, so the ESC is held by a passing
		// wrapper, not by one still being decided.
		{name: "an ESC held inside a tmux wrapper", prefix: "\x1bPtmux;\x1b\x1b[1m\x1b", rest: "\x1b[31mX\x1b\\"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.prefix + tc.rest
			}

			ch := &slowChannel{}
			sink := newHostSink(ch, nil, "s", discardLogger())
			defer func() { _ = sink.Close() }()

			_, err := sink.Write([]byte(tc.prefix))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.True(t, sink.promote(ctx))
			_, err = sink.Write([]byte(tc.rest))
			require.NoError(t, err)
			require.Equal(t, want, string(ch.rec.bytes()))
		})
	}
}

func TestHostSinkPromoteAtEveryBoundaryOfADroppedQuery(t *testing.T) {
	in := "\x1bP+q544e\x1b\\hello"
	headerEnd := len("\x1bP+q") // classified once 'q' arrives
	for k := 0; k <= len(in); k++ {
		ch := &slowChannel{}
		sink := newHostSink(ch, nil, "s", discardLogger())
		_, err := sink.Write([]byte(in[:k]))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		require.True(t, sink.promote(ctx))
		cancel()
		_, err = sink.Write([]byte(in[k:]))
		require.NoError(t, err)
		got := string(ch.rec.bytes())
		if k < headerEnd {
			// Still deciding: the new primary gets the query whole, and answers it.
			require.Equal(t, in, got, "k=%d", k)
		} else {
			// Dropping (the terminator's ESC included) or past the query: none of
			// the query, and hello intact.
			require.Equal(t, "hello", got, "k=%d", k)
		}
		_ = sink.Close()
	}
}

// promotedAt promotes a secondary once it has been written the first k bytes
// of in, writes it the rest, and returns everything its channel received:
// what the secondary delivered before the flip, and what the new primary got
// after it.
func promotedAt(t *testing.T, in string, k int) string {
	t.Helper()
	ch := &slowChannel{}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close() }()
	_, err := sink.Write([]byte(in[:k]))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx), "k=%d", k)
	_, err = sink.Write([]byte(in[k:]))
	require.NoError(t, err)
	return string(ch.rec.bytes())
}

// A query that restarts at a dropped string's end reaches a primary promoted
// at any boundary inside the drop whole, from the ESC that ends the string:
// the primary is the one to answer it. Promoted before the string is
// classified, it gets the input whole; promoted after the secondary has
// dropped the restarted query too, it gets what the secondary left of it.
func TestHostSinkPromoteAtEveryBoundaryOfARestartedDrop(t *testing.T) {
	in := "\x1bP+q544e\x1bZhello"
	for k := 0; k <= len(in); k++ {
		want := "hello" // the secondary dropped ESC Z before the flip
		switch {
		case k < len("\x1bP+q"):
			want = in
		case k <= len("\x1bP+q544e\x1b"): // up to and including the restarting ESC
			want = "\x1bZhello"
		}
		require.Equal(t, want, promotedAt(t, in, k), "k=%d", k)
	}

	// Wrapped, the inner header completes at index 11, and the pair at 16 and
	// 17 decodes to the inner ESC that ends the drop. The stream resumes at
	// the pair's second raw ESC: carried from the last write at k == 18, and
	// at k == 19 and 20 the secondary has resumed and holds ESC [ or ESC [6
	// undecided, which promotion hands over raw.
	in = "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b[6nhello\x1b\\"
	for k := 0; k <= len(in); k++ {
		want := "hello\x1b\\" // the secondary dropped the DSR before the flip
		switch {
		case k < 12:
			want = in
		case k <= 20:
			want = "\x1b[6nhello\x1b\\"
		}
		require.Equal(t, want, promotedAt(t, in, k), "k=%d", k)
	}
}

// The same over wrapped strings, ESCs doubled. A wrapped query reaches the new
// primary whole before it is classified, and not at all from then on, while
// the wrapper's raw remainder does. A wrapper that passes reaches it whole
// wherever the flip lands.
func TestHostSinkPromoteAtEveryBoundaryOfAWrappedString(t *testing.T) {
	in := "\x1bPtmux;\x1b\x1b_Ga=q;AAAA\x1b\x1b\\\x1b\\hello"
	classified := len("\x1bPtmux;\x1b\x1b_Ga=q;")
	for k := 0; k <= len(in); k++ {
		want := "\x1b\\hello"
		if k < classified {
			want = in
		}
		require.Equal(t, want, promotedAt(t, in, k), "k=%d", k)
	}

	in = "\x1bPtmux;\x1b\x1b[31mX\x1b\\"
	for k := 0; k <= len(in); k++ {
		require.Equal(t, in, promotedAt(t, in, k), "k=%d", k)
	}
}

// A query that restarts at the drop's end must reach the new primary whole:
// it is answering queries now. Owen's case: ST and CAN endings can't catch a
// handoff that parses past the end.
func TestHostSinkPromoteMidDropKeepsTheQueryThatFollows(t *testing.T) {
	for _, c := range []struct{ before, after, want string }{
		{"\x1bP+q544e", "\x1bZhello", "\x1bZhello"}, // the restarting ESC in this write
		{"\x1bP+q544e\x1b", "Zhello", "\x1bZhello"}, // the restarting ESC held from the last write
		{"\x1bP+q544e", "\x1b[6nhello", "\x1b[6nhello"},
		{"\x1bP+q544e", "\x18hello", "\x18hello"}, // CAN goes raw
		{"\x1bP+q544e", "\x1b\\hello", "hello"},   // ST is part of the drop
		{"\x1bP+q544e\x1b", "\\hello", "hello"},
		// Inside a wrapper, the resume point carried from the last write
		// (Owen, 2026-10-11).
		{"\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b", "[6nhello\x1b\\", "\x1b[6nhello\x1b\\"},
		{"\x1bPtmux;\x1b\x1bP+q544e\x1b", "\x1b[6nhello\x1b\\", "\x1b[6nhello\x1b\\"},
		// A lone raw ESC x ends the wrapper during its inner drop, and the
		// stream resumes at that ESC, in this write or carried from the last.
		{"\x1bPtmux;\x1b\x1bP+q544e", "\x1b[6nhello", "\x1b[6nhello"},
		{"\x1bPtmux;\x1b\x1bP+q544e\x1b", "[6nhello", "\x1b[6nhello"},
		// An inner ESC after a pending one ends the string at the pending one,
		// so the stream resumes at that pair's second raw ESC, two raw ESCs
		// back: both carried, or one.
		{"\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b\x1b", "\x1b[6nhello", "\x1b\x1b\x1b[6nhello"},
		{"\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b", "\x1b\x1b[6nhello", "\x1b\x1b\x1b[6nhello"},
		{"\x1bP+q54", "4e", ""}, // still dropping when the write ends...
	} {
		ch := &slowChannel{}
		sink := newHostSink(ch, nil, "s", discardLogger())
		_, err := sink.Write([]byte(c.before))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		require.True(t, sink.promote(ctx))
		cancel()
		_, err = sink.Write([]byte(c.after))
		require.NoError(t, err)
		require.Equal(t, c.want, string(ch.rec.bytes()), "%q|%q", c.before, c.after)
		_ = sink.Close()
	}
	// ...and settles on a later write.
	ch := &slowChannel{}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close() }()
	_, _ = sink.Write([]byte("\x1bP+q54"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx))
	_, _ = sink.Write([]byte("4e"))
	_, _ = sink.Write([]byte("\x1bZhi"))
	require.Equal(t, "\x1bZhi", string(ch.rec.bytes()))
}

func TestHostSinkSecondaryFiltersLiveQueries(t *testing.T) {
	ch := &slowChannel{}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close() }()
	_, err := sink.Write([]byte("a\x1b[6nb"))
	require.NoError(t, err)
	require.NoError(t, sink.Flush(context.Background()))
	require.Equal(t, "ab", string(ch.rec.bytes()))
}

func TestHostSinkPromoteGivesUpWhenTheQueueDoesNotDrain(t *testing.T) {
	gate := make(chan struct{})
	ch := &gatedWriter{gate: gate, rec: &recordingWriter{}}
	sink := newHostSink(ch, nil, "s", discardLogger())
	defer func() { _ = sink.Close(); close(gate) }()
	_, err := sink.Write([]byte("stuck"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.False(t, sink.promote(ctx))
	require.False(t, sink.isPrimary())
}

// disconnectingChannel blocks every write until disconnect is called, then
// fails them: an SSH channel whose window is exhausted, and the connection
// close that is the only thing that releases it.
type disconnectingChannel struct {
	closed chan struct{}
	once   sync.Once
}

func newDisconnectingChannel() *disconnectingChannel {
	return &disconnectingChannel{closed: make(chan struct{})}
}

func (d *disconnectingChannel) Write(p []byte) (int, error) {
	<-d.closed
	return 0, io.ErrClosedPipe
}

func (d *disconnectingChannel) disconnect() { d.once.Do(func() { close(d.closed) }) }

// The queue can be empty while the filter still holds bytes, and the channel
// can be full. Promotion's hand-over of those bytes must be under the
// watchdog like every other primary write, or the sink lock is held forever
// and the fan-out with it.
func TestHostSinkPromoteBoundsThePendingWriteByTheWatchdog(t *testing.T) {
	orig := primaryStallTimeout
	primaryStallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { primaryStallTimeout = orig })

	ch := newDisconnectingChannel()
	sink := newHostSink(ch, ch.disconnect, "s", discardLogger())
	defer func() { _ = sink.Close() }()

	// Held by the filter, so the async queue is empty and Flush is instant.
	_, err := sink.Write([]byte("\x1b[6"))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	require.False(t, sink.promote(ctx), "a hand-over that cannot be delivered must not promote")
	require.Less(t, time.Since(start), 2*time.Second, "promotion must be bounded by the stall watchdog, not by ctx")
	select {
	case <-ch.closed:
	default:
		t.Fatal("the watchdog did not disconnect the client")
	}
}

// A sink promoted mid-drop hands nothing over, so its promotion can't stall,
// but the write that settles the drop goes raw from the string's end: that is
// a primary's write like any other, and the watchdog bounds it.
func TestHostSinkPromoteBoundsTheSettlingWriteByTheWatchdog(t *testing.T) {
	orig := primaryStallTimeout
	primaryStallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { primaryStallTimeout = orig })

	ch := newDisconnectingChannel()
	defer ch.disconnect() // releases a write the watchdog left parked
	sink := newHostSink(ch, ch.disconnect, "s", discardLogger())
	defer func() { _ = sink.Close() }()

	// Dropped by the filter, so nothing reaches the channel and Flush is instant.
	_, err := sink.Write([]byte("\x1bP+q54"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx))

	done := make(chan error, 1)
	go func() {
		_, err := sink.Write([]byte("4e\x18hello"))
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "a settling write the channel never took must fail")
	case <-time.After(2 * time.Second):
		t.Fatal("the settling write was not bounded by the stall watchdog")
	}
	select {
	case <-ch.closed:
	default:
		t.Fatal("the watchdog did not disconnect the client")
	}
}

// The disconnect is the recovery; the diagnostic is not. A logger blocked
// on a stopped terminal must not delay the close it describes. Reuse the
// blocking slog.Handler fanout_test.go builds for
// TestCommandRunDoesNotHangOnABlockedLogger.
func TestHostSinkStallDisconnectsBeforeLogging(t *testing.T) {
	orig := primaryStallTimeout
	primaryStallTimeout = 50 * time.Millisecond
	t.Cleanup(func() { primaryStallTimeout = orig })

	blocked := make(chan struct{})
	defer close(blocked)
	logger := slog.New(newBlockingHandler(blocked)) // never returns until blocked is closed

	ch := newDisconnectingChannel()
	sink := newHostSink(ch, ch.disconnect, "s", logger)
	defer func() { _ = sink.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.True(t, sink.promote(ctx))

	done := make(chan struct{})
	go func() { defer close(done); _, _ = sink.Write([]byte("parked")) }()
	select {
	case <-ch.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the stalled primary was not disconnected while its logger was blocked")
	}
	<-done
}

// parkingChannel blocks the drain inside its first write and says when it has,
// so a test can be certain what the filter is holding at that moment.
type parkingChannel struct {
	entered  chan struct{}
	tokens   chan struct{}
	open     chan struct{}
	once     sync.Once
	openOnce sync.Once
}

func newParkingChannel() *parkingChannel {
	return &parkingChannel{entered: make(chan struct{}), tokens: make(chan struct{}), open: make(chan struct{})}
}

func (p *parkingChannel) Write(b []byte) (int, error) {
	p.once.Do(func() { close(p.entered) })
	select {
	case <-p.tokens:
	case <-p.open:
	}
	return len(b), nil
}

// allow releases exactly one parked write, and returns once it has.
func (p *parkingChannel) allow() { p.tokens <- struct{}{} }

// openUp stops parking altogether, so nothing is left blocked on this channel.
func (p *parkingChannel) openUp() { p.openOnce.Do(func() { close(p.open) }) }

// A sink whose delivery has failed still flushes to nil — that is what
// AsyncWriter.Flush promises — while its drain goroutine may be anywhere,
// including inside the filter. Promoting it would read the filter from under
// that goroutine and put whatever the drain was carrying on the channel after
// the flip.
func TestHostSinkPromoteFailsOnAFailedSink(t *testing.T) {
	ch := newParkingChannel()
	defer ch.openUp()
	disconnected := make(chan struct{})
	var once sync.Once
	sink := newHostSink(ch, func() { once.Do(func() { ch.openUp(); close(disconnected) }) },
		"s", discardLogger())
	defer func() { _ = sink.Close() }()

	// The drain parks inside the filter's write to the channel.
	_, err := sink.Write([]byte("one"))
	require.NoError(t, err)
	<-ch.entered

	// Queue a second chunk and let the first through: the drain picks the
	// second up, leaves a partial sequence in the filter, and parks again — in
	// flight, with nothing ordering that work against this goroutine.
	_, err = sink.Write([]byte("two\x1b[6"))
	require.NoError(t, err)
	ch.allow()
	time.Sleep(100 * time.Millisecond)

	// Overflow the queue behind it. The client is disconnected, and from here
	// on Flush reports nil for a sink that delivered none of this.
	_, err = sink.Write(make([]byte, uio.DefaultGuestBufferSize+1))
	require.ErrorIs(t, err, uio.ErrOverflow)
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("the overflowed sink never disconnected its client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.False(t, sink.promote(ctx), "a sink whose delivery has failed is not a candidate")
	require.False(t, sink.isPrimary())
}

// The disconnect in Close is there to release a write parked in SSH, which can
// only exist once the fan-out has taken the sink. On the refused-attach path
// there is no such write, and the handler goes on to tell the client so.
func TestHostSinkCloseDisconnectsOnlyOnceAttached(t *testing.T) {
	calls := make(chan struct{}, 4)
	disconnect := func() { calls <- struct{}{} }

	refused := newHostSink(io.Discard, disconnect, "refused", discardLogger())
	require.NoError(t, refused.Close())
	require.Empty(t, calls, "a sink the fan-out refused must leave the connection alone")

	attached := newHostSink(io.Discard, disconnect, "attached", discardLogger())
	attached.markAttached()
	require.NoError(t, attached.Close())
	require.Len(t, calls, 1, "an attached sink disconnects on the way out")
}

// add and remove run an election on the attaching or detaching client's own
// handler. A diagnostic written under the election lock would hold every other
// client's attach and detach behind a stopped terminal.
func TestHostClientsElectionIsNotHeldByABlockedLogger(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	hc := &hostClients{logger: slog.New(newBlockingHandler(blocked))}

	a := &hostClient{id: "a", sink: newHostSink(io.Discard, nil, "a", discardLogger())}
	b := &hostClient{id: "b", sink: newHostSink(io.Discard, nil, "b", discardLogger())}
	defer func() { _ = a.sink.Close(); _ = b.sink.Close() }()

	done := make(chan struct{})
	go func() { defer close(done); hc.add(a); hc.add(b) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a blocked logger held the election lock")
	}
	require.Equal(t, "a", hc.primaryID())
}

func TestHostClientsElectTheEarliestAndReelectOnRemoval(t *testing.T) {
	hc := &hostClients{logger: discardLogger()}
	a := &hostClient{id: "a", sink: newHostSink(io.Discard, nil, "a", discardLogger())}
	b := &hostClient{id: "b", sink: newHostSink(io.Discard, nil, "b", discardLogger())}
	defer func() { _ = a.sink.Close(); _ = b.sink.Close() }()
	hc.add(a)
	hc.add(b)
	require.Equal(t, "a", hc.primaryID())
	require.True(t, a.sink.isPrimary())
	require.False(t, b.sink.isPrimary())

	hc.remove(a)
	require.Equal(t, "b", hc.primaryID())
	require.True(t, b.sink.isPrimary())

	hc.remove(b)
	require.Empty(t, hc.primaryID(), "no host client, no primary")
}

// The pacer stands aside while there is a primary, so it has to hear of every
// change and only of changes: elected, lost, the next one elected, lost.
func TestHostClientsReportThePrimaryToThePacer(t *testing.T) {
	var (
		mu      sync.Mutex
		reports []bool
	)
	hc := &hostClients{logger: discardLogger(), onPrimary: func(has bool) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, has)
	}}
	a := &hostClient{id: "a", sink: newHostSink(io.Discard, nil, "a", discardLogger())}
	b := &hostClient{id: "b", sink: newHostSink(io.Discard, nil, "b", discardLogger())}
	defer func() { _ = a.sink.Close(); _ = b.sink.Close() }()

	hc.add(a)
	hc.add(b)
	hc.remove(a)
	hc.remove(b)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []bool{true, false, true, false}, reports)
}

// Removal now runs on whichever goroutine saw the connection go, which can be
// the watchdog's, and it can land between the handler publishing its client
// and registering it. A client that has been removed is gone for good: adding
// it back would make a disconnected client the primary, which is the state
// this whole path exists to get out of.
func TestHostClientsAddRefusesAGoneClient(t *testing.T) {
	hc := &hostClients{logger: discardLogger()}
	c := &hostClient{id: "c", sink: newHostSink(io.Discard, nil, "c", discardLogger())}
	defer func() { _ = c.sink.Close() }()

	hc.remove(c)
	hc.add(c)
	require.Empty(t, hc.primaryID(), "a client removed before it was added must not become the primary")
	require.NotContains(t, hc.order, c, "a client removed before it was added must not be in the order")
}

// A sweep that promotes nobody is not the end of the election.
//
// Elections run from add and remove, so when the primary leaves while every
// client left is further behind than promoteFlushTimeout, the sweep skips all
// of them and the session has no primary: nothing paces the command and no
// terminal is sent the queries a full-screen program asks. Those clients do
// catch up — a stopped terminal is started again, a burst is delivered — and
// the one that does runs the election that promotes it, rather than the
// session waiting for somebody to attach or detach.
//
// One client, so that what is under test is the catching up rather than a
// second candidate arriving.
func TestHostClientsElectAgainOnceACandidateCatchesUp(t *testing.T) {
	gate := make(chan struct{})
	behind := &hostClient{id: "behind", sink: newHostSink(&gatedWriter{gate: gate, rec: &recordingWriter{}}, nil, "behind", discardLogger())}
	_, err := behind.sink.Write([]byte("more than a second's worth"))
	require.NoError(t, err)
	defer func() { _ = behind.sink.Close() }()

	orig := promoteFlushTimeout
	promoteFlushTimeout = 50 * time.Millisecond
	t.Cleanup(func() { promoteFlushTimeout = orig })

	hc := &hostClients{logger: discardLogger()}
	hc.add(behind)
	require.Empty(t, hc.primaryID(), "a client that cannot drain is not promoted")

	// The terminal reads again, and the queue goes out.
	close(gate)

	require.Eventually(t, func() bool {
		return hc.primaryID() == "behind"
	}, 5*time.Second, time.Millisecond, "the candidate was never promoted once its queue had caught up")
}

// The retry is not one-shot.
//
// A candidate is watched by one goroutine at a time, and the election that
// goroutine runs is also what arms the next watcher — output that arrived
// while the candidate was catching up leaves it behind again, and the sweep
// skips it again. So the candidate has to be watchable again before that
// election runs, not after it: the other order makes the arming a no-op
// against the watcher's own flag, and the first retry that fails to promote
// anyone is then the last retry there will ever be.
//
// The election is held up here by taking the lock it runs under, which is
// what makes the ordering observable rather than a race with the promotion.
func TestAWatchedCandidateIsWatchableAgainBeforeItsElectionRuns(t *testing.T) {
	gate := make(chan struct{})
	behind := &hostClient{id: "behind", sink: newHostSink(&gatedWriter{gate: gate, rec: &recordingWriter{}}, nil, "behind", discardLogger())}
	_, err := behind.sink.Write([]byte("queued"))
	require.NoError(t, err)
	defer func() { _ = behind.sink.Close() }()

	orig := promoteFlushTimeout
	promoteFlushTimeout = 50 * time.Millisecond
	t.Cleanup(func() { promoteFlushTimeout = orig })

	hc := &hostClients{logger: discardLogger()}
	hc.add(behind)
	require.True(t, behind.watching.Load(), "a skipped candidate is watched for catching up")

	// Everything up to the unlock below runs with the election blocked.
	hc.electMu.Lock()
	close(gate)

	watchable := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if !behind.watching.Load() {
			watchable = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	hc.electMu.Unlock()
	require.True(t, watchable, "the candidate was still spoken for while the election it triggered had not even started")

	// And the election it triggered runs to the end before the test does:
	// it reads promoteFlushTimeout, which the cleanup here restores.
	require.Eventually(t, func() bool {
		return hc.primaryID() == "behind"
	}, 5*time.Second, time.Millisecond, "the released candidate was never promoted")
}

func TestHostClientsSkipACandidateThatCannotDrain(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	stuck := &hostClient{id: "stuck", sink: newHostSink(&gatedWriter{gate: gate, rec: &recordingWriter{}}, nil, "stuck", discardLogger())}
	_, _ = stuck.sink.Write([]byte("x"))
	fine := &hostClient{id: "fine", sink: newHostSink(io.Discard, nil, "fine", discardLogger())}
	defer func() { _ = stuck.sink.Close(); _ = fine.sink.Close() }()

	orig := promoteFlushTimeout
	promoteFlushTimeout = 50 * time.Millisecond
	t.Cleanup(func() { promoteFlushTimeout = orig })

	hc := &hostClients{logger: discardLogger()}
	hc.add(stuck)
	require.Empty(t, hc.primaryID(), "a client that cannot drain is not promoted")
	hc.add(fine)
	require.Equal(t, "fine", hc.primaryID())
}
