package internal

import (
	"context"
	"io"
	"log/slog"
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
