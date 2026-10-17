package io

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
)

func Test_MultiWriter_ReplayIsByteBounded(t *testing.T) {
	w := NewMultiWriter(10)
	for _, s := range []string{"aaaaa", "bbbbb", "ccccc"} {
		_, err := w.Write([]byte(s))
		require.NoError(t, err)
	}

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "bbbbbccccc", late.String())
}

func Test_MultiWriter_ReplayTrimsOversizedWrite(t *testing.T) {
	w := NewMultiWriter(4)
	_, err := w.Write([]byte("abcdefgh"))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "efgh", late.String())
}

func Test_MultiWriter_ReplayTrimsPartialLeadingChunk(t *testing.T) {
	w := NewMultiWriter(8)
	for _, s := range []string{"aaaaaa", "bbbbbb"} {
		_, err := w.Write([]byte(s))
		require.NoError(t, err)
	}

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "aabbbbbb", late.String())
}

// The ring bounded its bytes but not its chunks, so a producer writing one
// byte at a time filled it with one chunk per byte: megabytes of slice
// headers, and a joining writer handed that many separate Write calls with
// the fan-out lock held for all of them.
func Test_MultiWriter_ReplayChunkCountIsBounded(t *testing.T) {
	const ring = 64 << 10

	w := NewMultiWriter(ring)
	want := make([]byte, 0, ring)
	for i := 0; i < ring; i++ {
		b := byte('a' + i%26)
		_, err := w.Write([]byte{b})
		require.NoError(t, err)
		want = append(want, b)
	}

	require.LessOrEqual(t, len(w.buffer.Data()), ring/ringChunkSize+2)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, string(want), late.String())
}

// Coalescing into the tail chunk must leave what Data already handed out
// alone: those slices are what a joiner is being written, and a chunk that
// grew or shifted under one would replay the wrong bytes.
func Test_MultiWriter_ReplayTrimsACoalescedTail(t *testing.T) {
	// Bigger than one chunk, so the ring's head is a coalesced tail by the
	// time the trimming starts on it.
	const ring = ringChunkSize + 1000

	w := NewMultiWriter(ring)
	var all []byte
	write := func(n int) {
		for i := 0; i < n; i++ {
			b := byte('a' + len(all)%26)
			_, err := w.Write([]byte{b})
			require.NoError(t, err)
			all = append(all, b)
		}
	}

	write(100)
	handedOut := w.buffer.Data()
	before := make([]string, len(handedOut))
	for i, chunk := range handedOut {
		before[i] = string(chunk)
	}

	// Enough to coalesce into that tail, open new chunks, and then trim the
	// front of the coalesced one.
	write(ring)

	for i, chunk := range handedOut {
		require.Equal(t, before[i], string(chunk),
			"chunk %d changed after it had been handed to a joiner", i)
	}

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, string(all[len(all)-ring:]), late.String())
}

func Test_MultiWriter_ReplayStripsTerminalQueries(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)

	live := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(live))

	_, err := w.Write([]byte("before\x1b[6nafter"))
	require.NoError(t, err)

	// Live output is untouched: filtering live output is the session handler's
	// job, per attached client, not the fan-out's.
	require.Equal(t, "before\x1b[6nafter", live.String())

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "beforeafter", late.String())
}

// tmux 3.8 asks its terminal whether synchronized output is supported with
// DECRQM, "ESC [ ? 2026 $ p", and a guest whose terminal answers it types the
// reply into the shared pty. The primary's stream is raw, so its terminal
// answers; every guest must see none of it, whether it was attached when the
// query was written, joins after it, or joins in the middle of it. The guests
// are built the way server.go builds one: a TerminalQueryFilter in front of
// what takes the bytes.
func TestMultiWriter_GuestsNeverSeeDECRQM(t *testing.T) {
	const query = "\x1b[?2026$p"

	w := NewMultiWriter(DefaultReplayBytes)
	primary := &recordingWriter{}
	require.NoError(t, w.Append(primary))
	attached := &recordingWriter{}
	require.NoError(t, w.Append(NewTerminalQueryFilter(attached)))

	_, err := w.Write([]byte("\x1b[?1049h" + query + "frame"))
	require.NoError(t, err)

	// Joining after the query was written: the ring replays it, and the ring
	// is filtered already, so the joiner's own filter has nothing to catch.
	joined := &recordingWriter{}
	require.NoError(t, w.Append(NewTerminalQueryFilter(joined)))

	for name, got := range map[string]*recordingWriter{"attached": attached, "joined": joined} {
		require.Equal(t, "\x1b[?1049hframe", string(got.bytes()), name)
	}
	require.Equal(t, 1, strings.Count(string(primary.bytes()), query), "the primary's terminal answers it once")

	// Joining in the middle of it: the filter is holding the lead-in, which
	// Append replays ahead of the live bytes, so the joiner's filter holds it
	// too and drops the query when its last byte arrives.
	_, err = w.Write([]byte("more\x1b[?2026$"))
	require.NoError(t, err)
	midway := &recordingWriter{}
	require.NoError(t, w.Append(NewTerminalQueryFilter(midway)))
	_, err = w.Write([]byte("pend"))
	require.NoError(t, err)

	for name, got := range map[string]*recordingWriter{"attached": attached, "joined": joined, "midway": midway} {
		require.NotContains(t, string(got.bytes()), "$p", name)
		require.Contains(t, string(got.bytes()), "frame", name)
		require.Equal(t, "\x1b[?1049hframemoreend", string(got.bytes()), name)
	}
	require.Equal(t, 2, strings.Count(string(primary.bytes()), query), "the primary's terminal answers both")
}

// A joiner that attaches mid-sequence must see the sequence whole, not just
// the tail the live fan-out delivers after it joins. The lead-in the filter
// is still holding is not in the ring yet, so Append must hand it over too.
func Test_MultiWriter_JoinerSeesSplitSequenceWhole(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)

	_, err := w.Write([]byte("before\x1b["))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))

	_, err = w.Write([]byte("?1049hafter"))
	require.NoError(t, err)

	require.Equal(t, "before\x1b[?1049hafter", late.String())
}

// The trim boundary lands wherever the ring's byte budget puts it, which is
// as easily inside an escape sequence as between two. The ring then starts
// with that sequence's tail while only the tracker still holds its head, and
// a joiner handed the tail alone prints it as text on the wrong screen --
// permanently, because nothing repeats the sequence for an attached guest.
func Test_MultiWriter_JoinerSeesTheSequenceTheRingStartsInside(t *testing.T) {
	w := NewMultiWriter(16)

	_, err := w.Write([]byte("\x1b[?1049h"))
	require.NoError(t, err)

	// 15 more bytes push the ring 7 over, which trims it to exactly the "h"
	// that terminates the switch to the alternate screen.
	_, err = w.Write([]byte("0123456789abcde"))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "\x1b[?1049"+"h0123456789abcde", late.String(),
		"the snapshot must carry the head of the sequence the ring starts inside")

	// Once the terminator has left the ring too, the tracker holds the
	// finished mode instead and there is no partial left to replay.
	_, err = w.Write([]byte("fghijklmnopqrstu"))
	require.NoError(t, err)

	later := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(later))
	require.Equal(t, "\x1b[?1049h"+"fghijklmnopqrstu", later.String())
}

// The same boundary falls inside string sequences, which are the long ones: a
// window title, a hyperlink, an OSC 52 clipboard. The ring then starts partway
// through the payload, and a joiner handed that alone has the rest of somebody
// else's title typed onto its screen, because the introducer that made those
// bytes a string left with the eviction.
func Test_MultiWriter_JoinerSeesTheStringTheRingStartsInside(t *testing.T) {
	w := NewMultiWriter(16)

	const title = "\x1b]0;title\x07" // 10 bytes
	_, err := w.Write([]byte(title))
	require.NoError(t, err)

	// 11 more bytes push the ring 5 over, which trims it to the middle of the
	// title's payload.
	const after = "0123456789a"
	_, err = w.Write([]byte(after))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "\x1b]0;t"+"itle\x07"+after, late.String(),
		"the snapshot must carry the head of the string the ring starts inside")
}

func Test_MultiWriter_ReplayRestoresModesAfterRollover(t *testing.T) {
	w := NewMultiWriter(16) // far too small to still hold the mode sequences

	_, err := w.Write([]byte("\x1b[?1049h\x1b[?2004h"))
	require.NoError(t, err)
	_, err = w.Write([]byte("0123456789abcdefghij"))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))

	got := late.String()
	// Bracketed paste first, then the alternate screen: the snapshot puts the
	// screen switch after the DEC private modes.
	require.True(t, strings.HasPrefix(got, "\x1b[?2004h\x1b[?1049h"),
		"replay must open with the mode snapshot, got %q", got)
	require.True(t, strings.HasSuffix(got, "defghij"),
		"replay must still end with the ring's tail, got %q", got)
}

// The snapshot is replayed ahead of the ring, so it has to describe the
// terminal as of the ring's first byte. Fed at the ring's entrance instead,
// the tracker described the state after it, and a mode set inside the ring
// window was applied twice: "qqq ESC(0 qqq" reached a joiner as
// "ESC(0 qqq ESC(0 qqq", drawing all six characters in the graphics charset
// instead of three.
func Test_MultiWriter_SnapshotDescribesTheRingStartNotTheLatestState(t *testing.T) {
	w := NewMultiWriter(64)

	_, err := w.Write([]byte("qqq\x1b(0qqq"))
	require.NoError(t, err)

	// Nothing has left the ring, so the ring carries the charset switch
	// itself and the snapshot has nothing to add.
	early := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(early))
	require.Equal(t, "qqq\x1b(0qqq", early.String())

	// Push it out of the ring: now it survives only in the snapshot, and
	// still only once.
	plain := strings.Repeat("z", 64)
	_, err = w.Write([]byte(plain))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))
	require.Equal(t, "\x1b(0"+plain, late.String())
}

// A write larger than the ring drops everything queued and its own leading
// bytes. Both left the ring, and the queued bytes left first: handing them to
// the tracker the other way round makes it believe the older sequence is the
// newer one.
func Test_MultiWriter_OversizedWriteEvictsInStreamOrder(t *testing.T) {
	w := NewMultiWriter(8)

	_, err := w.Write([]byte("\x1b[?2004h"))
	require.NoError(t, err)

	_, err = w.Write([]byte("\x1b[?2004ltrailing"))
	require.NoError(t, err)

	late := bytes.NewBuffer(nil)
	require.NoError(t, w.Append(late))

	// Bracketed paste ends back off, which is where a joining terminal
	// already is, so the snapshot says nothing and the ring is all there is.
	// Out of order it would open with a stale "\x1b[?2004h".
	require.Equal(t, "trailing", late.String())
}

func Test_MultiWriter(t *testing.T) {
	assert := assert.New(t)

	w1 := bytes.NewBuffer(nil)
	w := NewMultiWriter(6, w1)

	r := bytes.NewBufferString("hello1")
	_, _ = io.Copy(w, r)

	assert.Equal("hello1", w1.String())

	// append w2
	r = bytes.NewBufferString("hello2")
	w2 := bytes.NewBuffer(nil)
	_ = w.Append(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2", w1.String())
	assert.Equal("hello1hello2", w2.String())

	// append w3
	r = bytes.NewBufferString("hello3")
	w3 := bytes.NewBuffer(nil)
	_ = w.Append(w3)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3", w3.String())

	// remove w2
	r = bytes.NewBufferString("hello4")
	w.Remove(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3hello4", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3hello4", w3.String())
}

// blockingWriter models a guest whose SSH channel window has filled because it
// stopped reading: Write blocks until released. It closes entered first, so a
// test can wait for the fan-out to actually reach a writer rather than for the
// goroutine that will eventually call Write to be scheduled.
type blockingWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

type failingWriter struct{ writes int }

func (f *failingWriter) Write(p []byte) (int, error) {
	f.writes++
	return 0, errors.New("guest went away")
}

// A stuck writer must not stop the session being modified around it.
//
// MultiWriter used to hold its lock across every write, so a guest that stopped
// reading blocked Remove. The host removes its writer as HandleSession returns,
// so HandleSession never returned and never emitted the client-left event that
// is deferred behind it.
func TestMultiWriterStuckWriterDoesNotBlockRemove(t *testing.T) {
	stuck := newBlockingWriter()
	defer close(stuck.release)

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(stuck))

	go func() { _, _ = w.Write([]byte("shell output")) }()

	// Wait for the fan-out to be inside the stuck writer, not merely for the
	// writing goroutine to have started. Signalling from the caller side let
	// Remove win the race and pass without ever exercising the bug.
	<-stuck.entered

	done := make(chan struct{})
	go func() { defer close(done); w.Remove(stuck) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Remove blocked behind a stuck writer")
	}
}

// Concurrent producers must not reach the same writer at once.
//
// Most attached writers are not concurrency safe, and even one that is would
// end up with two writes interleaved. Run under -race, two goroutines writing
// into a shared bytes.Buffer report a data race if the fan-out is unserialized.
func TestMultiWriterConcurrentWritesAreSerialized(t *testing.T) {
	var shared bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(&shared))

	const (
		producers = 4
		writes    = 200
	)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range producers {
		wg.Go(func() {
			<-start
			for range writes {
				_, _ = w.Write([]byte("chunk"))
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, producers*writes*len("chunk"), shared.Len(), "every write should land intact")
}

// sliceWriter is a legal io.Writer whose dynamic type cannot be compared, so
// `t.writers[i] == v` inside Remove would panic on it.
type sliceWriter []byte

func (s sliceWriter) Write(p []byte) (int, error) { return len(p), nil }

type funcWriter func(p []byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) }

// wrappedWriter hides the problem one level down. Its type is comparable --
// a struct with an interface field is -- so a check that asks the type says
// yes, and the comparison inside Remove panics anyway when the writers it
// holds are funcs. Decorators shaped exactly like this are ordinary: the host
// attaches one, TerminalQueryFilter, and it is only safe because it is
// attached by pointer.
type wrappedWriter struct{ io.Writer }

// Append refuses a writer Remove could never match.
//
// Write removes the writers that failed it, so a non-comparable writer turns
// an ordinary guest disconnect into a panic in the host's pty copy, which
// takes the process down. Reporting it from Append keeps the failure at the
// call that can still do something about it.
func TestMultiWriterAppendRejectsUnremovableWriters(t *testing.T) {
	discard := funcWriter(func(p []byte) (int, error) { return len(p), nil })

	tests := []struct {
		name   string
		writer io.Writer
	}{
		{name: "nil", writer: nil},
		{name: "slice", writer: sliceWriter(nil)},
		{name: "func", writer: discard},
		{name: "struct wrapping a func writer", writer: wrappedWriter{discard}},
		{name: "struct wrapping a slice writer", writer: wrappedWriter{sliceWriter(nil)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, NewMultiWriter(1).Append(tt.writer))
		})
	}
}

// The check is on the value, so it must not turn away a writer that is
// perfectly removable. A decorator holding a pointer is the shape the host
// actually attaches, and rejecting it would stop guests joining at all.
func TestMultiWriterAppendAcceptsComparableWrappers(t *testing.T) {
	var inner bytes.Buffer
	wrapped := wrappedWriter{&inner}

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(wrapped))

	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", inner.String())

	// Removal is where an unremovable writer would have panicked, and Write
	// does it unprompted for any writer that fails, so this is the half of
	// the invariant that keeps the panic out of the host's pty copy.
	w.Remove(wrapped)
	_, err = w.Write([]byte("gone"))
	require.NoError(t, err)
	assert.Equal(t, "hello", inner.String(), "the wrapper should have been removable by identity")
}

// A writer that fails must not fail the producer.
//
// The producer is the host's pty copy. Returning an error aborted it, which
// ended the command and tore the session down, so one guest disconnecting at
// the wrong moment killed everyone's session.
func TestMultiWriterFailingWriterIsDroppedNotPropagated(t *testing.T) {
	bad := &failingWriter{}
	var good bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(bad))
	require.NoError(t, w.Append(&good))

	n, err := w.Write([]byte("first"))
	require.NoError(t, err, "a broken guest must not fail the host's output copy")
	assert.Equal(t, len("first"), n)
	assert.Equal(t, "first", good.String(), "a broken guest must not silence the writers after it")

	_, err = w.Write([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, "firstsecond", good.String())
	assert.Equal(t, 1, bad.writes, "a writer that failed should be dropped, not retried")
}

// Remove used to count down to index 1, so whatever sat at index 0 was stuck
// there for the life of the session.
func TestMultiWriterRemoveFirstWriter(t *testing.T) {
	var first, second bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(&first))
	require.NoError(t, w.Append(&second))

	w.Remove(&first)
	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)

	assert.Empty(t, first.String(), "the writer at index 0 should have been removed")
	assert.Equal(t, "hello", second.String())
}

// A writer joining a live session must see a contiguous stream: no byte
// delivered twice, none missing. Append replays the buffer and joins the member
// list as two separate steps today, with no lock spanning them, so a concurrent
// Write lands either side of the gap.
func TestMultiWriterAppendIsAtomicWithTheFanOut(t *testing.T) {
	for attempt := range 50 {
		w := NewMultiWriter(5)

		produced := make(chan string, 1)
		stop := make(chan struct{})
		// Closed after the first write. The joiner must not be attached
		// before the producer has run at all: on a loaded runner (or with one
		// P) the goroutine can otherwise be starved past the whole window,
		// see stop already closed on its first iteration, and hand back
		// nothing -- which failed the non-empty assertion below in CI while
		// proving nothing about atomicity.
		started := make(chan struct{})
		go func() {
			var sent []byte
			for i := 0; ; i++ {
				select {
				case <-stop:
					produced <- string(sent)
					return
				default:
				}
				p := []byte{byte('a' + i%26)}
				sent = append(sent, p...)
				_, _ = w.Write(p)
				if i == 0 {
					close(started)
				}
			}
		}()

		<-started
		time.Sleep(time.Duration(attempt%5) * time.Millisecond)
		var joined bytes.Buffer
		require.NoError(t, w.Append(&joined))
		time.Sleep(time.Millisecond)
		close(stop)
		all := <-produced

		got := joined.String()
		require.NotEmpty(t, got, "a joining writer should receive the replay buffer")
		require.Contains(t, all, got,
			"attempt %d: a joining writer saw bytes that were duplicated or skipped", attempt)
	}
}

// Data built its result with make([][]byte, len(queue)) and then appended, so it
// returned N nil entries before the N real ones and every newly attached writer
// received N zero-length writes.
func TestMultiWriterReplayHasNoEmptyWrites(t *testing.T) {
	w := NewMultiWriter(6)
	_, _ = w.Write([]byte("one"))
	_, _ = w.Write([]byte("two"))

	var rec recordingWriter
	require.NoError(t, w.Append(&rec))

	// Chunk boundaries are the ring's business -- small writes are coalesced
	// -- but none of them may be empty.
	require.NotContains(t, rec.writeSizes(), 0, "replay must not emit empty writes")
	require.Equal(t, "onetwo", string(rec.bytes()))
}

func TestMultiWriterZeroSizedReplayBufferDoesNotPanic(t *testing.T) {
	w := NewMultiWriter(0)
	var rec recordingWriter
	require.NoError(t, w.Append(&rec))
	require.NotPanics(t, func() { _, _ = w.Write([]byte("output")) })
	require.Equal(t, "output", string(rec.bytes()))
}

func TestMultiWriterShutdownFlushesAsyncMembers(t *testing.T) {
	gate := newGateWriter()
	sink := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(sink))
	_, _ = w.Write([]byte("last line of the session"))
	<-gate.entered

	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdown <- w.Shutdown(ctx)
	}()

	select {
	case err := <-shutdown:
		t.Fatalf("Shutdown returned before the sink drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(gate.release)
	select {
	case err := <-shutdown:
		require.NoError(t, err)
		require.Equal(t, "last line of the session", string(gate.bytes()))
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown never returned")
	}
}

// The SSH server keeps serving while the flush runs. Without the quiesce, a
// guest attaching after the snapshot has its replay queued into a sink nobody
// will flush, and teardown closes it before delivery: an empty screen and a
// disconnect.
func TestMultiWriterShutdownRefusesLaterAppends(t *testing.T) {
	w := NewMultiWriter(5)
	var before bytes.Buffer
	require.NoError(t, w.Append(&before))

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))

	var after bytes.Buffer
	require.ErrorIs(t, w.Append(&after), ErrClosed)
}

// The sequential case above proves the door is shut; this proves there is no
// gap in front of it. An attach racing the quiesce must land on one side or
// the other — attached and therefore flushed, or refused — never attached to a
// snapshot that has already been taken, which is the outcome that leaves a
// guest with a queued replay nobody will deliver.
func TestMultiWriterAppendRacingShutdownHasOnlyTwoOutcomes(t *testing.T) {
	for attempt := range 50 {
		w := NewMultiWriter(6)
		_, _ = w.Write([]byte("output"))

		var out recordingWriter
		sink := NewAsyncWriter(&out, DefaultGuestBufferSize, nil)

		var (
			wg        sync.WaitGroup
			appendErr error
		)
		wg.Add(2)
		go func() { defer wg.Done(); appendErr = w.Append(sink) }()
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = w.Shutdown(ctx)
		}()
		wg.Wait()

		if appendErr == nil {
			require.Equal(t, "output", string(out.bytes()),
				"attempt %d: an attach that succeeded must have been flushed", attempt)
		} else {
			require.ErrorIs(t, appendErr, ErrClosed, "attempt %d", attempt)
			require.Empty(t, out.bytes(), "attempt %d: a refused attach must receive nothing", attempt)
		}
		_ = sink.Close()
	}
}

// resetBuffer is a member that wants the session's reset, as a guest's sink
// does.
type resetBuffer struct{ *bytes.Buffer }

func (resetBuffer) WantsReset() bool { return true }

// resetSink is the same, for a member that delivers asynchronously.
type resetSink struct{ *AsyncWriter }

func (resetSink) WantsReset() bool { return true }

// A session can end with its command still holding the terminal: killed on
// the alternate screen, say, with bracketed paste on. Every terminal watching
// is left that way too, and a guest's is not one anything else will put back
// -- a plain ssh client restores termios on the way out and nothing more. So
// the fan-out's last write to each member that wants one, behind everything
// else it was sent, undoes what the session left set: on the member that
// watched it all, and on one that joined after the modes had scrolled out of
// the ring. A member that does not want one -- a viewer capturing the output
// to a file -- is sent what the command wrote and nothing more.
func TestMultiWriterShutdownPutsEveryTerminalBack(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replay  int
		stream  []string
		restore string
	}{
		{
			name:    "modes still in the ring",
			replay:  1024,
			stream:  []string{"\x1b[?1049h\x1b[?2004h\x1b[>1u", "0123456789abcdefghij"},
			restore: "\x1b[<1u\x1b[?1049l\x1b[?2004l",
		},
		{
			name:    "modes only in the tracker",
			replay:  16,
			stream:  []string{"\x1b[?1049h\x1b[?2004h\x1b[>1u", "0123456789abcdefghij"},
			restore: "\x1b[<1u\x1b[?1049l\x1b[?2004l",
		},
		{
			// The terminal is inside the OSC as well, and would read the
			// reset as the rest of its title.
			name:    "output stopped inside a sequence",
			replay:  1024,
			stream:  []string{"\x1b[?2004h", "\x1b]0;a title"},
			restore: "\x18\x1b[?2004l",
		},
		{
			name:   "the command put everything back itself",
			replay: 1024,
			stream: []string{"\x1b[?1049h\x1b[?2004h", "\x1b[?2004l\x1b[?1049l"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewMultiWriter(tc.replay)
			early, late := resetBuffer{&bytes.Buffer{}}, resetBuffer{&bytes.Buffer{}}
			var capture bytes.Buffer
			require.NoError(t, w.Append(early, &capture))
			_, _ = w.Write([]byte(tc.stream[0]))
			require.NoError(t, w.Append(late))
			_, _ = w.Write([]byte(tc.stream[1]))
			lateBefore := late.Len()

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			require.NoError(t, w.Shutdown(ctx))

			require.Equal(t, strings.Join(tc.stream, "")+tc.restore, early.String(), "the member that saw it all")
			require.Equal(t, tc.restore, late.String()[lateBefore:], "the member that joined later")
			require.Equal(t, strings.Join(tc.stream, ""), capture.String(), "a member that wants no reset")
		})
	}
}

// The reset is queued only once a guest's tail has been delivered. Queued
// behind it, it could take a sink that was going to drain past its bound, and
// a sink that overflows is a guest dropped -- for a reset, and its tail with
// it.
func TestMultiWriterShutdownResetDoesNotOverflowAGuest(t *testing.T) {
	gate := newGateWriter()
	dropped := make(chan error, 1)
	sink := NewAsyncWriter(gate, 64, func(err error) { dropped <- err })
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(1024)
	require.NoError(t, w.Append(resetSink{sink}))
	_, _ = w.Write([]byte("\x1b[?2004h"))
	<-gate.entered
	// 60 of the sink's 64 bytes queued behind the write the guest has not
	// taken yet, so an 8-byte reset does not fit beside them.
	tail := strings.Repeat("x", 60)
	_, _ = w.Write([]byte(tail))

	go func() {
		time.Sleep(50 * time.Millisecond)
		close(gate.release)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))

	select {
	case err := <-dropped:
		t.Fatalf("the guest was dropped: %v", err)
	default:
	}
	require.Equal(t, "\x1b[?2004h"+tail+"\x1b[?2004l", string(gate.bytes()))
}

// laggingWriter takes a while over every write, as a guest at the far end of a
// real network does.
type laggingWriter struct{ recordingWriter }

func (s *laggingWriter) Write(p []byte) (int, error) {
	time.Sleep(20 * time.Millisecond)
	return s.recordingWriter.Write(p)
}

// A guest that is stuck until the deadline must not cost the others their
// reset. Each member is reset as soon as its own tail is delivered, so the
// healthy one has its reset by the time Shutdown gives up on the stuck one.
func TestMultiWriterShutdownResetsEachGuestOnItsOwnTime(t *testing.T) {
	stuck := newGateWriter()
	defer close(stuck.release)
	stuckSink := NewAsyncWriter(stuck, DefaultGuestBufferSize, nil)
	defer func() { _ = stuckSink.Close() }()
	healthy := &laggingWriter{}
	healthySink := NewAsyncWriter(healthy, DefaultGuestBufferSize, nil)
	defer func() { _ = healthySink.Close() }()

	w := NewMultiWriter(1024)
	require.NoError(t, w.Append(resetSink{stuckSink}, resetSink{healthySink}))
	_, _ = w.Write([]byte("\x1b[?2004h"))
	<-stuck.entered

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, w.Shutdown(ctx), context.DeadlineExceeded, "the stuck guest")

	require.Equal(t, "\x1b[?2004h\x1b[?2004l", string(healthy.bytes()), "the healthy guest, reset before Shutdown returned")
}

// pacedWriter takes the next of its delays over each write, as a guest on a
// slow link does.
type pacedWriter struct {
	recordingWriter
	delays []time.Duration
}

func (p *pacedWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	var d time.Duration
	if len(p.delays) > 0 {
		d, p.delays = p.delays[0], p.delays[1:]
	}
	p.mu.Unlock()
	time.Sleep(d)
	return p.recordingWriter.Write(b)
}

// A guest that takes its tail just inside the deadline still gets its reset:
// the reset's own flush has a window of its own rather than what is left of
// the shared one, which may be nothing.
func TestMultiWriterShutdownGivesAResetItsOwnWindow(t *testing.T) {
	slow := &pacedWriter{delays: []time.Duration{200 * time.Millisecond, 150 * time.Millisecond}}
	sink := NewAsyncWriter(slow, DefaultGuestBufferSize, nil)
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(1024)
	require.NoError(t, w.Append(resetSink{sink}))
	_, _ = w.Write([]byte("\x1b[?2004h"))

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))
	require.Equal(t, "\x1b[?2004h\x1b[?2004l", string(slow.bytes()))
}

func TestMultiWriterShutdownIgnoresPlainWriters(t *testing.T) {
	w := NewMultiWriter(5)
	var plain bytes.Buffer
	require.NoError(t, w.Append(&plain))
	_, _ = w.Write([]byte("output"))

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx), "a synchronous writer is delivered by definition")
}

func TestMultiWriterShutdownGivesUpOnAStuckSink(t *testing.T) {
	gate := newGateWriter()
	defer close(gate.release)
	sink := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(sink))
	_, _ = w.Write([]byte("never delivered"))
	<-gate.entered

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, w.Shutdown(ctx), context.DeadlineExceeded)
}

// The issue, end to end at the fan-out level: one guest that has stopped
// reading must not stall the host's terminal or any other guest, and must
// itself be dropped rather than tolerated.
//
// Before per-guest buffering, the stuck writer held the serial fan-out inside
// its Write and nothing after it in the slice received anything at all.
func TestMultiWriterSlowGuestDoesNotStallTheSession(t *testing.T) {
	const sinkCap = 4 << 10

	var hostStdout recordingWriter // attached unwrapped, as the host's own is

	healthyOut := &recordingWriter{}
	healthy := NewAsyncWriter(healthyOut, DefaultGuestBufferSize, nil)
	defer func() { _ = healthy.Close() }()

	stuckOut := newGateWriter()
	defer close(stuckOut.release)
	dropped := make(chan error, 1)
	stuck := NewAsyncWriter(stuckOut, sinkCap, func(err error) { dropped <- err })
	defer func() { _ = stuck.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(&hostStdout))
	require.NoError(t, w.Append(stuck))
	require.NoError(t, w.Append(healthy))

	// Fill the stuck guest's buffer and keep going, as a `cat` of a large file
	// would. Run on its own goroutine and race it against a timeout, the same
	// way TestAsyncWriterWriteDoesNotBlockOnStuckWriter does: nothing here
	// bounds an individual w.Write call, so a regression that reintroduces
	// blocking would otherwise hang this goroutine until the package's
	// -timeout killed the whole binary instead of failing just this test.
	line := bytes.Repeat([]byte("x"), 1<<10)
	var (
		want     []byte
		writeErr error
		writeN   int
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 64 {
			want = append(want, line...)
			writeN, writeErr = w.Write(line)
			if writeErr != nil || writeN != len(line) {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the fan-out blocked on a stuck guest")
	}
	// require.FailNow, which these call on failure, must only run on the test
	// goroutine, so the checks are made here rather than inside the goroutine
	// above.
	require.NoError(t, writeErr, "the fan-out never reports a guest's failure")
	require.Equal(t, len(line), writeN)

	select {
	case err := <-dropped:
		require.ErrorIs(t, err, ErrOverflow)
	case <-time.After(5 * time.Second):
		t.Fatal("the stuck guest was never dropped")
	}

	require.Equal(t, want, hostStdout.bytes(), "the host's terminal must see everything")
	require.Eventually(t, func() bool { return bytes.Equal(healthyOut.bytes(), want) },
		5*time.Second, time.Millisecond, "a healthy guest must see everything")

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx), "a dropped guest must not fail shutdown")
}

// ringStream is n bytes of the stream starting at offset at. No two adjacent
// offsets hold the same byte, so a range that is off by one in either
// direction reads back different.
func ringStream(at, n int) []byte {
	p := make([]byte, n)
	for i := range p {
		o := at + i
		p[i] = byte(o*131 + o>>8)
	}
	return p
}

// ringCase is a ring and the sizes it is written in.
type ringCase struct {
	name   string
	max    int
	writes []int
	chunks int // the fewest chunks the ring is left holding; 0 for no minimum
}

// ringCases cover the ways bytes enter and leave the ring: a ring evicting
// part of its head chunk on every write; one whose writes close chunks, so
// that a range spans several; one handed a write larger than itself, an empty
// one and one exactly its size; and one that keeps nothing.
var ringCases = []ringCase{
	{"64 bytes in 16-byte writes", 64, []int{16, 16, 16, 16, 16, 16, 16, 16, 16}, 1},
	{"chunks", 10000, []int{1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500}, 4},
	{"large and empty writes", 64, []int{0, 16, 16, 100, 5, 0, 64, 65, 3}, 1},
	{"nothing kept", 0, []int{16, 8, 0, 16}, 0},
}

// A ring of 64 bytes written 16 at a time: End and Start follow every write,
// and Range hands back exactly the bytes written over [from, to) for any range
// the ring still holds. It refuses one it does not, rather than return what is
// left of it.
func TestRingOffsetsAndRange(t *testing.T) {
	for _, tc := range ringCases {
		t.Run(tc.name, func(t *testing.T) {
			b := &buffer{max: tc.max}
			var written []byte
			for _, n := range tc.writes {
				// What a caller holds from before the write is the ring's own
				// bytes and must read the same after it: the tail chunk is
				// grown in place and the head is trimmed, neither of which
				// may reach what has been handed out.
				held, ok := b.Range(b.Start(), b.End())
				require.True(t, ok)
				heldWant := bytes.Clone(written[b.Start():])

				p := ringStream(len(written), n)
				b.Append(p)
				written = append(written, p...)

				require.Equal(t, string(heldWant), string(bytes.Join(held, nil)), "bytes handed out before a write of %d", n)
				requireRing(t, b, written)
			}
			require.GreaterOrEqual(t, len(b.Data()), tc.chunks, "the chunks the ring ends with")
		})
	}
}

// requireRing checks b against written, every byte ever appended to it.
func requireRing(t *testing.T, b *buffer, written []byte) {
	t.Helper()

	end := uint64(len(written))
	start := end
	if b.max > 0 {
		start = end - uint64(min(len(written), b.max))
	}
	require.Equal(t, end, b.End(), "End")
	require.Equal(t, start, b.Start(), "Start")

	// Every range at the bounds, at each chunk's edges and at a spread in
	// between, which is every range the 64-byte ring holds and a sample of the
	// larger one's.
	offsets := []uint64{start, end}
	if start < end {
		offsets = append(offsets, start+1, end-1)
	}
	at := start
	for _, c := range b.Data() {
		at += uint64(len(c))
		offsets = append(offsets, at, at-min(at, 1), min(at+1, end))
	}
	step := max(1, (end-start)/32)
	for o := start; o < end; o += step {
		offsets = append(offsets, o)
	}

	for _, from := range offsets {
		for _, to := range offsets {
			if from > to {
				chunks, ok := b.Range(from, to)
				require.False(t, ok, "Range(%d, %d) runs backwards", from, to)
				require.Nil(t, chunks)
				continue
			}
			chunks, ok := b.Range(from, to)
			require.True(t, ok, "Range(%d, %d) of [%d, %d)", from, to, start, end)
			if from == to {
				require.Nil(t, chunks, "an empty Range(%d, %d)", from, to)
				continue
			}
			require.Equal(t, string(written[from:to]), string(bytes.Join(chunks, nil)), "Range(%d, %d)", from, to)
			for _, c := range chunks {
				require.NotEmpty(t, c, "Range(%d, %d) hands out an empty chunk", from, to)
				// What a caller appends to a chunk it was handed must not
				// land on the ring's bytes after the range.
				_ = append(c, 0xff, 0xff, 0xff)
			}
		}
	}
	got, ok := b.Range(start, end)
	require.True(t, ok)
	require.Equal(t, string(written[start:]), string(bytes.Join(got, nil)), "the ring after appends to the chunks Range handed out")

	// Outside the ring: before its first byte, or past its last.
	if start > 0 {
		for _, r := range [][2]uint64{{start - 1, end}, {start - 1, start - 1}, {0, start}} {
			chunks, ok := b.Range(r[0], r[1])
			require.False(t, ok, "Range(%d, %d) starts before Start %d", r[0], r[1], start)
			require.Nil(t, chunks)
		}
	}
	for _, r := range [][2]uint64{{start, end + 1}, {end + 1, end + 1}, {end, end + 1}} {
		chunks, ok := b.Range(r[0], r[1])
		require.False(t, ok, "Range(%d, %d) ends after End %d", r[0], r[1], end)
		require.Nil(t, chunks)
	}
}

// Everything that leaves the ring is handed to onEvict with the stream offset
// of its first byte, in order and with nothing between one span and the next:
// together the spans are exactly the stream's bytes before Start, and each is
// delivered before the Append that pushed it out returns.
func TestRingEvictsWithOffsets(t *testing.T) {
	type span struct {
		offset uint64
		data   []byte
	}

	for _, tc := range ringCases {
		t.Run(tc.name, func(t *testing.T) {
			b := &buffer{max: tc.max}
			var evicted []span
			b.onEvict = func(offset uint64, p []byte) {
				evicted = append(evicted, span{offset, bytes.Clone(p)})
			}

			var written []byte
			for _, n := range tc.writes {
				p := ringStream(len(written), n)
				b.Append(p)
				written = append(written, p...)

				var next uint64
				var got []byte
				for _, e := range evicted {
					require.Equal(t, next, e.offset, "a span's offset follows the one before it")
					next += uint64(len(e.data))
					got = append(got, e.data...)
				}
				require.Equal(t, b.Start(), next, "the spans end where the ring begins, after a write of %d", n)
				require.Equal(t, string(written[:next]), string(got))
			}
		})
	}
}

// writeString writes s to the fan-out.
func writeString(w *MultiWriter, s string) { _, _ = w.Write([]byte(s)) }

// marginsAt reads the fan-out's tracker as a capture does, with writeMu held
// once what was reported since the last hold is applied: Snapshot, and
// whether the region is uncertain.
func marginsAt(w *MultiWriter) (snapshot string, uncertain bool) {
	withLog(w, func(*sizeLog, uint64) {
		snapshot, uncertain = string(w.modes.Snapshot()), w.modes.uncertain()
	})
	return snapshot, uncertain
}

// Through the fan-out: the tracker hears the 8-row event before the bytes it
// evicts after it, and decides each DECSTBM at that height.
func TestEvictedDECSTBMKeepsTheAcceptedRegion(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(8))
	writeString(w, "\x1b[2;5r\x1b[10;11r\x1b[10r")
	write(w, 16)

	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[2;5r", snap)
}

// A resize resets the region on a terminal, so one the tracker hears in
// order does too: priming never sets margins a resize already cleared. An
// event exactly at the ring's start is in effect there, so eviction that
// reaches its offset crosses it.
func TestTrackerResetsMarginsAtAnEvictedResize(t *testing.T) {
	for _, past := range []bool{false, true} {
		t.Run(fmt.Sprintf("past=%t", past), func(t *testing.T) {
			w := NewMultiWriter(16)
			resize(w, rows(24))
			writeString(w, "\x1b[2;10r") // 0 to 6
			resize(w, rows(30))
			write(w, 9) // the event at 7, and the ring full
			write(w, 7) // the ring starts at the event
			start := uint64(7)
			if past {
				write(w, 1)
				start++
			}

			withLog(w, func(_ *sizeLog, got uint64) { require.Equal(t, start, got) })
			snap, uncertain := marginsAt(w)
			require.False(t, uncertain)
			require.Empty(t, snap)
		})
	}
}

// Height 8, region 2;5; eviction crosses a tentative resize to 4; CSI 2;6r is
// evicted after it, 2;6 at 8 and 2;4 at 4, so the region is uncertain. The
// resize's outcome selects: failed, the region is the one decided without it,
// 2;6, which marks alone lost (they primed 2;5); committed, 2;4.
func TestAFailedResizeSelectsTheRegionDecidedWithoutIt(t *testing.T) {
	for _, tc := range []struct {
		applied bool
		want    string
	}{{false, "\x1b[2;6r"}, {true, "\x1b[2;4r"}} {
		t.Run(fmt.Sprintf("applied=%t", tc.applied), func(t *testing.T) {
			w := NewMultiWriter(16)
			resize(w, rows(8))
			writeString(w, "\x1b[2;5r")
			seq := w.ResizeBegin(rows(4))
			writeString(w, "\x1b[2;6r")
			write(w, 16)

			snap, uncertain := marginsAt(w)
			require.True(t, uncertain)
			require.Equal(t, "\x1b[2;4r", snap, "the newest candidate's")

			w.ResizeEnd(seq, tc.applied)
			snap, uncertain = marginsAt(w)
			require.False(t, uncertain)
			require.Equal(t, tc.want, snap)
		})
	}
}

// Candidates that agree aren't merged, and keep their heights, so a later
// DECSTBM is still decided under each. CSI 1;3r is 1;3 at 8 and at 4; CSI 2;6r
// after it isn't.
func TestACommonDECSTBMKeepsTheHeightCandidates(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(8))
	writeString(w, "\x1b[2;5r")
	seq := w.ResizeBegin(rows(4))
	writeString(w, "\x1b[1;3r")
	write(w, 16)

	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[1;3r", snap)

	writeString(w, "\x1b[2;6r")
	write(w, 16)
	_, uncertain = marginsAt(w)
	require.True(t, uncertain, "the heights were kept")

	w.ResizeEnd(seq, true)
	snap, uncertain = marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[2;4r", snap)
}

// Candidates that agree are no uncertainty. CSI 1;3r is 1;3 at 8 and at 4, so
// Snapshot carries it while the event is unresolved.
func TestSnapshotUsesTheCommonRegion(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(8))
	write(w, 1)
	w.ResizeBegin(rows(4))
	writeString(w, "\x1b[1;3r")
	write(w, 16)

	_, _, ok := unresolved(w)
	require.True(t, ok)
	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[1;3r", snap)
}

// Height 8; two tentative events crossed, to 4 then to 12, so the candidates
// are 8, 4 and 12; CSI 2;6r gives 2;6, 2;4 and 2;6. Each pair of outcomes, in
// either order, selects the region the terminal holds, and the tracker is
// uncertain exactly while the candidates left disagree.
func TestEveryHeightCandidateDecides(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second bool // e1's and e2's outcomes: committed or not
		afterFirst    bool // uncertain with only e1's outcome applied
		afterSecond   bool // uncertain with only e2's
		want          string
	}{
		{"deleted/deleted", false, false, false, true, "\x1b[2;6r"},
		{"committed/deleted", true, false, true, true, "\x1b[2;4r"},
		{"deleted/committed", false, true, false, false, "\x1b[2;6r"},
		{"committed/committed", true, true, true, false, "\x1b[2;6r"},
	} {
		for _, e1First := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/e1 first=%t", tc.name, e1First), func(t *testing.T) {
				w := NewMultiWriter(16)
				resize(w, rows(8))
				write(w, 1)
				e1 := w.ResizeBegin(rows(4))
				write(w, 1)
				e2 := w.ResizeBegin(rows(12))
				writeString(w, "\x1b[2;6r")
				write(w, 16)
				snap, uncertain := marginsAt(w)
				require.True(t, uncertain)
				require.Equal(t, "\x1b[2;6r", snap, "e2's, the newest")

				if e1First {
					w.ResizeEnd(e1, tc.first)
					_, uncertain = marginsAt(w)
					require.Equal(t, tc.afterFirst, uncertain)
					w.ResizeEnd(e2, tc.second)
				} else {
					w.ResizeEnd(e2, tc.second)
					_, uncertain = marginsAt(w)
					require.Equal(t, tc.afterSecond, uncertain)
					w.ResizeEnd(e1, tc.first)
				}
				snap, uncertain = marginsAt(w)
				require.False(t, uncertain)
				require.Equal(t, tc.want, snap)
			})
		}
	}
}

// A committed event heard in order after a crossed tentative one resets the
// region on a terminal whichever way the tentative one went, so the tracker
// keeps one candidate, the whole screen at its size, and the tentative
// event's later outcome changes nothing.
func TestAnInOrderResizeCollapsesTheCandidates(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(8))
	writeString(w, "\x1b[2;5r")
	seq := w.ResizeBegin(rows(4))
	writeString(w, "\x1b[2;6r")
	resize(w, rows(12))
	write(w, 1)
	write(w, 16)

	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Empty(t, snap)
	withLog(w, func(*sizeLog, uint64) { require.Len(t, w.modes.candidates, 1) })

	w.ResizeEnd(seq, true)
	snap, uncertain = marginsAt(w)
	require.False(t, uncertain)
	require.Empty(t, snap)

	// Decided at the 12 rows heard in order, not at the 4 that committed
	// before them.
	writeString(w, "\x1b[2;10r")
	write(w, 16)
	snap, _ = marginsAt(w)
	require.Equal(t, "\x1b[2;10r", snap)
}

// 16 crossed events still have a candidate each; a 17th overflows into the
// bounded fallback state, which is uncertain through every outcome, until a
// committed resize heard in order.
func TestTooManyCandidatesStayUncertain(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(8))
	var seqs []uint64
	for i := range maxUnresolvedResizes + 1 {
		write(w, 1)
		seqs = append(seqs, w.ResizeBegin(rows(10+i)))
	}
	write(w, 1) // the events at 1 to 17

	write(w, 14) // the ring starts at 16: 16 crossed
	_, uncertain := marginsAt(w)
	require.False(t, uncertain, "16 candidates, all with the whole screen")

	write(w, 1) // and the 17th
	_, uncertain = marginsAt(w)
	require.True(t, uncertain)

	for _, seq := range seqs {
		w.ResizeEnd(seq, true)
	}
	_, uncertain = marginsAt(w)
	require.True(t, uncertain, "outcomes change nothing while overflowed")

	resize(w, rows(20))
	write(w, 1)
	write(w, 16)
	_, uncertain = marginsAt(w)
	require.False(t, uncertain)
}

// A capture's clone describes the ring's first byte, so it has heard every
// event in effect there, even one no eviction has reached yet: the clone is
// fed the ring and decides its DECSTBMs at that size.
func TestTheTrackerHearsTheEventAtTheRingsStart(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	resize(w, rows(8))
	writeString(w, "abc")

	var clone *ModeTracker
	withLog(w, func(*sizeLog, uint64) { clone = w.modes.Clone() })
	_, _ = clone.Write([]byte("abc\x1b[2;5r\x1b[10;11r"))
	require.Equal(t, "\x1b[2;5r", string(clone.Snapshot()), "decided at the 8 rows in effect at the ring's start")
}

// armedGate passes writes through until armed, and then parks the next one
// until released, closing entered first.
type armedGate struct {
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *armedGate) Write(p []byte) (int, error) {
	if g.armed.Load() {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	return len(p), nil
}

// An outcome ResizeEnd records while a Write is still under way, after that
// Write's apply and its eviction crossing the event, is applied by the next
// hold of writeMu, and selects among the candidates the crossing kept.
func TestAnOutcomeRecordedMidWriteReachesTheTracker(t *testing.T) {
	for _, tc := range []struct {
		applied bool
		want    string
	}{{false, "\x1b[2;6r"}, {true, "\x1b[2;4r"}} {
		t.Run(fmt.Sprintf("applied=%t", tc.applied), func(t *testing.T) {
			gate := &armedGate{entered: make(chan struct{}), release: make(chan struct{})}
			w := NewMultiWriter(16)
			require.NoError(t, w.Append(gate))
			resize(w, rows(8))
			writeString(w, "\x1b[2;5r")
			seq := w.ResizeBegin(rows(4))
			writeString(w, "\x1b[2;6r")

			// The ring takes this Write and evicts past the event, and then
			// the Write parks in the gate, writeMu held.
			gate.armed.Store(true)
			wrote := make(chan struct{})
			go func() { defer close(wrote); write(w, 16) }()
			<-gate.entered
			w.ResizeEnd(seq, tc.applied)
			close(gate.release)
			<-wrote

			snap, uncertain := marginsAt(w)
			require.False(t, uncertain)
			require.Equal(t, tc.want, snap)
		})
	}
}

// Restore goes to guests' own terminals, which can be taller than the pty,
// so it resets the margins after any DECSTBM, whatever the pty's height
// decided: 0;24 is the whole of a 24-row pty and not of a 30-row guest; 1;30
// clamps to the whole pty at 24 rows and not at 30; a resize of the pty
// resets the pty's region, not a guest's; and Shutdown feeds the tracker the
// ring without its resizes, so it ignores 25;28 at the 24 rows it last heard,
// where the pty, at 30 by then, took it. Each case but the last is evicted
// whole, so the tracker decides it at the pty's 24 rows.
func TestShutdownResetsTheMarginsAfterAnyDECSTBM(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream func(w *MultiWriter)
	}{
		{"the whole pty, after a region", func(w *MultiWriter) {
			writeString(w, "\x1b[0;23rabc\x1b[0;24r")
			write(w, 16)
		}},
		{"clamped to the whole pty", func(w *MultiWriter) {
			writeString(w, "\x1b[1;30r")
			write(w, 16)
		}},
		{"a region, then a resize", func(w *MultiWriter) {
			writeString(w, "\x1b[2;10r")
			resize(w, termsize.Size{Cols: 100, Rows: 24})
			write(w, 16)
			write(w, 16)
		}},
		{"decided at a height the pty had left", func(w *MultiWriter) {
			write(w, 17) // evicts its first byte, and the 24-row event with it
			resize(w, termsize.Size{Cols: 80, Rows: 30})
			writeString(w, "\x1b[25;28r")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewMultiWriter(16)
			guest := resetBuffer{&bytes.Buffer{}}
			require.NoError(t, w.Append(guest))
			resize(w, at80x24)
			tc.stream(w)
			before := guest.Len()

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			require.NoError(t, w.Shutdown(ctx))
			require.Equal(t, "\x1b[r", guest.String()[before:])
		})
	}
}

// Events at one offset are each heard, in Seq order: here a committed resize
// to 4 rows and a tentative one to 8, with no output between them, then
// CSI 2;6r, which is 2;4 at 4 rows and 2;6 at 8. With the tentative one
// deleted, the region is the one decided at 4.
func TestEveryEventAtOneOffsetIsHeard(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, rows(24))
	write(w, 1)
	resize(w, rows(4))
	seq := w.ResizeBegin(rows(8))
	writeString(w, "\x1b[2;6r")
	write(w, 16)
	_, uncertain := marginsAt(w)
	require.True(t, uncertain)

	w.ResizeEnd(seq, false)
	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[2;4r", snap)
}

// A resize to the size the pty already has sends no SIGWINCH, and a terminal
// resets nothing, so the tracker doesn't either, as the replay applies no
// such event.
func TestASameSizeResizeResetsNothing(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, at80x24)
	writeString(w, "\x1b[2;10r")
	resize(w, at80x24)
	write(w, 1)
	write(w, 16)

	snap, uncertain := marginsAt(w)
	require.False(t, uncertain)
	require.Equal(t, "\x1b[2;10r", snap)
}

// Append's snapshot hears every resize reported before it, as a capture's
// does: with the ring empty, an event reported since the last Write is in
// effect at the ring's start, and it resets the margins on a terminal, so
// the snapshot must not carry the region the tracker held before it.
func TestAppendHearsAResizeReportedSinceTheLastWrite(t *testing.T) {
	w := NewMultiWriter(0) // the ring keeps nothing: the tracker hears it all
	resize(w, rows(8))
	writeString(w, "\x1b[2;5r")
	resize(w, rows(12))

	var joined bytes.Buffer
	require.NoError(t, w.Append(&joined))
	require.Empty(t, joined.String(), "the resize reset the margins before the snapshot")
}
