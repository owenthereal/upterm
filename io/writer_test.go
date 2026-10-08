package io

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	case <-shutdown:
		t.Fatal("Shutdown returned before the sink drained")
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

var (
	at80x24  = termsize.Size{Cols: 80, Rows: 24}
	at45x30  = termsize.Size{Cols: 45, Rows: 30}
	at200x50 = termsize.Size{Cols: 200, Rows: 50}
)

// A joiner at least as big as the pty gets what Append gives it.
func TestMultiWriter_AppendSizedReplaysTheRingToAJoinerItFits(t *testing.T) {
	for _, j := range []termsize.Size{at80x24, {Cols: 200, Rows: 50}} {
		w := NewMultiWriter(DefaultReplayBytes)
		w.Resized(at80x24)
		_, _ = w.Write([]byte("\x1b[?2004hline one\r\nline two\r\n"))
		var got, want bytes.Buffer
		require.NoError(t, w.AppendSized(j, &got))
		require.NoError(t, w.Append(&want))
		require.Equal(t, want.String(), got.String(), "a %v joiner", j)
	}
}

// Smaller in either dimension: no ring, but the modes as they are now. The
// joiner is about to shrink the pty and be repainted at its own size, and a
// replay recorded wider or taller than its terminal is what that repaint lands
// on top of. The filter's pending lead-in is live output, so it still comes
// last.
func TestMultiWriter_AppendSizedSkipsTheRingForASmallerJoiner(t *testing.T) {
	for _, j := range []termsize.Size{at45x30, {Cols: 100, Rows: 20}} {
		w := NewMultiWriter(DefaultReplayBytes)
		w.Resized(at80x24)
		_, _ = w.Write([]byte("\x1b[?2004htext"))
		_, _ = w.Write([]byte("\x1b["))
		var got bytes.Buffer
		require.NoError(t, w.AppendSized(j, &got))
		require.Contains(t, got.String(), "\x1b[?2004h", "a %v joiner", j)
		require.NotContains(t, got.String(), "text", "a %v joiner", j)
		require.True(t, strings.HasSuffix(got.String(), "\x1b["), "a %v joiner gets the pending lead-in, got %q", j, got.String())
	}
}

// 80x24 is wider than a 45x30 joiner, so it gets only what was recorded since
// the resize to 45x30, behind the modes as of then.
func TestMultiWriter_AppendSizedReplaysOnlySinceTheLastResize(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("\x1b[?1049hbefore"))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("after"))
	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at45x30, &got))
	require.Equal(t, "\x1b[?1049hafter", got.String())
}

// Output recorded smaller than the joiner's terminal renders on it as it was
// drawn, so a joiner every recorded size fits gets the whole ring. This is the
// CI rejoin: the first guest's join grew the pty from 80x24, and a guest
// joining after it still sees what was written before.
func TestMultiWriter_AppendSizedReplaysEverythingThatFits(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("pre "))
	w.Resized(at200x50)
	_, _ = w.Write([]byte("post"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at200x50, &got))
	require.Equal(t, "pre post", got.String())
}

// The replay stops at the newest size the joiner doesn't fit, in either
// dimension, and the snapshot carries the modes set before it. 200x40 has
// the columns 200x50 was recorded at but not the rows.
func TestMultiWriter_AppendSizedStopsAtASizeThatDoesNotFit(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at200x50)
	_, _ = w.Write([]byte("\x1b[?1049hbig "))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("small"))

	for _, j := range []termsize.Size{{Cols: 100, Rows: 40}, {Cols: 200, Rows: 40}} {
		var got bytes.Buffer
		require.NoError(t, w.AppendSized(j, &got))
		require.Equal(t, "\x1b[?1049hsmall", got.String(), "a %v joiner", j)
	}

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at200x50, &got))
	require.Equal(t, "\x1b[?1049hbig small", got.String(), "a 200x50 joiner")
}

// The replay reaches back over every size the joiner fits, not just the
// newest, and stops at the first one it doesn't.
func TestMultiWriter_AppendSizedWalksBackOverEveryFittingSize(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	for _, step := range []struct {
		size termsize.Size
		out  string
	}{
		{at80x24, "a"},
		{at200x50, "b"},
		{at45x30, "c"},
		{termsize.Size{Cols: 120, Rows: 40}, "d"},
	} {
		w.Resized(step.size)
		_, _ = w.Write([]byte(step.out))
	}

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(termsize.Size{Cols: 120, Rows: 40}, &got))
	require.Equal(t, "cd", got.String(), "a 120x40 joiner")

	got.Reset()
	require.NoError(t, w.AppendSized(at200x50, &got))
	require.Equal(t, "abcd", got.String(), "a 200x50 joiner")
}

// The fan-out remembers 64 sizes. Bytes recorded at a size it has forgotten
// may have been recorded at any size, so they fit no joiner, however big.
func TestMultiWriter_BoundariesBeyondTheCapDoNotFit(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	var out []byte
	for i := range 70 {
		w.Resized(termsize.Size{Cols: 80 + i%2, Rows: 24})
		b := byte('0' + i)
		out = append(out, b)
		_, _ = w.Write([]byte{b})
	}

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at200x50, &got))
	require.Equal(t, string(out[len(out)-64:]), got.String())
}

// The sizes are forgotten as the ring forgets what was recorded at them. The
// one the ring's first byte was recorded at stays, because it is that byte's
// size; every one older is gone.
func TestMultiWriter_BoundariesArePrunedAsTheRingEvicts(t *testing.T) {
	// Four bytes at each of 20 sizes, 80 in all. A ring of 18 starts at
	// offset 62, inside what was recorded from 60 on, the 16th size; one of
	// 16 starts at 64, exactly where the 17th begins, so the 16th covers none
	// of it.
	for _, tc := range []struct{ ring, oldest int }{{18, 15}, {16, 16}} {
		w := NewMultiWriter(tc.ring)
		for i := range 20 {
			w.Resized(termsize.Size{Cols: 80 + i%2, Rows: 24})
			_, _ = w.Write([]byte("abcd"))
		}

		var want []boundary
		for i := tc.oldest; i < 20; i++ {
			want = append(want, boundary{offset: uint64(4 * i), size: termsize.Size{Cols: 80 + i%2, Rows: 24}})
		}
		require.Equal(t, want, w.boundaries, "a ring of %d", tc.ring)
	}
}

// A size the pty took and left with nothing written at it covers no bytes, so
// it is no size a joiner can fail to fit. Two guests joining before the
// command writes anything leave one: the first guest's size is applied at the
// second guest's join, and the second guest's size replaces it before
// anything is written.
func TestMultiWriter_ASizeNothingWasRecordedAtIsNoBoundary(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("pre "))
	w.Resized(at200x50)
	require.NoError(t, w.AppendSized(at45x30, &bytes.Buffer{}))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("post"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(termsize.Size{Cols: 100, Rows: 40}, &got))
	require.Equal(t, "pre post", got.String())
}

// A resize reported just before a join counts for it, with nothing written
// since: the joiner is weighed against the size the pty is now, and nothing
// has been recorded at that size yet. A 60x30 joiner fits the 45x30 the
// ring's newest bytes were recorded at, but not the 80x24 the pty is now, so
// it gets none of the ring. A 100x25 joiner fits 80x24 but not 45x30, which is
// too tall for it, so it gets none of the ring either: nothing it fits was
// recorded after the bytes it doesn't.
func TestMultiWriter_AppendSizedSeesAResizeWithNothingWrittenSince(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("\x1b[?1049hbefore"))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("after"))
	w.Resized(at80x24)

	for _, j := range []termsize.Size{{Cols: 60, Rows: 30}, {Cols: 100, Rows: 25}} {
		var got bytes.Buffer
		require.NoError(t, w.AppendSized(j, &got))
		require.Equal(t, "\x1b[?1049h", got.String(), "a %v joiner", j)
	}
}

// A resize and a resize back, with nothing written between them, leave the
// ring recorded at one size throughout, and so does a resize to the size it
// already is.
func TestMultiWriter_ResizedToTheSameSizeIsNoBoundary(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("one\r\n"))
	w.Resized(at45x30)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("two\r\n"))
	w.Resized(at80x24)
	_, _ = w.Write([]byte("three\r\n"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at80x24, &got))
	require.Equal(t, "one\r\ntwo\r\nthree\r\n", got.String())
	// Every size recorded here is 80x24, so the replay can't tell a boundary
	// at an equal size from none. The list can, and each such boundary would
	// take a place under the cap.
	require.Equal(t, []boundary{{offset: 0, size: at80x24}}, w.boundaries)
}

// A report of a size that isn't one, with no columns or no rows, is ignored,
// and the size reported before it still applies: an ssh -tt guest whose stdin
// is not a terminal asks for a 0x0 window, and a resize to it reaches the
// fan-out like any other. Joiners are weighed against 45x30: one that big gets
// what was recorded since the resize to it, and one a column narrower only
// the modes.
func TestMultiWriter_ResizedIgnoresASizeThatIsNotOne(t *testing.T) {
	for _, invalid := range []termsize.Size{{}, {Cols: 0, Rows: 24}} {
		t.Run(invalid.String(), func(t *testing.T) {
			w := NewMultiWriter(DefaultReplayBytes)
			w.Resized(at80x24)
			_, _ = w.Write([]byte("\x1b[?1049hbefore"))
			w.Resized(at45x30)
			w.Resized(invalid)
			_, _ = w.Write([]byte("after"))

			var fits, narrower bytes.Buffer
			require.NoError(t, w.AppendSized(at45x30, &fits))
			require.NoError(t, w.AppendSized(termsize.Size{Cols: 44, Rows: 30}, &narrower))
			require.Equal(t, "\x1b[?1049hafter", fits.String(), "a 45x30 joiner")
			require.Equal(t, "\x1b[?1049h", narrower.String(), "a 44x30 joiner")
		})
	}
}

// A boundary the ring has already evicted leaves the ring recorded at one
// size throughout, so all of it is the replay.
func TestMultiWriter_ABoundaryEvictedFromTheRingReplaysItWhole(t *testing.T) {
	w := NewMultiWriter(16)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("01234567"))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at45x30, &got))
	require.Equal(t, "qrstuvwxyzABCDEF", got.String())
}

// A resize can land between any two bytes of output, including the two halves
// of an escape sequence. The joiner still has to see the sequence whole.
func TestMultiWriter_ABoundaryInsideASequenceReplaysItWhole(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("\x1b[?20"))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("04hafter"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(at45x30, &got))
	require.Contains(t, got.String(), "\x1b[?2004hafter")

	// The query filter holds a CSI back until it has seen its end, so the
	// boundary above falls before the sequence rather than inside the ring's
	// copy of it. A charset designation is passed into the ring as soon as its
	// "(" is seen, so here the boundary does split the ring's bytes, and the
	// sequence's head is in the snapshot rather than in the replay.
	w = NewMultiWriter(DefaultReplayBytes)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("\x1b("))
	w.Resized(at45x30)
	_, _ = w.Write([]byte("0after"))

	got.Reset()
	require.NoError(t, w.AppendSized(at45x30, &got))
	require.Equal(t, "\x1b(0after", got.String())
}

// A viewer has no terminal size, and a writer never resized has no size to
// compare one with: either way the joiner gets the whole ring, as Append gives
// it.
func TestMultiWriter_AppendSizedWithoutASizeIsAppend(t *testing.T) {
	never := NewMultiWriter(DefaultReplayBytes)
	_, _ = never.Write([]byte("\x1b[?2004hnever resized"))
	for _, j := range []termsize.Size{{}, at45x30, at80x24} {
		var got, want bytes.Buffer
		require.NoError(t, never.AppendSized(j, &got))
		require.NoError(t, never.Append(&want))
		require.Equal(t, want.String(), got.String(), "a %v joiner", j)
	}

	resized := NewMultiWriter(DefaultReplayBytes)
	resized.Resized(at80x24)
	_, _ = resized.Write([]byte("\x1b[?1049hbefore"))
	resized.Resized(at45x30)
	_, _ = resized.Write([]byte("after"))
	var got, want bytes.Buffer
	require.NoError(t, resized.AppendSized(termsize.Size{}, &got))
	require.NoError(t, resized.Append(&want))
	require.Equal(t, want.String(), got.String())
	require.Contains(t, got.String(), "before")
}

// The pty reports a resize with terminalWindows's lock held, whose updates
// promise never to block, while a Write parked in a stopped primary writer
// can hold writeMu indefinitely.
func TestMultiWriter_ResizedDoesNotWaitForAParkedWrite(t *testing.T) {
	stuck := newBlockingWriter()
	w := NewMultiWriter(DefaultReplayBytes)
	require.NoError(t, w.Append(stuck))

	wrote := make(chan struct{})
	go func() { defer close(wrote); _, _ = w.Write([]byte("output")) }()
	<-stuck.entered

	resized := make(chan struct{})
	go func() { defer close(resized); w.Resized(at80x24) }()
	select {
	case <-resized:
	case <-time.After(2 * time.Second):
		t.Error("Resized waited on a Write parked in a stopped writer")
	}

	close(stuck.release)
	<-wrote
	<-resized
}

// A sized join works out its snapshot from a copy of the tracker. The tracker
// itself has to go on describing the ring's first byte, for every joiner after
// this one and for the Append that a viewer still makes.
func TestMultiWriter_SizedJoinsDoNotSpendTheTracker(t *testing.T) {
	w := NewMultiWriter(16)
	w.Resized(at80x24)
	_, _ = w.Write([]byte("\x1b[?2004h"))
	// 16 more bytes push the bracketed paste out of the ring and into the
	// tracker. A kitty push is in what stays, because unlike a mode it is not
	// the same after being applied twice.
	_, _ = w.Write([]byte("abc\x1b[>1u\x1b[?1049h"))

	var before bytes.Buffer
	require.NoError(t, w.Append(&before))

	var first, second bytes.Buffer
	require.NoError(t, w.AppendSized(at45x30, &first))
	require.NoError(t, w.AppendSized(at45x30, &second))
	require.Equal(t, "\x1b[?2004h\x1b[>1u\x1b[?1049h", first.String())
	require.Equal(t, first.String(), second.String())

	var after bytes.Buffer
	require.NoError(t, w.Append(&after))
	require.Equal(t, before.String(), after.String())
}
