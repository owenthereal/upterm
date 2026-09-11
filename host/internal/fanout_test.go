package internal

import (
	"context"
	"io"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// recordingWriter accumulates what it is given. The drain runs on its own
// goroutine, so every field is read under the mutex.
type recordingWriter struct {
	mu      sync.Mutex
	written []byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	return len(p), nil
}

func (r *recordingWriter) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.written)
}

// A guest that reaches the door after the fan-out has quiesced is refused, and
// the sink built for it must not outlive the attempt.
//
// The assertion is on the sink, not on the error: checking only ErrClosed would
// pass just as happily with the release deleted. A closed sink refuses writes,
// which is the observable consequence of its goroutine being released.
func TestAttachGuestOutputReleasesTheSinkWhenRefused(t *testing.T) {
	writers := uio.NewMultiWriter(5)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, writers.Shutdown(ctx))

	var out recordingWriter
	sink := uio.NewAsyncWriter(&out, uio.DefaultGuestBufferSize, nil)

	require.ErrorIs(t, attachGuestOutput(writers, sink), uio.ErrClosed)

	_, err := sink.Write([]byte("output"))
	require.ErrorIs(t, err, uio.ErrWriterClosed,
		"a refused attach must release the sink it was given")
}

// delayedWriter always takes longer to deliver than the copy takes to finish,
// so output is provably still pending when the producer stops. Without the
// flush, Run returns before this writer has been given anything at all.
type delayedWriter struct {
	delay time.Duration
	rec   *recordingWriter
}

func (d *delayedWriter) Write(p []byte) (int, error) {
	time.Sleep(d.delay)
	return d.rec.Write(p)
}

// The barrier: by the time Run returns, everything the fan-out accepted has
// reached the asynchronous guest.
//
// Ordering is the whole point. waitIdle returns after 100ms of quiet or its 1s
// deadline, in both cases with the copy still running, so a flush placed in the
// interrupt races the producer. Placing it where the copy returns is what makes
// it a barrier — and asserting *immediately after Run returns*, rather than
// eventually, is what makes this test notice if it moves back.
func TestCommandRunFlushesAcceptedOutputBeforeReturning(t *testing.T) {
	stdinr, stdinw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = stdinr.Close() }()
	defer func() { _ = stdinw.Close() }()
	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = stdoutr.Close() }()
	go func() { _, _ = io.Copy(io.Discard, stdoutr) }()

	const lastLine = "written just before exit"

	var guestOut recordingWriter
	// 200ms: longer than the copy takes to drain the pty, and well inside
	// guestFlushTimeout, so the flush both has work to do and can finish it.
	guest := uio.NewAsyncWriter(&delayedWriter{delay: 200 * time.Millisecond, rec: &guestOut},
		uio.DefaultGuestBufferSize, nil)
	defer func() { _ = guest.Close() }()

	writers := uio.NewMultiWriter(5)
	require.NoError(t, writers.Append(guest))

	cmd := &command{
		stdin:   stdinr,
		stdout:  stdoutw,
		writers: writers,
		ctx:     t.Context(),
		ptmx: &exitedPTY{
			pending:   [][]byte{[]byte("first chunk\r\n"), []byte(lastLine + "\r\n")},
			readDelay: 20 * time.Millisecond,
		},
	}

	require.NoError(t, cmd.Run())

	// No Eventually: the guarantee is that this has already happened.
	require.Contains(t, string(guestOut.bytes()), lastLine,
		"Run returned with output still queued for an attached guest")
}

// The shutdown barrier: waitIdle can return while the producer is still going,
// and anything produced after that must not be lost.
//
// waitIdle has two ways to give up: 100ms of quiet, or its own 1s outer bound
// regardless of quiet. The idle path cannot leave anything already accepted
// for this test to check, because the interrupt starts watching from the
// moment the mock pty's Wait returns -- immediately -- so a gap wide enough
// to read as quiet is also wide enough to swallow the first chunk before it
// ever arrives. The chunks here instead arrive well inside that 100ms window,
// so waitIdle never sees quiet at all; it is only cut off by the 1s deadline,
// with the pty still holding chunks the copy never got to. That is the other
// half of "waitIdle does not establish nothing more can be produced": even
// its own deadline leaves the copy still running when the interrupt cancels
// it. The comparison is against a synchronous writer attached to the same
// fan-out, which by definition has everything the fan-out accepted.
func TestCommandRunLosesNothingWhenTheProducerOutlivesWaitIdle(t *testing.T) {
	stdinr, stdinw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = stdinr.Close() }()
	defer func() { _ = stdinw.Close() }()
	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = stdoutr.Close() }()
	go func() { _, _ = io.Copy(io.Discard, stdoutr) }()

	var accepted recordingWriter // synchronous: the reference for what got in
	var guestOut recordingWriter
	guest := uio.NewAsyncWriter(&delayedWriter{delay: 200 * time.Millisecond, rec: &guestOut},
		uio.DefaultGuestBufferSize, nil)
	defer func() { _ = guest.Close() }()

	writers := uio.NewMultiWriter(5)
	require.NoError(t, writers.Append(&accepted))
	require.NoError(t, writers.Append(guest))

	var pending [][]byte
	for i := range 75 {
		pending = append(pending, []byte{byte('a' + i%26)})
	}
	cmd := &command{
		stdin:   stdinr,
		stdout:  stdoutw,
		writers: writers,
		ctx:     t.Context(),
		ptmx: &exitedPTY{
			pending: pending,
			// waitIdle's clock starts before the very first Read returns, so a
			// slow first read -- scheduler contention, not design -- competes
			// with outputIdleTimeout the same way a real mid-stream gap would.
			// 20ms leaves 80ms of slack for that: a widened margin was the
			// point of picking this value over a larger one, since a larger
			// delay leaves less room before the first read is mistaken for
			// quiet. 75 chunks at this cadence total 1.5s, longer than
			// outputDrainTimeout, so it is that 1s deadline -- not quiet --
			// that ends the wait while the copy is still producing.
			readDelay: 20 * time.Millisecond,
		},
	}

	require.NoError(t, cmd.Run())

	require.NotEmpty(t, accepted.bytes())
	require.Equal(t, string(accepted.bytes()), string(guestOut.bytes()),
		"output accepted by the fan-out was lost at teardown")
}
