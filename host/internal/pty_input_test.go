package internal

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

type heldInputDeadline struct {
	mu        sync.Mutex
	deadline  time.Time
	calls     int
	published chan struct{}
	release   chan struct{}
	writeErr  error
	success   bool
	publish   sync.Once
}

func (f *heldInputDeadline) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.calls++
	first, deadline := f.calls == 1, f.deadline
	f.mu.Unlock()
	if first {
		<-f.published
		if f.success {
			return len(b), nil
		}
		if f.writeErr != nil {
			return 2, f.writeErr
		}
		return 2, os.ErrDeadlineExceeded
	}
	if !deadline.IsZero() {
		return 0, os.ErrDeadlineExceeded
	}
	return len(b), nil
}
func (f *heldInputDeadline) SetWriteDeadline(d time.Time) error {
	f.mu.Lock()
	f.deadline = d
	f.mu.Unlock()
	if !d.IsZero() {
		f.publish.Do(func() { close(f.published) })
		<-f.release
	}
	return nil
}

func TestPTYInputCancellationCannotPoisonTheNextWrite(t *testing.T) {
	for _, success := range []bool{false, true} {
		name := "partial"
		if success {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := &heldInputDeadline{published: make(chan struct{}), release: make(chan struct{}), success: success}
				release := sync.OnceFunc(func() { close(f.release) })
				defer func() { f.publish.Do(func() { close(f.published) }); release() }()
				input := newPTYInput(f)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				first := make(chan inputTestResult, 1)
				go func() { n, err := input.WriteContext(ctx, []byte("first")); first <- inputTestResult{n, err} }()
				synctest.Wait()
				cancel()
				synctest.Wait()
				select {
				case <-f.published:
				default:
					t.Fatal("cancellation did not set a write deadline")
				}
				select {
				case result := <-first:
					t.Fatalf("writer released ownership before cancellation callback joined: %+v", result)
				default:
				}
				next := make(chan inputTestResult, 1)
				go func() {
					n, err := input.WriteContext(context.Background(), []byte("next"))
					next <- inputTestResult{n, err}
				}()
				synctest.Wait()
				f.mu.Lock()
				calls := f.calls
				f.mu.Unlock()
				require.Equal(t, 1, calls, "successor entered while prior callback still owns the deadline")
				release()
				synctest.Wait()
				a := <-first
				if success {
					require.NoError(t, a.err)
					require.Equal(t, 5, a.n)
				} else {
					require.ErrorIs(t, a.err, context.Canceled)
					require.Equal(t, 2, a.n)
				}
				b := <-next
				require.NoError(t, b.err, "stale deadline poisoned successor")
				require.Equal(t, 4, b.n)
				f.mu.Lock()
				deadline := f.deadline
				f.mu.Unlock()
				require.True(t, deadline.IsZero(), "write owner must reset only its write deadline before releasing the permit")
			})
		})
	}
}

type inputTestResult struct {
	n   int
	err error
}
type countInputDeadline struct{ calls int }

func (f *countInputDeadline) Write(b []byte) (int, error)    { f.calls++; return len(b), nil }
func (*countInputDeadline) SetWriteDeadline(time.Time) error { return nil }
func TestPTYInputAlreadyCanceledCannotAcquireAvailablePermit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &countInputDeadline{}
		input := newPTYInput(f)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for range 100 {
			n, err := input.WriteContext(ctx, []byte("discard"))
			require.Zero(t, n)
			require.ErrorIs(t, err, context.Canceled)
		}
		require.Zero(t, f.calls)
	})
}

type readFromInputPTY struct {
	*exitedPTY
	contextCalls, plainCalls, readFromCalls int
	got                                     bytes.Buffer
}

func (f *readFromInputPTY) WriteContext(_ context.Context, b []byte) (int, error) {
	f.contextCalls++
	return f.got.Write(b)
}
func (f *readFromInputPTY) Write(b []byte) (int, error) { f.plainCalls++; return f.got.Write(b) }
func (f *readFromInputPTY) ReadFrom(r io.Reader) (int64, error) {
	f.readFromCalls++
	return io.Copy(&f.got, r)
}
func TestPTYInputAdapterCannotBypassContextWrite(t *testing.T) {
	f := &readFromInputPTY{exitedPTY: &exitedPTY{}}
	// Hide WriterTo as well, so io.Copy would select a promoted ReadFrom.
	n, err := io.Copy(ptyInputWriter(context.Background(), f), struct{ io.Reader }{bytes.NewBufferString("ordered input")})
	require.NoError(t, err)
	require.EqualValues(t, 13, n)
	require.Equal(t, "ordered input", f.got.String())
	require.Equal(t, 1, f.contextCalls)
	require.Zero(t, f.plainCalls)
	require.Zero(t, f.readFromCalls)
	plain := &exitedPTY{}
	n, err = io.Copy(ptyInputWriter(context.Background(), plain), bytes.NewBufferString("fallback"))
	require.NoError(t, err)
	require.EqualValues(t, 8, n)
}

func TestPTYInputCancellationPreservesUnrelatedWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &heldInputDeadline{published: make(chan struct{}), release: make(chan struct{}), writeErr: os.ErrClosed}
		defer f.publish.Do(func() { close(f.published) })
		close(f.release)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan inputTestResult, 1)
		go func() { n, err := newPTYInput(f).WriteContext(ctx, []byte("first")); done <- inputTestResult{n, err} }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		result := <-done
		require.ErrorIs(t, result.err, os.ErrClosed)
		require.Equal(t, 2, result.n)
	})
}

type inputActorSession struct {
	*fakeGuestSession
	input *bytes.Reader
}

func (s *inputActorSession) Read(b []byte) (int, error) { return s.input.Read(b) }

type inputActorContext struct {
	fakeGuestContext
	parent context.Context
}

func (c inputActorContext) Err() error                  { return c.parent.Err() }
func (c inputActorContext) Done() <-chan struct{}       { return c.parent.Done() }
func (c inputActorContext) Deadline() (time.Time, bool) { return c.parent.Deadline() }

type inputActorPTY struct {
	*exitedPTY
	started chan context.Context
	release chan struct{}
}

func (p *inputActorPTY) WriteContext(ctx context.Context, b []byte) (int, error) {
	p.started <- ctx
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-p.release:
		return 0, io.ErrClosedPipe
	}
}
func (p *inputActorPTY) Write(b []byte) (int, error) { return p.WriteContext(context.Background(), b) }

func TestHandlerInputUsesItsActorContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p := &inputActorPTY{exitedPTY: &exitedPTY{}, started: make(chan context.Context, 1), release: make(chan struct{})}
		defer close(p.release)
		departure, leave := context.WithCancel(context.Background())
		defer leave()
		winCh := make(chan gssh.Window)
		closeWindow := sync.OnceFunc(func() { close(winCh) })
		defer closeWindow()
		session := &inputActorSession{fakeGuestSession: &fakeGuestSession{ctx: inputActorContext{fakeGuestContext{sessionID: "input-owner"}, departure}, winCh: winCh, out: io.Discard}, input: bytes.NewReader([]byte("input"))}
		h := &sessionHandler{kind: kindGuest, ctx: ctx, ptmx: p, writers: uio.NewMultiWriter(uio.DefaultReplayBytes), eventEmmiter: emitter.New(1), terminals: newTerminalWindows(discardLogger()), keepAliveDuration: time.Hour, logger: discardLogger()}
		done := make(chan struct{})
		go func() { defer close(done); h.HandleSession(session) }()
		synctest.Wait()
		var inputCtx context.Context
		select {
		case inputCtx = <-p.started:
		default:
			t.Fatal("handler never reached PTY input")
		}
		require.NotNil(t, inputCtx.Done(), "handler bypassed its cancelable input adapter")
		closeWindow()
		synctest.Wait()
		require.NoError(t, inputCtx.Err(), "channel departure canceled input before it could drain")
		leave()
		synctest.Wait()
		require.NoError(t, inputCtx.Err(), "transport departure canceled input before it could drain")
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("handler input ignored actor cancellation")
		}
		require.ErrorIs(t, inputCtx.Err(), context.Canceled)
	})
}
