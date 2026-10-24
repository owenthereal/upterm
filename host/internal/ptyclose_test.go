package internal

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// heldClosePTY acknowledges entry and lets each test release Close, including
// on Fatal. Its process and output have already ended unless a test says otherwise.
type heldClosePTY struct {
	*signalPTY
	entered    chan struct{}
	release    chan struct{}
	returned   chan struct{}
	calls      atomic.Int32
	once       sync.Once
	returnOnce sync.Once
	readGate   <-chan struct{}
}

func newHeldClosePTY(t *testing.T) *heldClosePTY {
	p := &heldClosePTY{signalPTY: newSignalPTY(0), entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	t.Cleanup(func() { p.unblock(); _ = p.signalPTY.Kill(); synctest.Wait() })
	return p
}
func (p *heldClosePTY) unblock() { p.once.Do(func() { close(p.release) }) }
func (p *heldClosePTY) Close() error {
	if p.calls.Add(1) == 1 {
		close(p.entered)
	}
	<-p.release
	// Only the first call owns the acknowledgement, so double-start is an
	// assertion failure instead of a panic in the test double.
	p.returnOnce.Do(func() { close(p.returned) })
	return nil
}

func (p *heldClosePTY) Read(b []byte) (int, error) {
	if p.readGate != nil {
		<-p.readGate
	}
	return p.signalPTY.Read(b)
}

func TestPTYCloseStartsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newHeldClosePTY(t)
		c := newPTYCloser(p)
		c.start()
		c.start()
		synctest.Wait()
		requireCloseCompleted(t, p.entered)
		require.EqualValues(t, 1, p.calls.Load(), "one PTY owner must start Close exactly once")
		p.unblock()
		synctest.Wait()
		require.True(t, c.wait(time.Now().Add(time.Second)))
		requireCloseCompleted(t, c.done)
	})
}
func TestPTYCloseWaitsForCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newHeldClosePTY(t)
		c := newPTYCloser(p)
		c.start()
		synctest.Wait()
		done := make(chan struct{})
		var completed bool
		go func() { completed = c.wait(time.Now().Add(time.Second)); close(done) }()
		synctest.Wait()
		requirePending(t, done, "wait skipped an in-flight Close")
		p.unblock()
		synctest.Wait()
		requireCloseCompleted(t, done)
		require.True(t, completed)
		requireCloseCompleted(t, c.done)
	})
}
func TestPTYCloseWaitIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newHeldClosePTY(t)
		c := newPTYCloser(p)
		c.start()
		synctest.Wait()
		done := make(chan struct{})
		var completed bool
		go func() { completed = c.wait(time.Now().Add(time.Second)); close(done) }()
		synctest.Wait()
		time.Sleep(time.Second - time.Nanosecond)
		synctest.Wait()
		requirePending(t, done, "close wait returned before its deadline")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		requireCloseCompleted(t, done)
		require.False(t, completed)
		requirePending(t, c.done, "held Close reported completion")
		p.unblock()
		synctest.Wait()
		requireCloseCompleted(t, c.done)
	})
}
func TestTerminationEscalatesWhilePTYCloseIsBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newHeldClosePTY(t)
		c := newPTYCloser(p)
		done := make(chan struct{})
		go func() { terminateWith(p, c, p.exited, time.Second, time.Second, discardLogger(), "held"); close(done) }()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		requireCloseCompleted(t, p.entered)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		requireCloseCompleted(t, done)
		require.Equal(t, []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL}, p.signals)
		require.True(t, p.killed, "leader Kill must proceed while Close is held")
		requirePending(t, c.done, "Close was not held through escalation")
		p.unblock()
		synctest.Wait()
		requireCloseCompleted(t, c.done)
	})
}
func TestCommandRunJoinsPTYClose(t *testing.T) {
	for _, natural := range []bool{true, false} {
		name := "terminated"
		if natural {
			name = "natural"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newHeldClosePTY(t)
				releaseRead := func() {}
				if natural {
					readGate := make(chan struct{})
					p.readGate = readGate
					releaseRead = sync.OnceFunc(func() { close(readGate) })
					t.Cleanup(releaseRead)
					close(p.exited)
				}
				cmd := &command{ctx: context.Background(), ptmx: p, writers: uio.NewMultiWriter(uio.DefaultReplayBytes), logger: discardLogger(), stopGrace: 100 * time.Millisecond, timing: serverTiming{hangup: 100 * time.Millisecond}}
				done := make(chan struct{})
				go func() { _ = cmd.Run(); close(done) }()
				synctest.Wait()
				if natural {
					require.True(t, cmd.Result().Exited, "natural process result must be recorded before output EOF")
					releaseRead()
					synctest.Wait()
				}
				if !natural {
					time.Sleep(300 * time.Millisecond)
					synctest.Wait()
				}
				requireCloseCompleted(t, p.entered)
				requirePending(t, done, "Run returned without joining its PTY Close")
				p.unblock()
				synctest.Wait()
				requireCloseCompleted(t, done)
				requireCloseCompleted(t, p.returned)
				require.EqualValues(t, 1, p.calls.Load(), "natural cleanup and termination must share Close")
			})
		})
	}
}
func TestCommandRunBoundsPTYCloseJoin(t *testing.T) {
	for _, natural := range []bool{true, false} {
		name := "terminated"
		if natural {
			name = "natural"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newHeldClosePTY(t)
				releaseRead := func() {}
				if natural {
					readGate := make(chan struct{})
					p.readGate = readGate
					releaseRead = sync.OnceFunc(func() { close(readGate) })
					t.Cleanup(releaseRead)
					close(p.exited)
				}
				cmd := &command{ctx: context.Background(), ptmx: p, writers: uio.NewMultiWriter(uio.DefaultReplayBytes), logger: discardLogger(), stopGrace: 100 * time.Millisecond, timing: serverTiming{hangup: 100 * time.Millisecond}}
				done := make(chan struct{})
				go func() { _ = cmd.Run(); close(done) }()
				synctest.Wait()
				if natural {
					require.True(t, cmd.Result().Exited, "natural process result must be recorded before output EOF")
					releaseRead()
					synctest.Wait()
				}
				bound := time.Second
				if !natural {
					bound = 400 * time.Millisecond
				}
				time.Sleep(bound - time.Nanosecond)
				synctest.Wait()
				requirePending(t, done, "Run's Close join ended before its absolute bound")
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				requireCloseCompleted(t, done)
				requirePending(t, p.returned, "Run must return even when Close remains held")
				p.unblock()
				synctest.Wait()
				requireCloseCompleted(t, p.returned)
			})
		})
	}
}

func requireCloseCompleted(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	default:
		t.Fatal("owned PTY close or termination did not complete by its asserted bound")
	}
}
