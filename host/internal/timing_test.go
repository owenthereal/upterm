package internal

import (
	"context"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// A missing default or normalization of an explicit positive override changes
// the consumer's deadline. Pin the complete configuration for every case.
func TestServerTimingDefaults(t *testing.T) {
	want := serverTiming{
		pacingStall: 5 * time.Second, primaryStall: 5 * time.Second,
		promoteFlush: time.Second, outputIdle: 100 * time.Millisecond,
		outputDrain: time.Second, hangup: time.Second, forceCommandStop: time.Second,
	}
	require.Equal(t, want, (serverTiming{}).orDefault())
	for _, tc := range []struct {
		name string
		set  func(*serverTiming, time.Duration)
	}{
		{"pacingStall", func(v *serverTiming, d time.Duration) { v.pacingStall = d }},
		{"primaryStall", func(v *serverTiming, d time.Duration) { v.primaryStall = d }},
		{"promoteFlush", func(v *serverTiming, d time.Duration) { v.promoteFlush = d }},
		{"outputIdle", func(v *serverTiming, d time.Duration) { v.outputIdle = d }},
		{"outputDrain", func(v *serverTiming, d time.Duration) { v.outputDrain = d }},
		{"hangup", func(v *serverTiming, d time.Duration) { v.hangup = d }},
		{"forceCommandStop", func(v *serverTiming, d time.Duration) { v.forceCommandStop = d }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			negative := want
			tc.set(&negative, -time.Nanosecond)
			require.Equal(t, want, negative.orDefault())
			positive := want
			tc.set(&positive, 37*time.Millisecond)
			require.Equal(t, positive, positive.orDefault())
		})
	}
}

// timingPTY keeps a read outstanding after exit, optionally continuing output
// so the command must use its hard drain bound rather than its quiet window.
type timingPTY struct {
	*exitedPTY
	closed chan struct{}
	once   sync.Once
	every  time.Duration
}

func (p *timingPTY) Read(b []byte) (int, error) {
	if p.every > 0 {
		select {
		case <-time.After(p.every):
			b[0] = 'x'
			return 1, nil
		case <-p.closed:
			return 0, io.EOF
		}
	}
	<-p.closed
	return 0, io.EOF
}
func (p *timingPTY) Close() error { p.once.Do(func() { close(p.closed) }); return nil }

func checkCommandTiming(t *testing.T, timing, want serverTiming) {
	for _, drain := range []bool{false, true} {
		name := "quiet"
		if drain {
			name = "drain"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := &timingPTY{exitedPTY: &exitedPTY{}, closed: make(chan struct{})}
				t.Cleanup(func() { _ = p.Close() })
				duration := want.outputIdle
				if drain {
					p.every = timing.outputIdle / 8
					duration = want.outputDrain
				}
				c := &command{timing: timing, ptmx: p, writers: uio.NewMultiWriter(1), logger: discardLogger(), ctx: context.Background()}
				done := make(chan error, 1)
				go func() { done <- c.Run() }()
				synctest.Wait()
				time.Sleep(duration - time.Nanosecond)
				synctest.Wait()
				require.Empty(t, done, "command must still be draining before its configured bound")
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				require.Len(t, done, 1, "command must finish at its configured bound")
				require.NoError(t, <-done)
			})
		})
	}
}

func checkPacerTiming(t *testing.T, stall, want time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var once sync.Once
		var sink *uio.AsyncWriter
		var p *guestPacer
		t.Cleanup(func() {
			if p != nil {
				p.release()
			}
			if sink != nil {
				_ = sink.Close()
			}
			once.Do(func() { close(gate) })
		})
		sink = uio.NewAsyncWriter(&gatedWriter{gate: gate, rec: &recordingWriter{}}, uio.DefaultGuestBufferSize, nil)
		p = newGuestPacer(context.Background(), io.Discard, stall)
		p.mu.Lock()
		p.guests = append(p.guests, sink)
		p.mu.Unlock()
		_, err := sink.Write(make([]byte, pacingLowWater))
		require.NoError(t, err)
		done := make(chan struct{})
		go func() { _, _ = p.Write([]byte("tail")); close(done) }()
		synctest.Wait()
		require.EqualValues(t, 1, p.waiting.Load())
		time.Sleep(want - time.Nanosecond)
		synctest.Wait()
		require.Empty(t, done)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("pacer did not drop the stalled sink at its configured deadline")
		}
		require.ErrorIs(t, sink.Err(), uio.ErrStalled)
	})
}

func checkSinkTiming(t *testing.T, stall time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		ch := newDisconnectingChannel()
		var sink *hostSink
		t.Cleanup(func() {
			ch.disconnect()
			if sink != nil {
				_ = sink.Close()
			}
		})
		sink = newHostSink(ch, ch.disconnect, "timing", discardLogger(), stall)
		require.True(t, sink.promote(context.Background()))
		done := make(chan error, 1)
		go func() { _, err := sink.Write([]byte("parked")); done <- err }()
		synctest.Wait()
		time.Sleep(stall + stall/4 - time.Nanosecond)
		synctest.Wait()
		require.Empty(t, done)
		// StallWriter checks strictly greater than the bound on its quarter tick.
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Len(t, done, 1, "watchdog must disconnect at its configured bound plus one tick")
		require.Error(t, <-done)
	})
}

func checkPromotionTiming(t *testing.T, flush, want time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		ch := newDisconnectingChannel()
		var sink *hostSink
		t.Cleanup(func() {
			ch.disconnect()
			if sink != nil {
				_ = sink.Close()
			}
		})
		sink = newHostSink(ch, ch.disconnect, "timing", discardLogger(), time.Hour)
		_, err := sink.Write([]byte("queued"))
		require.NoError(t, err)
		h := &hostClients{promoteFlushTimeout: flush, logger: discardLogger(), order: []*hostClient{{id: "behind", sink: sink}}}
		done := make(chan string, 1)
		go func() { done <- h.electOne() }()
		synctest.Wait()
		time.Sleep(want - time.Nanosecond)
		synctest.Wait()
		require.Empty(t, done)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Len(t, done, 1, "elector must skip a blocked candidate at its configured bound")
		require.Empty(t, <-done)
		_ = sink.Close()
		ch.disconnect()
		synctest.Wait()
	})
}

func checkCommandHangup(t *testing.T, timing serverTiming, want time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		p := newCloseThenExitPTY()
		t.Cleanup(func() { _ = p.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := &command{timing: timing, ptmx: p, writers: uio.NewMultiWriter(1), logger: discardLogger(), ctx: ctx, stopGrace: time.Hour}
		done := make(chan error, 1)
		go func() { done <- c.Run() }()
		synctest.Wait()
		time.Sleep(want - time.Nanosecond)
		synctest.Wait()
		require.Empty(t, done)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Len(t, done, 1, "command teardown must close its master at the configured hangup bound")
		require.ErrorIs(t, <-done, context.Canceled)
	})
}

func checkReleaseTiming(t *testing.T, drain, want time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		var once sync.Once
		t.Cleanup(func() { once.Do(func() { close(done) }) })
		released := make(chan struct{})
		go releaseSessions(done, drain+guestFlushTimeout, func() { close(released) })
		synctest.Wait()
		time.Sleep(want + time.Second - time.Nanosecond)
		synctest.Wait()
		select {
		case <-released:
			t.Fatal("session released before its drain plus flush bound")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-released:
		default:
			t.Fatal("session not released at its drain plus flush bound")
		}
	})
}
