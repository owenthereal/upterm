package internal

import (
	"io"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// blockingReader never returns, standing in for a pty whose reader does not
// report EOF when the command exits.
type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) {
	select {}
}

func TestDrainForceCommandOutput(t *testing.T) {
	for _, end := range []string{"EOF", "session"} {
		t.Run("returns immediately on "+end, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				drained, session := make(chan struct{}), make(chan struct{})
				if end == "EOF" {
					close(drained)
				} else {
					close(session)
				}
				returned := make(chan struct{})
				go func() {
					defer close(returned)
					drainForceCommandOutput(discardLogger(), newActivityReader(blockingReader{}), drained, session)
				}()
				requireCompleted(t, returned)
			})
		})
	}
	for _, sustained := range []bool{false, true} {
		name := "idle window"
		if sustained {
			name = "sustained activity reaches hard bound"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				output := newActivityReader(blockingReader{})
				session := make(chan struct{})
				defer close(session)
				returned := make(chan struct{})
				go func() {
					defer close(returned)
					drainForceCommandOutput(discardLogger(), output, make(chan struct{}), session)
				}()
				synctest.Wait()
				bound := 100 * time.Millisecond
				if sustained {
					bound = 2 * time.Second
				}
				// Publish before each tick; activity and timer delivery never compete.
				for elapsed := time.Duration(0); elapsed < bound-50*time.Millisecond; elapsed += 50 * time.Millisecond {
					if sustained {
						output.touch()
					}
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					requirePending(t, returned, "drain returned while output was still arriving")
				}
				if sustained {
					output.touch()
				}
				time.Sleep(50*time.Millisecond - time.Nanosecond)
				synctest.Wait()
				requirePending(t, returned, "drain returned before its deadline")
				time.Sleep(time.Nanosecond)
				requireCompleted(t, returned)
			})
		})
	}
	t.Run("keeps waiting while output is still arriving", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			output := newActivityReader(blockingReader{})
			session, returned := make(chan struct{}), make(chan struct{})
			defer close(session)
			go func() {
				defer close(returned)
				drainForceCommandOutput(discardLogger(), output, make(chan struct{}), session)
			}()
			synctest.Wait()
			for range 6 {
				output.touch()
				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
				requirePending(t, returned, "drain returned while output was still arriving")
			}
			time.Sleep(50*time.Millisecond - time.Nanosecond)
			synctest.Wait()
			requirePending(t, returned, "drain skipped the final quiet window")
			time.Sleep(time.Nanosecond)
			requireCompleted(t, returned)
		})
	})
}

func TestActivityReaderTracksReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		output := newActivityReader(newRepeatReader())
		time.Sleep(20 * time.Millisecond)
		require.Equal(t, 20*time.Millisecond, output.idleFor())
		buf := make([]byte, 4)
		n, err := output.Read(buf)
		require.NoError(t, err)
		require.Positive(t, n)
		require.Zero(t, output.idleFor(), "a successful read should reset the idle clock")
	})
}

func TestActivityWriterWaitIdleBoundaries(t *testing.T) {
	t.Run("EOF or session completion returns immediately", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			done, returned := make(chan struct{}), make(chan struct{})
			close(done)
			output := &activityWriter{Writer: io.Discard}
			go func() { defer close(returned); output.waitIdle(done, 100*time.Millisecond, time.Second) }()
			requireCompleted(t, returned)
		})
	})
	for _, kind := range []string{"quiet", "activity extends quiet", "sustained activity reaches hard bound"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				done, returned := make(chan struct{}), make(chan struct{})
				defer close(done)
				output := &activityWriter{Writer: io.Discard}
				go func() { defer close(returned); output.waitIdle(done, 100*time.Millisecond, time.Second) }()
				synctest.Wait()
				bound := 100 * time.Millisecond
				if kind == "activity extends quiet" {
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					_, err := output.Write([]byte("activity"))
					require.NoError(t, err)
					bound = 150 * time.Millisecond
				}
				elapsed := time.Duration(0)
				if kind == "activity extends quiet" {
					elapsed = 50 * time.Millisecond
				}
				if kind == "sustained activity reaches hard bound" {
					bound = time.Second
					for ; elapsed < bound-25*time.Millisecond; elapsed += 25 * time.Millisecond {
						_, err := output.Write([]byte("activity"))
						require.NoError(t, err)
						time.Sleep(25 * time.Millisecond)
						synctest.Wait()
						requirePending(t, returned, "waitIdle returned while output was still arriving")
					}
					_, err := output.Write([]byte("activity"))
					require.NoError(t, err)
				}
				time.Sleep(bound - elapsed - time.Nanosecond)
				synctest.Wait()
				requirePending(t, returned, "waitIdle returned before its deadline")
				time.Sleep(time.Nanosecond)
				requireCompleted(t, returned)
			})
		})
	}
}

// repeatReader always yields a byte, so Read reports progress.
type repeatReader struct{}

func newRepeatReader() repeatReader { return repeatReader{} }

func (repeatReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}
