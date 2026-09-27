package internal

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	uio "github.com/owenthereal/upterm/io"
)

// The close is the recovery and the line only describes it. A logger blocked
// on a stopped terminal must not keep a dropped guest's channel open, whatever
// it was dropped for.
func TestGuestDropClosesBeforeLogging(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"overflow", uio.ErrOverflow},
		{"stalled", uio.ErrStalled},
		{"other", errors.New("broken pipe")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocked := make(chan struct{})
			closed := make(chan struct{})
			// At Debug, so every case's line reaches the gate: a failure that
			// is neither an overflow nor a stall is logged at Debug, and a
			// handler at the default Info level would discard that line
			// without blocking, so the case could not see the order at all.
			logger := slog.New(slog.NewTextHandler(&gatedWriter{gate: blocked, rec: &recordingWriter{}},
				&slog.HandlerOptions{Level: slog.LevelDebug}))
			onDrop := guestDropHandler(func() error { close(closed); return nil },
				logger, "s", pacingStallTimeout)

			done := make(chan struct{})
			go func() {
				defer close(done)
				onDrop(tc.err)
			}()
			t.Cleanup(func() {
				close(blocked)
				<-done
			})

			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("the guest's session was not closed while the logger was blocked")
			}
		})
	}
}
