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
			onDrop := guestDropHandler(func() error { close(closed); return nil },
				slog.New(newBlockingHandler(blocked)), "s", pacingStallTimeout)

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
