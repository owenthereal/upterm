//go:build !windows

package internal

import (
	"fmt"
	"testing"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/assert"
)

// repaintsOnWinch prints RING-MARK once, and then on every SIGWINCH the size
// its terminal has at that moment, rows first, as `stty size` prints it: a
// full-screen program repainting at the size it is told.
//
// The trap's body is single-quoted so that $(stty size) runs each time the
// trap does. Double-quoted, the shell would expand it once, as the trap is
// set, and every repaint would report the size the command started at.
var repaintsOnWinch = []string{"sh", "-c", `trap 'printf "REPAINT %s\n" "$(stty size)"' WINCH; printf RING-MARK; while :; do sleep 0.05; done`}

// A guest whose terminal is narrower or shorter than the pty is about to
// shrink it, and the command repaints at the guest's size once it has. The
// ring was recorded wider than the guest can show, so replaying it would wrap
// and split under that repaint: the guest gets the repaint and none of the
// ring.
func TestAGuestSmallerThanThePtyGetsNoRingButTheRepaint(t *testing.T) {
	h := startHost(t, &Server{Command: repaintsOnWinch})

	// The pty opened at 80x24, nobody having offered a size; a viewer has no
	// terminal to change that, and reading the mark proves the ring holds it.
	_, viewer, _ := h.connectHost(t, nil)
	readUntil(t, viewer, "RING-MARK")

	// Narrower than the pty, though taller. Read to the repaint at the
	// guest's own size rather than to the first one: a repaint the viewer's
	// own join asked for can still be on its way, at the old size.
	_, guest := h.connectGuest(t, withGuestPty(45, 30))
	got := readUntil(t, guest, "REPAINT 30 45")
	assert.NotContains(t, got, "RING-MARK", "a guest smaller than the pty must not be replayed the ring")
}

// A guest whose terminal fits the pty in both dimensions shows the ring as it
// was drawn, so it gets the ring, as every joiner did before.
func TestAGuestAtLeastAsBigAsThePtyGetsTheRing(t *testing.T) {
	for _, size := range []struct{ cols, rows int }{{80, 24}, {120, 40}} {
		t.Run(fmt.Sprintf("%dx%d", size.cols, size.rows), func(t *testing.T) {
			h := startHost(t, &Server{Command: repaintsOnWinch})

			_, viewer, _ := h.connectHost(t, nil)
			readUntil(t, viewer, "RING-MARK")

			_, guest := h.connectGuest(t, withGuestPty(size.cols, size.rows))
			readUntil(t, guest, "RING-MARK")
		})
	}
}

// A pinned pty never shrinks to a smaller guest, so the command never repaints
// at the guest's size, and withholding the ring would leave the guest nothing
// to see until the command next draws. It gets the ring, as every joiner did
// before.
func TestAGuestOfAPinnedSessionGetsTheRing(t *testing.T) {
	h := startHost(t, &Server{Command: repaintsOnWinch, PtySize: termsize.Size{Cols: 100, Rows: 30}, PinPtySize: true})

	_, viewer, _ := h.connectHost(t, nil)
	readUntil(t, viewer, "RING-MARK")

	_, guest := h.connectGuest(t, withGuestPty(45, 30))
	readUntil(t, guest, "RING-MARK")
}
