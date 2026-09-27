//go:build !windows

package internal

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// capturePacer has the session startHost builds hand its pacer to the returned
// channel. Called before startHost: the seam is read on the serving goroutine,
// and its reset, registered first, runs after startHost's cleanup has waited
// for that goroutine to stop.
func capturePacer(t *testing.T) <-chan *guestPacer {
	t.Helper()
	pacers := make(chan *guestPacer, 1)
	onGuestPacer = func(p *guestPacer) { pacers <- p }
	t.Cleanup(func() { onGuestPacer = nil })
	return pacers
}

// awaitPacer returns the pacer capturePacer caught.
func awaitPacer(t *testing.T, pacers <-chan *guestPacer) *guestPacer {
	t.Helper()
	select {
	case p := <-pacers:
		return p
	case <-time.After(harnessTimeout):
		t.Fatal("the session never built its pacer")
		return nil
	}
}

// setPacingStall sets the pacing guest's stall bound for one test. Called
// before startHost, for the same reason as capturePacer.
func setPacingStall(t *testing.T, d time.Duration) {
	t.Helper()
	orig := pacingStallTimeout
	pacingStallTimeout = d
	t.Cleanup(func() { pacingStallTimeout = orig })
}

// readWhileHeld reads r 32 KiB at a time, and only while p is holding a write,
// until it has counted heldFor bytes of 'x'; from then on it reads freely
// until marker arrives. It returns how many 'x' bytes it read, and an error if
// the stream ended first. The marker is matched in a rolling tail, so a stream
// of megabytes is never held whole.
//
// The free reading at the end is what lets the stream finish: once the
// command has written its last byte nothing is held any more. And if nothing
// is held for harnessTimeout it reads freely from then on, which is how a
// guest that was dropped, rather than paced, finds out: its stream ends.
func readWhileHeld(r io.Reader, p *guestPacer, heldFor int, marker string) (int, error) {
	buf := make([]byte, 32<<10)
	var tail []byte
	xs := 0
	free := false
	for {
		if !free && xs < heldFor {
			free = !awaitHold(p, harnessTimeout)
		}
		n, err := r.Read(buf)
		xs += bytes.Count(buf[:n], []byte("x"))
		tail = append(tail, buf[:n]...)
		if bytes.Contains(tail, []byte(marker)) {
			return xs, nil
		}
		if len(tail) > len(marker) {
			tail = tail[len(tail)-len(marker):]
		}
		if err != nil {
			return xs, fmt.Errorf("the stream ended before %q, %d bytes of x in: %w", marker, xs, err)
		}
	}
}

// awaitHold reports whether p held a write within d, polling rather than
// sleeping on a guess.
func awaitHold(p *guestPacer, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for p.waiting.Load() == 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Microsecond)
	}
	return true
}

// readAtLeast reads r until n bytes have arrived, failing if that takes longer
// than within. A read that gets nothing at all is bounded by the connection's
// own deadline instead.
func readAtLeast(t *testing.T, r io.Reader, n int, within time.Duration) {
	t.Helper()
	buf := make([]byte, 32<<10)
	deadline := time.Now().Add(within)
	for got := 0; got < n; {
		if !time.Now().Before(deadline) {
			t.Fatalf("received %d of %d bytes within %s", got, n, within)
		}
		k, err := r.Read(buf)
		got += k
		if err != nil && got < n {
			t.Fatalf("the stream ended after %d of %d bytes: %v", got, n, err)
		}
	}
}

// waitsFor is a command that prints READY, waits for the file named by its
// first argument, and then runs then.
func waitsFor(file, then string) []string {
	return []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; while [ ! -f "$1" ]; do sleep 0.01; done; ` + then, "sh", file}
}

// With no terminal attached, the one guest paces the command: a burst far past
// its buffer and SSH window arrives whole at the guest's own pace, rather than
// dropping it.
//
// The guest reads only while the gate is holding the pty copy on it. The pty
// path's own speed differs several-fold between race and non-race builds —
// about 6.5 MiB/s end to end under -race where this was written, against
// about 30 without — so no fixed read rate guarantees that the guest is what
// holds it back, and a guest that happens to keep up proves nothing. Reading
// only while held makes the guest the bottleneck on any runner. Without a
// pacer nothing is ever held, so the guest never reads, and it is dropped once
// the command is its cap plus one window ahead. The last 4 MiB are read
// freely, since once the command has finished nothing is held.
//
// Both kinds of guest attach through the pacer, and read-only is the other
// path through the handler.
func TestServerPacesAGuestWhenNoTerminalIsAttached(t *testing.T) {
	const payload = 16 << 20
	const heldFor = 12 << 20
	for _, readOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("read-only=%v", readOnly), func(t *testing.T) {
			pacers := capturePacer(t)
			goAhead := filepath.Join(t.TempDir(), "go")
			h := startHost(t, &Server{ReadOnly: readOnly, Command: waitsFor(goAhead,
				`head -c `+strconv.Itoa(payload)+` /dev/zero | tr '\000' x; printf 'DONE\n'; IFS= read -r line`)})
			pacer := awaitPacer(t, pacers)

			_, gOut := h.connectGuest(t, withDialDeadline(time.Minute))
			readUntil(t, gOut, "READY")
			require.NoError(t, os.WriteFile(goAhead, nil, 0600))

			xs, err := readWhileHeld(gOut, pacer, heldFor, "DONE")
			require.NoError(t, err, "the guest was dropped: nothing paced the command to it")
			require.Equal(t, payload, xs, "the guest missed output")
			require.Positive(t, pacer.holds.Load(), "no write was ever held, so pacing was never tested")
		})
	}
}

// A terminal that attaches while the gate is holding output for a stalled
// guest takes over pacing: the gate stands aside for the primary at once,
// rather than when the guest is dropped a stall timeout later. The stall bound
// is a minute so that only the primary can be what lets output through; the
// guest gets a minute's connection for the same reason, since its deadline
// ending the connection would take it out of the gate too.
func TestServerAttachedTerminalTakesOverFromAStalledGuest(t *testing.T) {
	setPacingStall(t, time.Minute)
	pacers := capturePacer(t)
	goAhead := filepath.Join(t.TempDir(), "go")
	h := startHost(t, &Server{Command: waitsFor(goAhead, `yes`)})
	pacer := awaitPacer(t, pacers)

	// The guest reads its replay and nothing more.
	_, gOut := h.connectGuest(t, withDialDeadline(time.Minute))
	readUntil(t, gOut, "READY")
	require.NoError(t, os.WriteFile(goAhead, nil, 0600))
	require.Eventually(t, func() bool { return pacer.waiting.Load() > 0 }, harnessTimeout, time.Millisecond,
		"the gate never held output for the stalled guest")

	// Far more than the replay, so only live output can make it up.
	_, hOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readAtLeast(t, hOut, 1<<20, harnessTimeout)
}

// Stopping the session is not held up by a guest the gate is waiting on, and
// both of the things that should end that hold are in place. The command
// ignores the hangup, so the teardown walks on to closing the pty with the
// gate still holding. What should end the hold, each enough alone, is the
// pacer's context, which is the command's and so ends with the session, and
// the release the command's exit makes before it waits for output to go quiet.
//
// The bound on stop cannot tell whether either is there. The guest door's
// interrupt releases the sessions after a bounded wait for the command, and
// the stalled guest's handler, returning, takes its sink out of the pacer,
// which opens the gate as well: with neither mechanism, stop still finishes
// inside the bound. So once stop has returned, the pacer is asked directly.
func TestServerStopIsNotHeldByAStalledPacer(t *testing.T) {
	setPacingStall(t, time.Minute)
	pacers := capturePacer(t)
	goAhead := filepath.Join(t.TempDir(), "go")
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`trap '' HUP; stty -echo -opost; printf 'READY\n'; while [ ! -f "$1" ]; do sleep 0.01; done; yes`, "sh", goAhead}})
	pacer := awaitPacer(t, pacers)

	_, gOut := h.connectGuest(t, withDialDeadline(time.Minute))
	readUntil(t, gOut, "READY")
	require.NoError(t, os.WriteFile(goAhead, nil, 0600))
	require.Eventually(t, func() bool { return pacer.waiting.Load() > 0 }, harnessTimeout, time.Millisecond,
		"the gate never held output for the stalled guest")

	t.Logf("stop took %s", h.stop(t))

	// Serve has returned, so the command's context has ended and its Run has
	// run every interrupt: both hold whenever the wiring is right.
	require.Error(t, pacer.ctx.Err(), "the pacer's context outlived the session: it is not the command's")
	pacer.mu.Lock()
	released := pacer.released
	pacer.mu.Unlock()
	require.True(t, released, "the command's exit never released pacing")
}
