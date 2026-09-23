//go:build !windows

package internal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func shortenStallTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := primaryStallTimeout
	primaryStallTimeout = d
	t.Cleanup(func() { primaryStallTimeout = orig })
}

// queryOnDemand prints a marker, then on each input line prints a cursor
// position query followed by a marker.
var queryOnDemand = []string{"sh", "-c", `stty -echo -opost; printf 'READY\n'; while IFS= read -r line; do printf '\033[6nQ_%s\n' "$line"; done`}

func TestLiveQueriesReachOnlyThePrimary(t *testing.T) {
	h := startHost(t, &Server{Command: queryOnDemand})
	aIn, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")
	_, bOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, bOut, "READY")
	_, gOut := h.connectGuest(t)
	readUntil(t, gOut, "READY")

	_, err := io.WriteString(aIn, "one\n")
	require.NoError(t, err)
	require.Contains(t, readUntil(t, aOut, "Q_one"), "\x1b[6n", "the primary answers live queries")
	require.NotContains(t, readUntil(t, bOut, "Q_one"), "\x1b[6n", "a secondary host client is filtered")
	require.NotContains(t, readUntil(t, gOut, "Q_one"), "\x1b[6n", "a guest is filtered")
}

func TestPromotionAfterThePrimaryLeavesLosesNothingAndUnfilters(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; IFS= read -r line; seq 1 20000; printf '\033[6nEND\n'; IFS= read -r line`}})
	aIn, aOut, aSess := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")
	_, bOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, bOut, "READY")

	_, err := io.WriteString(aIn, "go\n")
	require.NoError(t, err)
	// Let the stream get going on B, then take A away mid-stream.
	bSeen := readUntil(t, bOut, "\n1000\n")
	require.NoError(t, aSess.Close())
	rest := readUntil(t, bOut, "END")
	all := bSeen + rest

	// Every line, in order, no gaps: promotion did not drop or interleave.
	next := 1
	for _, line := range strings.Split(all, "\n") {
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		require.Equal(t, next, n, "gap or reorder around line %d", next)
		next++
	}
	require.Equal(t, 20001, next)
	require.Contains(t, rest, "\x1b[6n", "B is the primary now; live queries reach it")
}

// D21: a pty viewer — `upterm host &`, displaying but not reading — is never
// primary, whatever attached first. The interactive client that arrives
// second is elected, and the viewer stays filtered.
func TestAnInteractiveClientIsElectedOverAnEarlierViewer(t *testing.T) {
	h := startHost(t, &Server{Command: queryOnDemand})
	_, vOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24, viewer: true})
	readUntil(t, vOut, "READY")
	iIn, iOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, iOut, "READY")

	_, err := io.WriteString(iIn, "q\n")
	require.NoError(t, err)
	require.Contains(t, readUntil(t, iOut, "Q_q"), "\x1b[6n", "the interactive client is the primary")
	require.NotContains(t, readUntil(t, vOut, "Q_q"), "\x1b[6n", "a viewer is never the primary, even when it attached first")
}

// A pipe viewer — a redirected host — is a filtered asynchronous sink for the
// whole of its attachment.
func TestAPipeViewerIsNeverPrimary(t *testing.T) {
	h := startHost(t, &Server{Command: queryOnDemand})
	vIn, vOut, _ := h.connectHost(t, nil)
	readUntil(t, vOut, "READY")
	_, err := io.WriteString(vIn, "q\n")
	require.NoError(t, err)
	require.NotContains(t, readUntil(t, vOut, "Q_q"), "\x1b[6n")
	require.Empty(t, h.srv.hostClients.primaryID())
}

func TestAReattachingPrimaryDoesNotAnswerAReplayedQuery(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'before\033[6nAFTER\n'; IFS= read -r line`}})
	// The query is in the ring before anybody attaches.
	time.Sleep(300 * time.Millisecond)
	_, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	got := readUntil(t, aOut, "AFTER")
	require.NotContains(t, got, "\x1b[6n", "a historical query has no repainting value and is never stored")
	require.Contains(t, got, "before")
}

// Design item 4, the assertion that matters: a primary that stops reading is
// disconnected within primaryStallTimeout, after which Append completes and
// guests keep flowing. Append blocking is the deadlock the connection close
// exists to avoid.
//
// The primary is gated rather than merely idle, because only a client whose
// mux has stopped can tell the recovery from its imitation: a host that closed
// the channel instead of the connection releases nothing that is parked in
// SSH, yet a client still running its mux answers the close and looks exactly
// the same.
func TestStalledPrimaryIsDisconnectedAndTheFanOutRecovers(t *testing.T) {
	shortenStallTimeout(t, 500*time.Millisecond)
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; IFS= read -r line; yes | head -c 6000000; printf 'STREAM_DONE\n'; IFS= read -r line`}})

	// A healthy guest, reading continuously from the start. Six megabytes
	// outlasts the harness's default connection deadline on a loaded runner,
	// and this one reports what it saw rather than merely that it stopped: a
	// read that ends in an error is the guest going away, which is the
	// failure this test is looking for and not a reason to stop looking.
	_, gOut := h.connectGuest(t, withDialDeadline(60*time.Second))
	guestDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 65536)
		var tail []byte
		for !strings.Contains(string(tail), "STREAM_DONE") {
			n, err := gOut.Read(buf)
			if err != nil {
				guestDone <- err
				return
			}
			tail = append(tail, buf[:n]...)
			if len(tail) > 4096 {
				tail = tail[len(tail)-4096:]
			}
		}
		guestDone <- nil
	}()

	// The primary: attaches, starts the stream, and then stops taking bytes
	// off its socket altogether.
	aIn, aOut, aSess, aGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, aOut, "READY")
	_, err := io.WriteString(aIn, "go\n")
	require.NoError(t, err)
	aGate.pauseReads()

	// Append completes: a new host client attaches to a fan-out whose writeMu
	// the stalled primary was holding, is elected, and reads to the end. This
	// is the recovery — nothing but closing the connection underneath the
	// parked write can produce it.
	_, bOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, bOut, "STREAM_DONE")

	select {
	case err := <-guestDone:
		require.NoError(t, err, "the guest's stream ended before the command's output did")
	case <-time.After(harnessTimeout):
		t.Fatal("the guest stopped flowing behind the stalled primary")
	}

	// And what the stalled client finds when it looks again: its connection
	// gone, not a command that exited.
	aGate.resumeReads()
	select {
	case <-aGate.transportClosed():
	case <-time.After(harnessTimeout):
		t.Fatal("the stalled primary's connection was never closed")
	}
	waited := make(chan error, 1)
	go func() { waited <- aSess.Wait() }()
	select {
	case err := <-waited:
		var exit *ssh.ExitError
		require.False(t, errors.As(err, &exit), "the stalled primary must be disconnected, not exited: %v", err)
		require.Error(t, err)
	case <-time.After(harnessTimeout):
		t.Fatal("the stalled primary was not disconnected")
	}
}

// AwaitInitialClient so the prompt is produced after this client is elected
// and therefore delivered through the primary path: without it the command's
// first output races the election and goes out through the async sink, leaving
// the watchdog never armed and this test asserting nothing.
func TestIdlePrimaryIsNeverDisconnected(t *testing.T) {
	shortenStallTimeout(t, 200*time.Millisecond)
	h := startHost(t, &Server{Command: readsALine("PROMPT", 0), AwaitInitialClient: true})
	aIn, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "PROMPT")
	time.Sleep(time.Second) // five timeouts of nothing outstanding
	_, err := io.WriteString(aIn, "still-here\n")
	require.NoError(t, err)
	readUntil(t, aOut, "got:still-here")
}

// Pacing means the producer's progress depends on the reader's, and showing it
// takes an observable that separates "the command is blocked on the primary"
// from "the buffers between us are simply large". A guest reading continuously
// alongside is that observable: a synchronous primary is *global* backpressure
// — MultiWriter.Write is parked inside the primary's write with writeMu held,
// so nothing reaches anyone — and the guest therefore cannot get further ahead
// of a slow primary than what was already in flight towards it. A primary that
// merely buffered would leave the fan-out running at the pty's speed, and the
// guest would hold the whole stream while the primary was still on its first
// megabyte.
//
// The arithmetic, and it is about buffer sizes rather than speeds, which is
// what makes it a proof. Behind a synchronous primary the only thing that can
// sit between the fan-out and the client is the SSH channel window — 2 MiB,
// x/crypto's channelWindowSize, credited back only as the client application
// reads — so the fan-out can never be more than that ahead of the primary, and
// neither can the guest. Behind an asynchronous one there is the sink's 1 MiB
// buffer as well, and the fan-out runs to 3 MiB ahead before the sink
// overflows. Measured: the guest peaks 2,098,228 bytes ahead, repeatably to
// within a kilobyte, which is channelWindowSize and a packet or two; with the
// primary made asynchronous it passes 2,650,000 inside 1.3 s. The threshold is
// 2.5 MiB, half a mebibyte clear of the first and comfortably under the
// second, and neither figure depends on how fast the machine is.
//
// The guest is what makes the window observable: it reads continuously over
// loopback, far faster than a pty produces, so its own backlog stays at zero
// and what it holds is what the fan-out was able to emit.
//
// And the same slow reader shows the other half: reading 4 KiB every 20 ms
// keeps chunks completing, so a primary that is slow but progressing is never
// disconnected and loses nothing.
func TestSlowPrimaryPacesTheCommandAndLosesNothing(t *testing.T) {
	shortenStallTimeout(t, 300*time.Millisecond)
	const payload = 6_000_000
	const pacedSlack = 2560 << 10 // 2.5 MiB
	mark := filepath.Join(t.TempDir(), "finished")
	h := startHost(t, &Server{
		Command: []string{"sh", "-c",
			`stty -echo -opost; printf 'READY\n'; IFS= read -r line; yes | head -c ` + strconv.Itoa(payload) + `; : > "$UPTERM_TEST_MARK"; printf 'END\n'; IFS= read -r line`},
		CommandEnv: []string{"UPTERM_TEST_MARK=" + mark},
	})

	// The guest: attached before the stream starts and reading it as fast as
	// loopback allows, so whatever it is holding is whatever the fan-out was
	// able to emit.
	_, gOut := h.connectGuest(t)
	var primaryRead, maxAhead atomic.Int64
	go func() {
		buf := make([]byte, 64<<10)
		var guestRead int64
		for {
			n, err := gOut.Read(buf)
			guestRead += int64(n)
			// Sampled here rather than on the reading loop below, so the peak
			// is caught at the guest's rate rather than once per 20 ms.
			if ahead := guestRead - primaryRead.Load(); ahead > maxAhead.Load() {
				maxAhead.Store(ahead)
			}
			if err != nil {
				return
			}
		}
	}()

	aIn, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, aOut, "READY")
	_, err := io.WriteString(aIn, "go\n")
	require.NoError(t, err)

	var got strings.Builder
	buf := make([]byte, 4096)
	read := func(until func() bool) {
		deadline := time.Now().Add(60 * time.Second)
		for !until() {
			require.True(t, time.Now().Before(deadline))
			n, err := aOut.Read(buf)
			got.Write(buf[:n])
			// Here as well as in the slow loop, so the guest's baseline is
			// live throughout: left at zero for the fast phase, the peak it
			// records would be the whole of that phase plus the window.
			primaryRead.Store(int64(got.Len()))
			require.NoError(t, err, "a slow primary must not be disconnected")
		}
	}

	// Read the first MiB at full speed, then read slowly for two seconds: 4
	// KiB every 20 ms, while the command — which would be done with all 6 MB
	// inside that window — is held back to what the buffers between us can
	// absorb. Stopping outright would be the stall case, a different test.
	read(func() bool { return got.Len() >= 1<<20 })
	for i := 0; i < 100; i++ {
		n, err := aOut.Read(buf)
		got.Write(buf[:n])
		require.NoError(t, err)
		primaryRead.Store(int64(got.Len()))
		require.Less(t, maxAhead.Load(), int64(pacedSlack),
			"the guest got further ahead of the crawling primary than the window between them: nothing paced the fan-out")
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("primary has taken %d bytes of %d; the guest was never more than %d ahead", got.Len(), payload, maxAhead.Load())
	_, err = os.Stat(mark)
	require.True(t, os.IsNotExist(err), "the command finished while its primary had taken ~1.4 MiB of 6 MB")

	read(func() bool { return strings.Contains(got.String(), "END") })
	_, err = os.Stat(mark)
	require.NoError(t, err)
	require.Equal(t, payload/2, strings.Count(got.String(), "y\n"), "every byte the command wrote reached the slow primary")
}

// The elector loses a client when its connection goes, not when its
// handler happens to return. A primary that stopped reading is disconnected
// by the watchdog, but its handler cannot return while its input actor is
// parked in ptmx.Write — the command has stopped reading its pty and the
// pty's input queue is full, and a kernel write there is released by the
// command reading; on macOS also by the command's exit, which fails the
// write, but on Linux by nothing short of the daemon's exit. The deferred
// removal is therefore behind that write, and while it waits the elector
// still holds a disconnected client as primary: no election runs, every later
// client stays secondary — filtered and unpaced — and the live queries a
// primary exists to answer reach nobody.
//
// The junk is what parks the input actor, and it is written before the reads
// are paused so the actor is provably inside that write when the watchdog
// fires. The stream is what the watchdog needs: a client that has stopped
// reading is only stalled while something is being written to it.
//
// -icanon matters. A command that has stopped reading its pty while the
// terminal is in raw mode — a full-screen program, which is the case this is
// about — backs the input queue up and the master's write parks once it is
// full: about a kilobyte on macOS, twenty on Linux, both well under the junk
// below. A canonical line discipline discards what overflows its line
// buffer instead, and on macOS a megabyte of junk is swallowed whole with the
// write returning success, so a canonical command would park nothing.
//
// Gate command startup on A's election, and output on the input flood being
// parked. Queries accompany each output chunk: requiring all six megabytes to
// drain before the first query can confuse slow throughput with failed election.
func TestAStalledPrimaryWithParkedInputIsReplaced(t *testing.T) {
	shortenStallTimeout(t, 300*time.Millisecond)
	startOutput := filepath.Join(t.TempDir(), "start-output")
	h := startHost(t, &Server{AwaitInitialClient: true, Command: []string{"sh", "-c",
		`stty -echo -opost -icanon; printf 'READY\n'; while [ ! -f "$1" ]; do sleep 0.01; done; while :; do yes | head -c 65536; printf '\033[6nQ\n'; done`, "sh", startOutput}})
	joined := h.srv.EventEmitter.On(upterm.EventClientJoined)
	defer h.srv.EventEmitter.Off(upterm.EventClientJoined, joined)

	aIn, aOut, _, aGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, aOut, "READY")
	aID := nextClientID(t, joined)
	require.Equal(t, aGate.transportID, h.srv.hostClients.primaryID())

	// Exceed the SSH window as well as the raw pty input queue, proving the
	// flood is parked while the command neither reads input nor emits output.
	floodErr := make(chan error, 1)
	go func() {
		_, err := aIn.Write(bytes.Repeat([]byte("x"), 4<<20))
		floodErr <- err
	}()
	select {
	case <-floodErr:
		t.Fatal("the flood write completed: the pty is not parking the input actor")
	case <-time.After(500 * time.Millisecond):
	}
	aGate.pauseReads()
	require.NoError(t, os.WriteFile(startOutput, nil, 0600))

	// The watchdog must remove A while its input actor is still parked. Do
	// not close A ourselves: that would exercise the hang-up test instead.
	require.Eventually(t, func() bool {
		return h.srv.hostClients.primaryID() == ""
	}, harnessTimeout, 10*time.Millisecond, "the stalled primary was never removed from the elector")

	_, bOut, _, bGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	bID := nextClientID(t, joined)
	require.NotEqual(t, aID, bID)
	awaitLiveQuery(t, bOut)
	require.Equal(t, bGate.transportID, h.srv.hostClients.primaryID(), "the elector still holds the disconnected client")

	aGate.resumeReads()
	select {
	case <-aGate.transportClosed():
	case <-time.After(harnessTimeout):
		t.Fatal("the stalled primary's transport was never closed")
	}
	select {
	case <-floodErr:
	case <-time.After(harnessTimeout):
		t.Fatal("the flood write was never released after transport closure")
	}
}

// TestTeardownIsNotHeldByParkedInputAndQueuedOutput pins the macOS teardown
// deadlock: a command whose hangup handler writes, with a client's input
// parked on a full pty input queue. XNU holds the session leader in exit
// until the tty's output queue drains, and the master's close cannot land
// behind the parked write, so without the flush terminate gives up after
// hangupGrace + 3 graces and leaves the group stuck in exit.
//
// TestAStalledPrimaryWithParkedInputIsReplaced hits the same deadlock about
// once in a hundred runs, when its stream races bytes into the queue after
// the last master read. Here the trap makes it certain, and it writes twice
// for that. The read the output copy abandoned when the session began ending
// is still parked on the master and takes the first write after the hangup;
// only a write after that one stays queued. The trap's own "HUP" is that
// first write, so BYE-BYE-BYE, 0.2 s later, always finds no reader. Without
// it the test would lean on bash's report of the sleep the hangup killed
// ("Hangup: 1") to absorb that read, and bash prints none when the hangup
// lands between two sleeps -- which would let this pass without the fix.
func TestTeardownIsNotHeldByParkedInputAndQueuedOutput(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the leader-exit drain wait is XNU's")
	}
	h := startHost(t, &Server{AwaitInitialClient: true, Command: []string{"sh", "-c",
		`stty raw -echo; trap 'printf "HUP\n"; sleep 0.2; printf "BYE-BYE-BYE"; exit 0' HUP; printf 'READY %s\n' $$; while :; do sleep 0.1; done`}})
	aIn, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	pid := readPID(t, aOut)

	// More than the SSH window and the raw pty input queue: parked, since the
	// command never reads its stdin.
	floodErr := make(chan error, 1)
	go func() {
		_, err := aIn.Write(bytes.Repeat([]byte("x"), 4<<20))
		floodErr <- err
	}()
	select {
	case <-floodErr:
		t.Fatal("the flood write completed: nothing is parked, so this would pass for the wrong reason")
	case <-time.After(500 * time.Millisecond):
	}
	// Keep A's output drained, so nothing but the parked write is in play.
	go func() { _, _ = io.Copy(io.Discard, aOut) }()

	elapsed := h.stop(t)
	t.Logf("teardown took %s", elapsed)
	require.Less(t, elapsed, hangupGrace+DefaultStopGrace,
		"teardown walked past the close step: the close did not release the leader")
	require.Eventually(t, func() bool { return syscall.Kill(-pid, 0) == syscall.ESRCH },
		2*time.Second, 20*time.Millisecond, "the command's process group is still there: terminate gave up on it")
}

// readPID reads r up to the command's "READY <pid>" line and returns the pid.
func readPID(t *testing.T, r io.Reader) int {
	t.Helper()
	seen := readUntil(t, r, "READY ")
	line := seen[strings.Index(seen, "READY ")+len("READY "):]
	if !strings.Contains(line, "\n") {
		line += readUntil(t, r, "\n")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line[:strings.Index(line, "\n")]))
	require.NoError(t, err, "no pid after READY in %q", seen)
	return pid
}

// This is TestAStalledPrimaryWithParkedInputIsReplaced's twin, but
// nothing here ever fires the watchdog or the overflow path — the only two
// callers of disconnect. The command is quiet: `exec sleep 60` replaces the
// shell outright, never reading its pty again and never writing anything a
// live query could ride on to arm the stall timer. The only signal that
// this primary is gone is the connection's end, and it is the client, not
// the daemon, that ends it — closing its own socket while its input write
// is still parked in the kernel.
func TestAPrimaryThatHangsUpWithParkedInputIsReplaced(t *testing.T) {
	// Gated, so READY is live output that follows A's election rather than a
	// replay that can reach A before its handler has registered it: the
	// assertion below reads the elector as soon as READY arrives.
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty raw -echo; printf 'READY\n'; exec sleep 60`}})
	joined := h.srv.EventEmitter.On(upterm.EventClientJoined)
	defer h.srv.EventEmitter.Off(upterm.EventClientJoined, joined)

	aIn, aOut, _, aGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")
	aID := nextClientID(t, joined)
	require.Equal(t, aGate.transportID, h.srv.hostClients.primaryID())

	// More than the 2 MiB SSH channel window, so this can only complete if
	// the daemon's input actor is draining it into the pty.
	floodErr := make(chan error, 1)
	go func() {
		_, err := aIn.Write(bytes.Repeat([]byte("x"), 4<<20))
		floodErr <- err
	}()
	select {
	case <-floodErr:
		t.Fatal("the flood write completed: the pty is not parking the input actor, so this test would pass for the wrong reason")
	case <-time.After(500 * time.Millisecond):
	}

	// The client hangs up — the raw socket, not a channel or the session.
	require.NoError(t, aGate.Close())

	select {
	case <-floodErr:
	case <-time.After(harnessTimeout):
		t.Fatal("the flood write was never released")
	}

	_, bOut, _, bGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	bID := nextClientID(t, joined)
	require.NotEqual(t, aID, bID)
	readUntil(t, bOut, "READY") // the replay; proves B is served

	require.Eventually(t, func() bool {
		return h.srv.hostClients.primaryID() == bGate.transportID
	}, harnessTimeout, 10*time.Millisecond, "the elector still holds the client that hung up")
}

// This is TestAPrimaryThatHangsUpWithParkedInputIsReplaced's twin for the
// size calculation rather than the elector: the only signal that A is gone
// is the connection's end, and the pty actor's interrupt that would
// otherwise drop A out of resizeWindow's minimum does not run until the
// group ends -- which this scenario deliberately never lets happen on its
// own, because A's command never reads its stdin. Without the fix A keeps
// constraining the size to 24x80 for as long as the session lives.
func TestAHungUpPrimaryStopsConstrainingTheSize(t *testing.T) {
	// stty size on demand would need a read, which this command must never
	// do; SIGWINCH is the only nudge left, and Redraw sends one on every
	// attach. The loop re-enters sleep every 0.1s rather than blocking in one
	// long sleep: a shell only runs a trap between foreground commands, not
	// by interrupting one already running, so a single long sleep could defer
	// the trap for its whole duration instead of running it promptly.
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty raw -echo; trap 'stty size' WINCH; printf 'READY\n'; while :; do sleep 0.1; done`}})

	aIn, aOut, _, aGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")

	// More than the 2 MiB SSH channel window, so this can only complete once
	// A hangs up; parked because the command above never reads its stdin.
	floodErr := make(chan error, 1)
	go func() {
		_, err := aIn.Write(bytes.Repeat([]byte("x"), 4<<20))
		floodErr <- err
	}()
	select {
	case <-floodErr:
		t.Fatal("the flood write completed: the pty is not parking the input actor, so this test would pass for the wrong reason")
	case <-time.After(500 * time.Millisecond):
	}

	// The client hangs up -- the raw socket, not a channel or the session.
	require.NoError(t, aGate.Close())

	select {
	case <-floodErr:
	case <-time.After(harnessTimeout):
		t.Fatal("the flood write was never released")
	}

	// A is out of the elector once its connection actor has run; the fix
	// has the same actor take A out of the size tracking, on the next line,
	// so waiting for this is as good as waiting for A to be out of
	// resizeWindow's minimum.
	require.Eventually(t, func() bool {
		return h.srv.hostClients.primaryID() == ""
	}, harnessTimeout, 10*time.Millisecond, "A was never removed from the elector")

	_, bOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 100, rows: 30})
	readUntil(t, bOut, "30 100")
}

// The door accepted these bytes before the client hung up, so the session is
// owed them even though the client that sent them has gone. The danger is a
// handler that, on the connection's end, cancels its own input reader before
// the parked write has drained: it would report the context's error instead
// of delivering the bytes still pending in the channel.
func TestInputAcceptedBeforeAHangUpIsDeliveredWhenTheCommandReads(t *testing.T) {
	// Gated, so the command's second of not reading starts when A attaches,
	// not when the daemon did: a slow attach must not let head start reading
	// before the write is parked, which would pass this test for nothing.
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty raw -echo; printf 'READY\n'; sleep 1; head -c 262144 | wc -c`}})

	aIn, aOut, _, aGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")
	// Fits the channel window, so this returns whether or not the daemon is
	// draining it: about a kilobyte on macOS and twenty on Linux parks in
	// the pty's queue, one io.Copy chunk parks in the write, and the rest
	// sits in the channel.
	_, err := aIn.Write(bytes.Repeat([]byte("x"), 256<<10))
	require.NoError(t, err)
	// Long enough for the daemon to have taken the bytes off the channel and
	// parked in the pty; microseconds of work, so the margin is large.
	time.Sleep(200 * time.Millisecond)
	// The client hangs up with all of it still parked in the daemon.
	require.NoError(t, aGate.Close())

	_, bOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	// wc prints the count once every one of the 256 KiB reached the pty
	// after the hang-up; matching the digits rather than the whole line
	// dodges the padding difference between BSD and GNU wc.
	readUntil(t, bOut, "262144")
}

// nextClientID is the lifecycle event ID of the next client to join. It is
// distinct from the SSH transport ID used by host election and sizing.
func nextClientID(t *testing.T, joined <-chan emitter.Event) string {
	t.Helper()
	select {
	case evt := <-joined:
		return evt.Args[0].(*api.Client).Id
	case <-time.After(harnessTimeout):
		t.Fatal("no client-joined event")
		return ""
	}
}

// awaitLiveQuery reads r until a cursor-position query arrives, which only an
// unfiltered primary is sent — and never from the ring, which does not store
// queries. Its own reader rather than readUntil's, because what it reads
// through is megabytes of padding and the failure message should not be.
func awaitLiveQuery(t *testing.T, r io.Reader) {
	t.Helper()
	query := []byte("\x1b[6n")
	buf := make([]byte, 4096)
	var tail []byte
	deadline := time.Now().Add(harnessTimeout)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		tail = append(tail, buf[:n]...)
		if bytes.Contains(tail, query) {
			return
		}
		// Keep enough to span a query split across two reads.
		if len(tail) > len(query) {
			tail = tail[len(tail)-len(query):]
		}
		if err != nil {
			t.Fatalf("the stream ended before any live query arrived: %v", err)
		}
	}
	t.Fatal("no live query reached this client within the timeout")
}

// The secondary is gated for the same reason the stalled primary is: what has
// to be shown is the connection closing, and a client whose mux is still
// running would report a closed channel identically.
func TestSecondaryHostClientOverflowClosesTheConnection(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c",
		`stty -echo -opost; printf 'READY\n'; IFS= read -r line; yes | head -c 6000000; printf 'STREAM_DONE\n'; IFS= read -r line`}})
	aIn, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, aOut, "READY")
	_, bOut, bSess, bGate := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24},
		withDialDeadline(60*time.Second))
	readUntil(t, bOut, "READY")

	_, err := io.WriteString(aIn, "go\n")
	require.NoError(t, err)
	// B stops taking bytes off its socket altogether.
	bGate.pauseReads()

	// The primary reads to the end regardless: a secondary that overflows is
	// dropped, never allowed to pace the fan-out. Six megabytes of it, so on
	// the same budget as this client's connection rather than the harness's
	// default, which the payload alone spends most of on a macOS runner.
	readUntilWithin(t, aOut, "STREAM_DONE", 60*time.Second)

	bGate.resumeReads()
	select {
	case <-bGate.transportClosed():
	case <-time.After(harnessTimeout):
		t.Fatal("the overflowed secondary's connection was never closed")
	}
	waited := make(chan error, 1)
	go func() { waited <- bSess.Wait() }()
	select {
	case err := <-waited:
		require.Error(t, err)
	case <-time.After(harnessTimeout):
		t.Fatal("the overflowed secondary was not disconnected")
	}
}

// Design item 3: pinned size, alternate screen and mouse mode set long ago,
// more output than the ring holds, then an attach: the modes come from the
// snapshot, the redraw comes from SIGWINCH, and the geometry does not move.
func TestReattachAfterRolloverRestoresModesAndNudges(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "proceed")
	h := startHost(t, &Server{
		Command:    []string{"sh", "-c", `trap 'printf WINCH_SEEN' WINCH; stty -echo -opost; printf '\033[?1049h\033[?1000h'; yes | head -c 300000; printf 'ROLLED'; while [ ! -e "$UPTERM_TEST_FLAG" ]; do sleep 0.05; done; stty size; sleep 1`},
		CommandEnv: []string{"UPTERM_TEST_FLAG=" + flag},
		PtySize:    termsize.Size{Cols: 100, Rows: 30}, PinPtySize: true,
	})
	time.Sleep(500 * time.Millisecond) // let the ring roll over

	_, aOut, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	got := readUntil(t, aOut, "WINCH_SEEN")
	head := got[:strings.Index(got, "ROLLED")]
	require.Contains(t, head, "\x1b[?1049h", "alternate screen restored from the snapshot")
	require.Contains(t, head, "\x1b[?1000h", "mouse mode restored from the snapshot")

	require.NoError(t, os.WriteFile(flag, nil, 0600))
	readUntil(t, aOut, "30 100") // the nudge did not resize a pinned pty
}
