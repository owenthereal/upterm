package ftests

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

const (
	// burstChunkBytes is how much output the host produces per go-ahead. It is
	// the bound on how far the guest that keeps reading may fall behind, because
	// the test never asks for the next chunk until that guest has seen the last
	// one, so it has to stay well under the 1 MiB host-side cap.
	burstChunkBytes = 256 << 10

	// burstChunks caps the burst at burstChunks * burstChunkBytes = 16 MiB. That
	// has to exceed what the path already buffers before the host's write to a
	// stalled guest blocks: up to 2 MiB of SSH window on each leg between host
	// and guest, plus TCP socket buffers, plus the 1 MiB host-side cap — roughly
	// 5.5 MiB for one node and more for two, and platform-dependent because
	// Windows autotunes its socket buffers. The loop stops as soon as the drop
	// lands, so the margin costs nothing when it lands early; if it never lands,
	// this is the knob to raise.
	burstChunks = 64

	// burstLineWidth matches the guests' 80-column pty, so the burst is not
	// re-wrapped on the way through and a marker stays on one line.
	burstLineWidth = 80

	burstChunkMarker = "BURST-CHUNK-"

	// burstChunkTimeout bounds the wait for one 256 KiB chunk to cross the whole
	// path. Measured on the happy path a chunk takes tens of milliseconds, so
	// this is about whether the fan-out is stuck, not about how loaded the
	// machine is. It is deliberately shorter than the loop's budget
	// (burstLoopBudget), so a fan-out that has genuinely wedged is reported
	// against the chunk it wedged on rather than against the loop as a whole.
	burstChunkTimeout = 10 * time.Second

	// guestDropTimeout is how long the dropped guest has to observe its own
	// disconnect. It budgets a different mechanism from the two above: the drop
	// reaches the guest through uptermd's watchdog, which waits
	// sshForwardChannelDrainTimeout before closing the stalled channel and
	// sshForwardChannelAbortGrace again before escalating — several seconds of
	// deliberate delay that no amount of throughput removes.
	guestDropTimeout = 30 * time.Second

	// streamChunks is how many chunks TestStreamHelper writes: far more than
	// any case consumes, so the producer is still running whenever a test
	// samples it. The test ends the host long before it gets there.
	streamChunks = 4096

	streamChunkMarker = "STREAM-CHUNK-"
)

// TestBurstHelper is not a test. It is the host command for
// testClientSlowGuestDropped and testClientSurvivesBurstWithoutPrimary:
// re-executing this binary generates the burst without a shell, so the cases
// run identically on macOS, Linux and Windows.
//
// It skips unless invoked with a chunk count, so an ordinary suite run walks
// past it.
func TestBurstHelper(t *testing.T) {
	chunks, ok := burstHelperChunks(flag.Args())
	if !ok {
		t.Skip("helper process, not run directly")
	}

	in := bufio.NewReader(os.Stdin)
	line := strings.Repeat("x", burstLineWidth-1) + "\n"
	for i := 0; i < chunks; i++ {
		// One line of input buys one chunk. testClientSlowGuestDropped asks
		// for each only once the guest that is still reading has the last, so
		// that guest cannot be dropped for falling behind and only the guest
		// that has stopped reading is; testClientSurvivesBurstWithoutPrimary
		// asks for them all at once.
		if _, err := in.ReadString('\n'); err != nil {
			return
		}
		for written := 0; written < burstChunkBytes; written += len(line) {
			if _, err := os.Stdout.WriteString(line); err != nil {
				return
			}
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s%03d\n", burstChunkMarker, i); err != nil {
			return
		}
	}

	// Hold the session open past the burst, so the drop can be observed while
	// the host is still running.
	_, _ = in.ReadString('\n')
}

// burstHelperChunks reads the chunk count out of the positional arguments and
// reports whether this process was invoked as the helper at all.
//
// "There are no positionals" is not a reliable test of that, and assuming it
// broke make test on this branch. The Makefile has GO_TEST_FLAGS ?= "" and
// interpolates it unquoted, so an ordinary `make test` hands the binary a
// literal empty string as a positional argument and flag.Args() has length one.
// Plain `go test ./ftests/...` does not, which is why every check that did not
// run the real command missed it.
//
// So the test is whether the argument is a usable count, and anything else
// declines rather than fails: a helper that cannot tell it was invoked as a
// helper is looking at someone else's command line, not at a broken one. Zero
// is a real count — testHostExitsWhileGuestHoldsConnection passes it to get a
// command that exits as soon as it is released.
func burstHelperChunks(args []string) (int, bool) {
	if len(args) != 1 {
		return 0, false
	}
	chunks, err := strconv.Atoi(args[0])
	if err != nil || chunks < 0 {
		return 0, false
	}
	return chunks, true
}

// The empty-string case below is the one that matters: it is what `make test`
// actually passes, and TestBurstHelper's own SKIP is invisible to a suite run
// that does not reproduce it.
func TestBurstHelperChunks(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
		ok   bool
	}{
		{name: "no positionals", args: nil},
		{name: "make test's empty GO_TEST_FLAGS", args: []string{""}},
		{name: "not a number", args: []string{"-race"}},
		{name: "negative", args: []string{"-1"}},
		{name: "more than one positional", args: []string{"4", "8"}},
		{name: "zero chunks", args: []string{"0"}, want: 0, ok: true},
		{name: "a real count", args: []string{"64"}, want: 64, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chunks, ok := burstHelperChunks(tc.args)
			require.Equal(t, tc.ok, ok, "helper invocation should be recognised as %v", tc.ok)
			require.Equal(t, tc.want, chunks)
		})
	}
}

// TestStreamHelper is not a test. It is the host command for
// testClientNewcomerDoesNotDisplacePacer: once one line of input releases it,
// it writes chunk after chunk as fast as the pty takes them, and records how
// many it has written in a file, so the test can see how far the command has
// got — and so whether something is holding it back — without reading its
// output.
//
// It skips unless invoked with a chunk count and that file, so an ordinary
// suite run walks past it.
func TestStreamHelper(t *testing.T) {
	chunks, progress, ok := streamHelperArgs(flag.Args())
	if !ok {
		t.Skip("helper process, not run directly")
	}

	in := bufio.NewReader(os.Stdin)
	if _, err := in.ReadString('\n'); err != nil {
		return
	}
	line := strings.Repeat("x", burstLineWidth-1) + "\n"
	tmp := progress + ".tmp"
	for i := 0; i < chunks; i++ {
		for written := 0; written < burstChunkBytes; written += len(line) {
			if _, err := os.Stdout.WriteString(line); err != nil {
				return
			}
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s%04d\n", streamChunkMarker, i); err != nil {
			return
		}
		// Written aside and renamed into place, so a reader sees this count or
		// the last one whole, never a torn write.
		if err := os.WriteFile(tmp, []byte(strconv.Itoa(i+1)), 0o600); err != nil {
			return
		}
		if err := os.Rename(tmp, progress); err != nil {
			return
		}
	}

	_, _ = in.ReadString('\n')
}

// streamHelperArgs reads the chunk count and the progress file out of the
// positional arguments and reports whether this process was invoked as the
// helper at all. As with burstHelperChunks, anything but a usable pair
// declines rather than fails, because make test hands every test binary an
// empty positional of its own. Zero is not a usable count here: a stream with
// nothing in it has nothing to show.
func streamHelperArgs(args []string) (int, string, bool) {
	if len(args) != 2 || args[1] == "" {
		return 0, "", false
	}
	chunks, err := strconv.Atoi(args[0])
	if err != nil || chunks <= 0 {
		return 0, "", false
	}
	return chunks, args[1], true
}

func TestStreamHelperArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		chunks   int
		progress string
		ok       bool
	}{
		{name: "no positionals", args: nil},
		{name: "make test's empty GO_TEST_FLAGS", args: []string{""}},
		{name: "two empty positionals", args: []string{"", ""}},
		{name: "not a number", args: []string{"-race", "/p"}},
		{name: "zero chunks", args: []string{"0", "/p"}},
		{name: "no progress file", args: []string{"8", ""}},
		{name: "a real count and file", args: []string{"8", "/p"}, chunks: 8, progress: "/p", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chunks, progress, ok := streamHelperArgs(tc.args)
			require.Equal(t, tc.ok, ok, "helper invocation should be recognised as %v", tc.ok)
			require.Equal(t, tc.chunks, chunks)
			require.Equal(t, tc.progress, progress)
		})
	}
}

// One guest that has stopped reading must not stall the host or another guest
// for longer than the pacer's stall bound, and must itself be disconnected —
// all the way through: the host drops it, and the forwarder's watchdog turns
// that into a closed channel the guest can observe without ever resuming
// reads.
func testClientSlowGuestDropped(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	// The suite runs every connection case over both protocols, and this one is
	// far and away the most expensive: the stalled guest cannot observe its own
	// disconnect until sshForwardChannelDrainTimeout and the abort grace have
	// both elapsed, so it costs seconds where its neighbours cost about one,
	// and it sets the critical path of whichever topology group it runs in.
	//
	// Running it on ssh only costs nothing real. What stalls the guest is SSH
	// channel windowing, which is identical on both: the WebSocket protocol
	// changes how bytes reach uptermd, not how a channel's window is accounted.
	// The topology axis is the one that matters here and is kept — a
	// node-to-node hop puts a second forwarder in the path, with its own abort
	// scope to get right.
	if !strings.HasPrefix(hostURL, "ssh://") {
		t.Skip("covered on ssh; the stall is SSH channel windowing, not transport-specific")
	}

	left := make(chan *api.Client, 4)

	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{os.Args[0], "-test.run=^TestBurstHelper$", strconv.Itoa(burstChunks)},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientLeftCallback:       func(c *api.Client) { left <- c },
	}
	require.NoError(t, h.Share(hostURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)

	stalled := &Client{PrivateKeys: []string{ClientPrivateKey}, NoDrainStdout: true}
	require.NoError(t, stalled.Join(session, clientJoinURL))
	defer stalled.Close()

	healthy := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, healthy.Join(session, clientJoinURL))
	defer healthy.Close()

	// Both readers must run *concurrently*, and must be started before the
	// first go-ahead. Client.JoinWithContext pumps output into an unbuffered
	// channel, so a guest whose channel nobody is reading stops reading its SSH
	// channel — draining the host to completion first would turn the "healthy"
	// guest into a second stalled one and it would be dropped too. This is the
	// same hazard ftests/host_test.go:106 already documents.
	hostInput, hostOutput := h.InputOutput()
	_, healthyOutput := healthy.InputOutput()
	hostMarkers := watchMarkers(hostOutput)
	healthyMarkers := watchMarkers(healthyOutput)

	// Observe the stalled guest's own channel without ever reading its stdout.
	// Started before the burst because the forwarder's watchdog takes seconds to
	// escalate, and there is no reason to spend them serially.
	closed := make(chan error, 1)
	go func() { closed <- stalled.WaitSession() }()

	budget := burstLoopBudget(t)
	expiry := time.Now().Add(budget)

	// The burst is produced a chunk at a time, and the next chunk is not asked
	// for until the guest that is still reading has seen the last one. That was
	// once essential. With nothing pacing a session that has no primary, the
	// host read its own pty several times faster than a guest can drain an SSH
	// channel under -race, so an unthrottled burst overflowed every guest's
	// 1 MiB cap, the healthy one included, and the case could not tell "stopped
	// reading" from "reading". Now the earliest guest paces such a session, and
	// the stalled guest joined first: once its windows are full, output waits
	// on it until it has delivered nothing for the 5 s stall bound — inside
	// burstChunkTimeout — and then it is dropped and the healthy guest paces.
	// Pacing on the healthy guest is kept for what it gives the waits below:
	// they are short, and they do not depend on how fast the machine is. What
	// that costs in wall clock is bounded by expiry rather than by burstChunks,
	// which is a ceiling on volume, not on time.
	var dropped *api.Client
	var produced int
	for chunk := 0; chunk < burstChunks && dropped == nil; chunk++ {
		if time.Now().After(expiry) {
			t.Fatalf("the stalled guest was not dropped within %s, half of what the test binary's -timeout had left, after %d of %d bytes of output",
				budget, produced, burstChunks*burstChunkBytes)
		}

		hostInput <- "" // go-ahead for one chunk
		produced += burstChunkBytes

		// The host's own terminal keeps up. This is the head-of-line assertion
		// for the host: the fan-out writes to it synchronously, so before
		// per-guest buffering the stalled guest froze the host's own screen.
		awaitBurstChunk(t, hostMarkers, chunk, "the host's terminal")

		// So does the guest that kept reading — the head-of-line assertion for
		// the other guests.
		awaitBurstChunk(t, healthyMarkers, chunk, "a healthy guest")

		// Which guest left is established by elimination, not by matching the
		// event: both guests authenticate with the same key, so there is nothing
		// cheap to match on, and the healthy one has just delivered this chunk's
		// marker. If it were ever the healthy guest that had been dropped, the
		// WaitSession below would not return and the case would fail there — a
		// true failure, but reported one assertion after its cause.
		select {
		case c := <-left:
			dropped = c
		default:
		}
	}
	if dropped == nil {
		// The poll above is non-blocking so the loop can stop as soon as a drop
		// is visible. A drop landing during the final chunk has not necessarily
		// been delivered by the time the loop runs out of chunks, and reporting
		// that as "never dropped" would be wrong.
		select {
		case c := <-left:
			dropped = c
		case <-time.After(callbackTimeout):
		}
	}
	require.NotNil(t, dropped, "the stalled guest was never dropped within %d bytes of output; raise burstChunks", burstChunks*burstChunkBytes)
	// How much of the budget the drop actually needed. It varies with the number
	// of hops and with the platform's socket buffers, so it is the number to
	// look at before changing burstChunks.
	t.Logf("stalled guest dropped after %d of %d bytes of output", produced, burstChunks*burstChunkBytes)

	// The drop has to reach the guest. The host-side callback alone would pass
	// even if the guest were left stranded on uptermd, which is what the
	// forwarder's watchdog prevents.
	select {
	case <-closed:
	case <-time.After(guestDropTimeout):
		t.Fatal("the stalled guest was never disconnected")
	}
}

// burstLoopBudget is how long the paced loop may run: half of what is left of
// the binary's own -timeout. That deadline is what the loop is really
// competing for, and overrunning it is a panic that takes every other ftest
// with it, whereas overrunning the budget is one failure that says how far the
// burst got.
//
// It is not a fixed figure, because how long a healthy loop takes is set by
// the machine, not by upterm: the drop lands at the same chunk on every run of
// a platform, but each chunk is a 256 KiB render through the host's terminal.
// On a Windows runner under make test, where the other packages' -race binaries
// compete for its four CPUs, ConPTY takes about 1.4 s a chunk against 0.2 s
// with ftests alone, and ssh/singleNode's 18 chunks took 25-26 s — a fixed
// 25 s budget, calibrated where the slowest healthy loop took 11.8 s, failed
// runs whose drop was on its way. A wedged fan-out is still caught by
// burstChunkTimeout, and a drop that never comes by burstChunks.
//
// Without a -timeout, those two are the only bounds the loop needs.
func burstLoopBudget(t *testing.T) time.Duration {
	if deadline, ok := t.Deadline(); ok {
		if half := time.Until(deadline) / 2; half > 0 {
			return half
		}
	}
	return burstChunks * burstChunkTimeout
}

// With no terminal attached, the guest paces the command: a burst far past its
// buffer and the SSH windows in front of it arrives whole, at the guest's own
// rate, and the guest stays. Before, nothing paced a session without a
// primary, so the host read its pty as fast as the kernel handed it over and
// dropped any guest slower than that on the first burst past the slack between
// them — every remote guest of a detached session.
func testClientSurvivesBurstWithoutPrimary(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	if !strings.HasPrefix(hostURL, "ssh://") {
		t.Skip("covered on ssh; the backpressure is SSH channel windowing, not transport-specific")
	}
	if runtime.GOOS == "windows" {
		t.Skip("ConPTY produces more slowly than the guest reads, so nothing is ever paced and the case would prove nothing; the server-level unix test and the pacer's unit tests cover the policy")
	}

	// The guest's link. The host reads its pty slowest under -race, at about
	// 6.8 MiB/s where this was written, so unpaced the whole burst, all
	// burstChunks of it, leaves this guest some 11 MiB behind against about
	// 5 MiB of slack through uptermd: a drop, not a close call. Without -race
	// it is further behind still.
	const readRate = 2 << 20

	joined := make(chan *api.Client, 4)
	left := make(chan *api.Client, 4)
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  []string{os.Args[0], "-test.run=^TestBurstHelper$", strconv.Itoa(burstChunks)},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientJoinedCallback: func(c *api.Client) {
			if c.GetKind() == api.Client_GUEST {
				joined <- c
			}
		},
		// Guests only. The fixture's own terminal is a pipe viewer, which is
		// what leaves the session without a primary, and a viewer is a bounded
		// sink that nothing waits on: the burst may drop it, and that is not
		// what this case is about.
		ClientLeftCallback: func(c *api.Client) {
			if c.GetKind() == api.Client_GUEST {
				left <- c
			}
		},
	}
	require.NoError(t, h.Share(hostURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)

	stop := make(chan struct{})
	defer close(stop)

	g := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, g.Join(session, clientJoinURL))
	defer g.Close()
	// Join returns before the host has attached the guest's output, and a
	// burst that started first would go out unpaced. The join is reported
	// once it is attached.
	select {
	case <-joined:
	case <-time.After(callbackTimeout):
		t.Fatal("the guest's join was never reported")
	}

	hostInput, hostOutput := h.InputOutput()
	_, guestOutput := g.InputOutput()
	markers := watchMarkers(throttled(guestOutput, readRate))
	discard(hostOutput, stop)

	// The whole burst at once: nothing but the pacer holds the command back.
	for i := 0; i < burstChunks; i++ {
		hostInput <- ""
	}

	// Every marker, in order, with the guest's departure watched throughout.
	for chunk := 0; chunk < burstChunks; {
		select {
		case line := <-markers:
			if i, ok := markerIndex(line, burstChunkMarker); ok && i == chunk {
				chunk++
			}
		case <-left:
			t.Fatalf("the guest was dropped after %d of %d chunks of the burst: nothing paced the command to it", chunk, burstChunks)
		case <-time.After(burstChunkTimeout):
			t.Fatalf("the guest did not receive chunk %d of the burst within %s", chunk, burstChunkTimeout)
		}
	}
}

// A guest that joins while another is pacing the session must not take the
// pace from it. The newcomer arrives with megabytes of empty SSH window on its
// way through uptermd, and host-side backlog is all the pacer can judge by, so
// until those windows fill even a guest that never reads looks the fastest. Were the fastest guest to pace, the newcomer would open the
// gate and the established guest, held to its own link, would overflow and be
// dropped. With the earliest pacing, the newcomer follows, overflows, and is
// the one dropped.
//
// Hence the order: the newcomer joins only once the established guest's link
// is what holds the command back. Joined before the output started, both
// guests would begin with fresh windows, and the case could not tell the two
// rules apart.
func testClientNewcomerDoesNotDisplacePacer(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	if !strings.HasPrefix(hostURL, "ssh://") {
		t.Skip("covered on ssh; the backpressure is SSH channel windowing, not transport-specific")
	}
	if runtime.GOOS == "windows" {
		t.Skip("ConPTY under load produces more slowly than any rate A could hold it to; the pacer's unit tests cover the policy")
	}

	const readRate = 1 << 20 // A's link: four chunks a second
	progress := filepath.Join(t.TempDir(), "progress")
	joined := make(chan *api.Client, 8)
	left := make(chan *api.Client, 8)
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  []string{os.Args[0], "-test.run=^TestStreamHelper$", strconv.Itoa(streamChunks), progress},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientJoinedCallback: func(c *api.Client) {
			if c.GetKind() == api.Client_GUEST {
				joined <- c
			}
		},
		ClientLeftCallback: func(c *api.Client) {
			if c.GetKind() == api.Client_GUEST {
				left <- c
			}
		},
	}
	require.NoError(t, h.Share(hostURL))
	defer func() {
		h.Close()
		// The helper writes its count into t.TempDir(), which goes once this
		// returns, and Close does not wait for the command. The host's exit
		// does: it hangs the helper up and reaps it.
		select {
		case <-h.Done():
		case <-time.After(30 * time.Second):
			t.Error("the host did not exit, so the stream helper may still be writing")
		}
	}()

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)
	guestID := func() string { // the next guest's join, so A and B can be told apart
		select {
		case c := <-joined:
			return c.Id
		case <-time.After(callbackTimeout):
			t.Fatal("a guest's join was never reported")
			return ""
		}
	}

	stop := make(chan struct{})
	defer close(stop)

	a := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, a.Join(session, clientJoinURL))
	defer a.Close()
	aID := guestID()
	aClosed := make(chan struct{})
	go func() { _ = a.WaitSession(); close(aClosed) }()

	// A's markers, read at readRate, tracked in aSeen (-1 until the first).
	// The viewer's output is drained and not asserted on.
	hostInput, hostOutput := h.InputOutput()
	_, aOutput := a.InputOutput()
	aMarkers := watchLines(throttled(aOutput, readRate), streamChunkMarker)
	var aSeen atomic.Int64
	aSeen.Store(-1)
	go func() {
		for {
			select {
			case line := <-aMarkers:
				if i, ok := markerIndex(line, streamChunkMarker); ok && int64(i) > aSeen.Load() {
					aSeen.Store(int64(i))
				}
			case <-stop:
				return
			}
		}
	}()
	discard(hostOutput, stop)

	hostInput <- "" // start the stream
	waitHeld(t, progress, &aSeen, aClosed)

	b := &Client{PrivateKeys: []string{ClientPrivateKey}, NoDrainStdout: true}
	require.NoError(t, b.Join(session, clientJoinURL))
	defer b.Close()
	bID := guestID()
	bClosed := make(chan struct{})
	go func() { _ = b.WaitSession(); close(bClosed) }()

	// B's departure, and only B's, with A watched throughout.
	deadline := time.After(time.Minute)
	for departed := false; !departed; {
		select {
		case c := <-left:
			require.NotEqual(t, aID, c.Id, "the established guest was dropped when a newcomer joined")
			departed = c.Id == bID
		case <-aClosed:
			t.Fatal("the established guest's session closed while the newcomer was being dropped")
		case <-deadline:
			t.Fatal("the newcomer that never reads was never dropped")
		}
	}

	// Output produced after B's departure must reach A. Bytes already in
	// flight to A cannot satisfy this, so a dropped A cannot pass it.
	after := int64(readProgress(progress))
	deadline = time.After(time.Minute)
	for aSeen.Load() < after+2 {
		select {
		case <-aClosed:
			t.Fatal("the established guest was dropped")
		case <-deadline:
			t.Fatalf("output produced after the newcomer left never reached A (A at %d, needed %d)", aSeen.Load(), after+2)
		case <-time.After(50 * time.Millisecond):
		}
	}
	select {
	case <-bClosed:
	case <-aClosed:
		t.Fatal("the established guest was dropped")
	case <-time.After(guestDropTimeout):
		t.Fatal("the newcomer was never disconnected")
	}
	select {
	case <-aClosed:
		t.Fatal("the established guest was dropped")
	default:
	}
}

// A guest that keeps its SSH connection open after the host's command exits
// must not hold the host open. charm.land/ssh's Shutdown waits on its
// connection WaitGroup until the context it is handed is done, so this hangs
// if that context is still live — and the deferred ReverseTunnel.Close never
// runs, wedging the process rather than any one session.
//
// The exit must be command-led. Cancelling the host instead would make the
// context done for the wrong reason and the test would pass either way.
func testHostExitsWhileGuestHoldsConnection(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{os.Args[0], "-test.run=^TestBurstHelper$", "0"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(t, h.Share(hostURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)

	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, c.Join(session, clientJoinURL))
	_, guestOutput := c.InputOutput()
	go func() {
		for range guestOutput { //nolint:revive // drained, not inspected
		}
	}()
	// Deliberately never closed: the guest keeps its SSH connection while the
	// host's command exits underneath it.

	hostInput, _ := h.InputOutput()
	hostInput <- "" // zero chunks, so this one line lets the helper exit on its own

	select {
	case <-h.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the host did not exit while a guest held its connection open")
	}
}

// awaitBurstChunk waits for the marker that closes one chunk of the burst.
//
// Markers carry their index and are matched on it rather than counted, so a
// terminal that repeats a line — ConPTY re-renders, readline redraws — cannot
// walk the loop one chunk ahead of what the reader has actually received.
func awaitBurstChunk(t *testing.T, markers <-chan string, chunk int, who string) {
	t.Helper()
	want := fmt.Sprintf("%s%03d", burstChunkMarker, chunk)
	deadline := time.After(burstChunkTimeout)
	for {
		select {
		case got := <-markers:
			if strings.Contains(got, want) {
				return
			}
		case <-deadline:
			t.Fatalf("%s did not receive chunk %d of the burst within %s", who, chunk, burstChunkTimeout)
		}
	}
}

// watchMarkers starts draining ch immediately and reports every line carrying a
// burst marker.
func watchMarkers(ch chan string) <-chan string {
	return watchLines(ch, burstChunkMarker)
}

// watchLines starts draining ch immediately and reports every line carrying
// marker.
//
// It must start draining at once: these output channels are unbuffered, so a
// channel nobody reads stops its client reading its SSH channel, which is
// exactly the state these cases reserve for the one guest that is meant to be
// in it. And it cannot test each chunk with strings.Contains — a marker split
// across two chunks would be missed — so it scans the stream, using the suite's
// existing scanner helper, which pipes the channel into a bufio.Scanner for
// exactly this reason.
func watchLines(ch chan string, marker string) <-chan string {
	lines := make(chan string, 4096)
	go func() {
		s := scanner(ch)
		for s.Scan() {
			if !strings.Contains(s.Text(), marker) {
				continue
			}
			select {
			case lines <- s.Text():
			default: // never block the drain on a test that stopped reading
			}
		}
		// Keep draining: stopping here would stall the client whose output
		// this is.
		for range ch { //nolint:revive // drained, not inspected
		}
	}()
	return lines
}

// markerIndex returns the number that follows marker in line.
func markerIndex(line, marker string) (int, bool) {
	i := strings.Index(line, marker)
	if i < 0 {
		return 0, false
	}
	digits := line[i+len(marker):]
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(digits[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// readProgress returns how many chunks TestStreamHelper has recorded writing
// to path, or -1 before it has recorded any.
func readProgress(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return -1
	}
	return n
}

// throttled passes on what arrives on ch at no more than rate bytes a second,
// standing in for a link that slow. Each string pays for its own length in
// time before it goes on, and time spent waiting for input banks no credit, so
// a burst after a lull goes no faster than steady output would.
func throttled(ch chan string, rate int) chan string {
	out := make(chan string)
	go func() {
		for s := range ch {
			time.Sleep(time.Duration(len(s)) * time.Second / time.Duration(rate))
			out <- s
		}
	}()
	return out
}

// waitHeld returns once the stream is held to A: over two seconds the producer
// advanced, by no more than A did plus a few chunks, while at least a full SSH
// window ahead of A. An unpaced producer outruns A many times over; a finished
// one does not advance at all.
func waitHeld(t *testing.T, progress string, aSeen *atomic.Int64, aClosed <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	p0, a0 := readProgress(progress), aSeen.Load()
	for time.Now().Before(deadline) {
		select {
		case <-aClosed:
			t.Fatal("A was dropped before its link held the producer")
		case <-time.After(2 * time.Second):
		}
		p1, a1 := readProgress(progress), aSeen.Load()
		if p0 >= 0 && a0 >= 0 && p1 > p0 && a1 > a0 &&
			int64(p1-p0) <= a1-a0+4 && int64(p1)-a1 >= 8 {
			return
		}
		p0, a0 = p1, a1
	}
	t.Fatal("the producer was never held to A's rate")
}

// discard drains ch until stop closes, for output a case has no use for but
// must not leave unread: an unread channel stops its client reading.
func discard(ch chan string, stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-ch:
			case <-stop:
				return
			}
		}
	}()
}
