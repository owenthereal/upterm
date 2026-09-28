package ftests

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	// machine is. It is deliberately shorter than burstBudget, so a fan-out that
	// has genuinely wedged is reported against the chunk it wedged on rather
	// than against the loop as a whole.
	burstChunkTimeout = 10 * time.Second

	// burstBudget bounds the paced loop in wall-clock time, which burstChunks
	// alone does not: a platform whose socket buffers push the drop late can
	// legitimately produce all 64 chunks, once per topology, inside a binary
	// that make test gives 180 s in total.
	//
	// 25 s is a little over twice the slowest healthy run measured here
	// (ssh/multiNodes, 28 chunks, 11.8 s under -race), and four of those on top
	// of the ~56 s the rest of the suite costs still fits. The loop clamps it
	// further against the binary's own deadline, because a case that fails
	// naming its knob is worth more than a timeout panic that takes every other
	// ftest down with it.
	burstBudget = 25 * time.Second

	// guestDropTimeout is how long the dropped guest has to observe its own
	// disconnect. It budgets a different mechanism from the two above: the drop
	// reaches the guest through uptermd's watchdog, which waits
	// sshForwardChannelDrainTimeout before closing the stalled channel and
	// sshForwardChannelAbortGrace again before escalating — several seconds of
	// deliberate delay that no amount of throughput removes.
	guestDropTimeout = 30 * time.Second
)

// TestBurstHelper is not a test. It is the host command for
// testClientSlowGuestDropped: re-executing this binary generates the burst
// without a shell, so the case runs identically on macOS, Linux and Windows.
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
		// One line of input buys one chunk. The producer never runs ahead of
		// the guest that is still reading, so that guest cannot be dropped for
		// falling behind and only the guest that has stopped reading does.
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

// One guest that has stopped reading must not stall the host or another guest,
// and must itself be disconnected — all the way through: the host drops it, and
// the forwarder's watchdog turns that into a closed channel the guest can
// observe without ever resuming reads.
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
	// for until the guest that is still reading has seen the last one. Blasting
	// instead would prove nothing: the host reads its own pty several times
	// faster than a guest can drain an SSH channel under -race, so an
	// unthrottled burst overflows every guest's 1 MiB cap, the healthy one
	// included, and the case could not tell "stopped reading" from "reading".
	// Pacing on the guest rather than on a timer is what keeps that true on a
	// machine of any speed. What that costs in wall clock is bounded by expiry
	// rather than by burstChunks, which is a ceiling on volume, not on time.
	var dropped *api.Client
	var produced int
	for chunk := 0; chunk < burstChunks && dropped == nil; chunk++ {
		if time.Now().After(expiry) {
			t.Fatalf("the stalled guest was not dropped within %s, after %d of %d bytes of output; raise burstBudget, and burstChunks with it if the whole ceiling was spent",
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

// burstLoopBudget is how long the paced loop may run.
//
// burstBudget is the figure to tune, but it is clamped against what is left of
// the binary's own -timeout, which is what the loop is really competing for:
// four topologies run this case, and make test gives the whole ftests binary
// 180 s. Overrunning that is a panic that takes every other ftest with it,
// whereas overrunning burstBudget is one failure naming one knob.
func burstLoopBudget(t *testing.T) time.Duration {
	budget := burstBudget
	if deadline, ok := t.Deadline(); ok {
		if half := time.Until(deadline) / 2; half > 0 && half < budget {
			budget = half
		}
	}
	return budget
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
//
// It must start draining at once: these output channels are unbuffered, so a
// channel nobody reads stops its client reading its SSH channel, which is
// exactly the state this case reserves for the one guest that is meant to be in
// it. And it cannot test each chunk with strings.Contains — a marker split
// across two chunks would be missed — so it scans the stream, using the suite's
// existing scanner helper, which pipes the channel into a bufio.Scanner for
// exactly this reason.
func watchMarkers(ch chan string) <-chan string {
	markers := make(chan string, 2*burstChunks)
	go func() {
		s := scanner(ch)
		for s.Scan() {
			if !strings.Contains(s.Text(), burstChunkMarker) {
				continue
			}
			select {
			case markers <- s.Text():
			default: // never block the drain on a test that stopped reading
			}
		}
		// Keep draining: stopping here would stall the client whose output
		// this is.
		for range ch { //nolint:revive // drained, not inspected
		}
	}()
	return markers
}
