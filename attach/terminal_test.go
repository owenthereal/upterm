package attach

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// dialDoor connects to door the way Client.Run does — a unix dial, then a
// handshake as user host with a throwaway key, pinned to door's host key —
// and hands over the connection a Terminal runs on.
func dialDoor(t *testing.T, door *fakeDoor) *ssh.Client {
	t.Helper()
	raw, err := net.Dial("unix", door.socket)
	require.NoError(t, err)
	conn, chans, reqs, err := ssh.NewClientConn(raw, door.socket, &ssh.ClientConfig{
		User:            "host",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newSigner(t))},
		HostKeyCallback: (&Client{HostKeys: door.pin()}).checkHostKey,
		ClientVersion:   upterm.AttachSSHClientVersion,
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// gatedWriteSink is a terminal that takes nothing until release is closed:
// every write parks there, then succeeds. The first open writes are taken at
// once, before the gate applies.
type gatedWriteSink struct {
	release chan struct{}
	open    int32

	writes atomic.Int32
}

func (g *gatedWriteSink) Write(p []byte) (int, error) {
	if g.writes.Add(1) > g.open {
		<-g.release
	}
	return len(p), nil
}

// stallingDoor completes the handshake and accepts the session channel, then
// never answers a request: a host that stopped after authentication. It runs
// on loopback TCP: both SSH ends write their version line before reading, so
// an unbuffered net.Pipe deadlocks before the handshake.
func stallingDoor(t *testing.T) func() *ssh.Client {
	return func() *ssh.Client {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(newSigner(t))
		go func() {
			srvConn, err := ln.Accept()
			if err != nil {
				return
			}
			_, chans, reqs, err := ssh.NewServerConn(srvConn, cfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				ch, chReqs, err := nc.Accept()
				if err != nil {
					continue
				}
				t.Cleanup(func() { _ = ch.Close() })
				go func() {
					for range chReqs {
					}
				}() // read, never Reply
			}
		}()
		c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User: "host", HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a test door on loopback
		})
		require.NoError(t, err)
		return c
	}
}

// refusingDoor completes the handshake and accepts the session channel, then
// refuses every request on it: a host that gives this client neither a pty
// nor a shell. Loopback TCP, as for stallingDoor.
func refusingDoor(t *testing.T) *ssh.Client {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(newSigner(t))
	go func() {
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(srvConn, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			t.Cleanup(func() { _ = ch.Close() })
			go func() {
				for r := range chReqs {
					_ = r.Reply(false, nil)
				}
			}()
		}
	}()
	c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User: "host", HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a test door on loopback
	})
	require.NoError(t, err)
	return c
}

// Whatever fails startup, Run has closed the client by the time it returns the
// error, so the caller has nothing to clean up after. setupBy is an hour off
// and ctx is never cancelled, so neither of Run's own timers is what closes it.
func TestTerminalClosesTheClientBeforeReturningAnError(t *testing.T) {
	client := refusingDoor(t)
	_, err := (&Terminal{Stdout: io.Discard, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
		Run(context.Background(), client, time.Now().Add(time.Hour))
	require.ErrorContains(t, err, "pty request")

	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Run returned its error with the client still open")
	}
}

func TestTerminalSetupIsCutOffAtSetupBy(t *testing.T) {
	client := stallingDoor(t)()
	setupBy := time.Now().Add(200 * time.Millisecond)
	errs := make(chan error, 1)
	go func() {
		_, err := (&Terminal{Stdout: io.Discard, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
			Run(context.Background(), client, setupBy)
		errs <- err
	}()
	select {
	case err := <-errs:
		require.Error(t, err)
	case <-time.After(time.Until(setupBy) + 3*time.Second):
		t.Fatal("setup was not cut off at setupBy")
	}
}

// setupBy bounds the setup and nothing after it: a session still running past
// it is not cut off.
func TestTerminalSetupByIsCalledOffOnceTheShellRuns(t *testing.T) {
	past := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		<-past
		_ = s.Exit(3)
	})
	client := dialDoor(t, door)
	setupBy := time.Now().Add(time.Second)
	time.AfterFunc(time.Until(setupBy)+250*time.Millisecond, func() { close(past) })
	res, err := (&Terminal{Stdout: io.Discard, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
		Run(context.Background(), client, setupBy)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited, Status: 3}, Result{Reason: res.Reason, Status: res.Status})
}

func TestTerminalOnReadyRunsBeforeTheFirstOutputByte(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) { _, _ = io.WriteString(s, "FROM-SESSION"); _ = s.Exit(0) })
	out := &syncSink{}
	term := &Terminal{Stdout: out, Pty: &Pty{Term: "xterm", Size: termsize.Default},
		OnReady: func() {
			// Long enough for the session's output to reach Stdout, were
			// anything copying it yet.
			time.Sleep(200 * time.Millisecond)
			_, _ = out.Write([]byte("READY|"))
		}}
	res, err := term.Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
	require.NoError(t, err)
	require.Equal(t, Exited, res.Reason)
	require.True(t, strings.HasPrefix(out.String(), "READY|FROM-SESSION"), out.String())
}

func TestTerminalReportsAnAbandonedRestoreAndHoldsReleasedOpen(t *testing.T) {
	// Long enough that the copy has read and fed the session's output before
	// the drain gives up on it, however slowly it is scheduled.
	old := outputDrainTimeout
	outputDrainTimeout = time.Second
	t.Cleanup(func() { outputDrainTimeout = old })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "\x1b[?1049h") // enter the alternate screen
		_ = s.Exit(0)
	})
	// The very first write parks: the tracker has seen ?1049h (it is fed
	// before the write), the drain times out, and the restore is skipped.
	sink := &gatedWriteSink{release: make(chan struct{})}
	res, err := (&Terminal{Stdout: sink, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
		Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
	require.NoError(t, err)
	require.Contains(t, string(res.Unrestored), "\x1b[?1049l")
	select {
	case <-res.Released:
		t.Fatal("Released closed while a write to Stdout was parked")
	default:
	}
	close(sink.release)
	select {
	case <-res.Released:
	case <-time.After(testTimeout):
		t.Fatal("Released never closed after the write returned")
	}
}

// The restore's own write can park too, once the copy has finished: Released
// waits for it as it waits for the copy, and a restore that was attempted is
// not handed back as Unrestored.
func TestTerminalReleasedWaitsForARestoreStillInFlight(t *testing.T) {
	old := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = old })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "\x1b[?1049h")
		_ = s.Exit(0)
	})
	// The session's output is taken; the restore after it parks.
	sink := &gatedWriteSink{release: make(chan struct{}), open: 1}
	res, err := (&Terminal{Stdout: sink, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
		Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
	require.NoError(t, err)
	require.Empty(t, res.Unrestored)
	select {
	case <-res.Released:
		t.Fatal("Released closed while the restore's write was parked")
	default:
	}
	close(sink.release)
	select {
	case <-res.Released:
	case <-time.After(testTimeout):
		t.Fatal("Released never closed after the restore's write returned")
	}
}

// runSuspending runs a Terminal on door with a pty, a typed-into Stdin and a
// Suspend that hands the terminal straight back, and hands back its Result.
func runSuspending(t *testing.T, door *fakeDoor, stdout io.Writer, stdin io.Reader, hooked *atomic.Bool) <-chan Result {
	t.Helper()
	client := dialDoor(t, door)
	done := make(chan Result, 1)
	go func() {
		res, err := (&Terminal{Stdin: stdin, Stdout: stdout, Escape: '~',
			Pty: &Pty{Term: "xterm", Size: termsize.Default},
			Suspend: func() (termsize.Size, bool) {
				hooked.Store(true)
				return termsize.Size{}, true
			}}).Run(context.Background(), client, time.Now().Add(testTimeout))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	return done
}

// A suspend that cannot take the output from a write parked on the terminal
// detaches having written nothing, so the terminal is still in the session's
// modes, and the restore is handed back — even though the parked write
// returns, and the drain finishes, before the drain's bound.
func TestTerminalUnrestoredHoldsWhatASuspendCouldNotWrite(t *testing.T) {
	old := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = old })

	ended := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, suspendScreen)
		<-s.Context().Done()
		close(ended)
	})
	// The screen's own write parks, holding the output.
	sink := &gatedWriteSink{release: make(chan struct{})}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	var hooked atomic.Bool
	done := runSuspending(t, door, sink, pr, &hooked)

	waitFor(t, func() bool { return sink.writes.Load() == 1 }, "the session's screen never reached the terminal")
	_, err := pw.Write([]byte("\r~\x1a"))
	require.NoError(t, err)
	// The connection closing is the detach; the parked write returns then,
	// well inside the drain's bound.
	select {
	case <-ended:
	case <-time.After(testTimeout):
		t.Fatal("~^Z held by a parked write did not detach")
	}
	close(sink.release)

	var res Result
	select {
	case res = <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after the detach")
	}
	require.Equal(t, Detached, res.Reason)
	require.False(t, hooked.Load(), "the process must not be stopped with a write still in flight")
	require.Contains(t, string(res.Unrestored), "\x1b[?1049l")
}

// A resume whose write putting the session's modes back does not finish
// leaves the terminal in them once that write lands: the restore is handed
// back, and Released waits for the write.
func TestTerminalUnrestoredHoldsWhatAStalledResumeLeaves(t *testing.T) {
	old := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = old })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, suspendScreen)
		<-s.Context().Done()
	})
	// The screen and the restore are taken; the snapshot that puts the
	// session's modes back parks.
	sink := &gatedWriteSink{release: make(chan struct{}), open: 2}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	var hooked atomic.Bool
	done := runSuspending(t, door, sink, pr, &hooked)

	waitFor(t, func() bool { return sink.writes.Load() == 1 }, "the session's screen never reached the terminal")
	_, err := pw.Write([]byte("\r~\x1a"))
	require.NoError(t, err)

	var res Result
	select {
	case res = <-done:
	case <-time.After(testTimeout):
		t.Fatal("a resume the terminal did not take kept the attachment")
	}
	require.Equal(t, Detached, res.Reason)
	require.True(t, hooked.Load())
	require.Contains(t, string(res.Unrestored), "\x1b[?1049l")
	select {
	case <-res.Released:
		t.Fatal("Released closed while the snapshot's write was parked")
	default:
	}
	close(sink.release)
	select {
	case <-res.Released:
	case <-time.After(testTimeout):
		t.Fatal("Released never closed after the snapshot's write returned")
	}
}

// A feed in progress when output is abandoned is in the snapshot: the tail
// waits for trackerMu, never reads the tracker under the copier.
// testHookFeeding (nil outside tests) runs inside trackerMu, just before the
// feed.
func TestTerminalUnrestoredWaitsForAFeedInProgress(t *testing.T) {
	// Long enough that the copy has read the session's output, and reached
	// the feed, before the drain gives up on it.
	old := outputDrainTimeout
	outputDrainTimeout = time.Second
	t.Cleanup(func() { outputDrainTimeout = old })

	feeding, release := make(chan struct{}), make(chan struct{})
	testHookFeeding = func() { close(feeding); <-release }
	t.Cleanup(func() { testHookFeeding = nil })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "\x1b[?1049h")
		_ = s.Exit(0)
	})
	// The write after the feed parks for good; released once the test is
	// over, so that no goroutine outlives it.
	sink := &gatedWriteSink{release: make(chan struct{})}
	t.Cleanup(func() { close(sink.release) })
	done := make(chan Result, 1)
	go func() {
		res, _ := (&Terminal{Stdout: sink, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
			Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
		done <- res
	}()
	<-feeding // the copier holds trackerMu, mid-feed
	select {
	case <-done:
		t.Fatal("Run took its snapshot while a feed was in progress")
	case <-time.After(2 * time.Second): // well past the drain timeout
	}
	close(release)
	res := <-done
	require.Contains(t, string(res.Unrestored), "\x1b[?1049l")
}

func TestTerminalReleasedIsClosedOnAnOrdinaryEnd(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) { _ = s.Exit(3) })
	res, err := (&Terminal{Stdout: io.Discard, Pty: &Pty{Term: "xterm", Size: termsize.Default}}).
		Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited, Status: 3}, Result{Reason: res.Reason, Status: res.Status})
	require.Empty(t, res.Unrestored)
	select {
	case <-res.Released:
	default:
		t.Fatal("Released not closed")
	}
}
