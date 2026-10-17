package attach

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
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

// runStatusTerminal runs a Terminal on door with a pty, a typed-into Stdin and
// the Status hook status, until ctx ends or the session does, and hands back
// its Result.
func runStatusTerminal(t *testing.T, ctx context.Context, door *fakeDoor, stdout io.Writer, stdin io.Reader, status func(context.Context) []string) <-chan Result {
	t.Helper()
	client := dialDoor(t, door)
	done := make(chan Result, 1)
	go func() {
		res, err := (&Terminal{Stdin: stdin, Stdout: stdout, Escape: '~',
			Pty:    &Pty{Term: "xterm", Size: termsize.Default},
			Status: status,
			Logger: slog.New(slog.DiscardHandler),
		}).Run(ctx, client, time.Now().Add(testTimeout))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	return done
}

// awaitResult waits for done, failing the test past testTimeout.
func awaitResult(t *testing.T, done <-chan Result) Result {
	t.Helper()
	select {
	case res := <-done:
		return res
	case <-time.After(testTimeout):
		t.Fatal("Run did not return")
		return Result{}
	}
}

// awaitClosed waits for ch to close, failing the test with msg past
// testTimeout.
func awaitClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testTimeout):
		t.Fatal(msg)
	}
}

// answering is a Status hook that answers lines at once, and closes asked
// the first time it is called.
func answering(lines []string, asked chan struct{}) func(context.Context) []string {
	var once sync.Once
	return func(context.Context) []string {
		once.Do(func() { close(asked) })
		return lines
	}
}

// tearingSink is a terminal that takes each write a few bytes at a time,
// letting other goroutines run in between: two writes made at once
// interleave in it, as they can on a real descriptor. saw is set once a write
// containing mark has been taken whole.
type tearingSink struct {
	mark string

	mu  sync.Mutex
	buf bytes.Buffer
	saw atomic.Bool
}

func (s *tearingSink) Write(p []byte) (int, error) {
	n := len(p)
	whole := s.mark != "" && bytes.Contains(p, []byte(s.mark))
	for len(p) > 0 {
		k := min(len(p), 16)
		s.mu.Lock()
		s.buf.Write(p[:k])
		s.mu.Unlock()
		p = p[k:]
		runtime.Gosched()
	}
	if whole {
		s.saw.Store(true)
	}
	return n, nil
}

func (s *tearingSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *tearingSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// runFloodWithStatus has a door write 1 KiB chunks of 'x' without pause, and
// the client type "\r~?" mid-flood with a Status hook answering lines. The
// flood stops at floodLimit, so a status that never comes costs a bounded
// buffer, and the session ends once the status has reached the terminal.
func runFloodWithStatus(t *testing.T, lines []string) string {
	t.Helper()
	const floodLimit = 16 << 20
	stop := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		chunk := bytes.Repeat([]byte("x"), 1024)
		for sent := 0; sent < floodLimit; sent += len(chunk) {
			select {
			case <-stop:
				_ = s.Exit(0)
				return
			case <-s.Context().Done():
				return
			default:
			}
			if _, err := s.Write(chunk); err != nil {
				return
			}
		}
		select {
		case <-stop:
			_ = s.Exit(0)
		case <-s.Context().Done():
		}
	})
	sink := &tearingSink{mark: lines[len(lines)-1]}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runStatusTerminal(t, ctx, door, sink, pr, answering(lines, make(chan struct{})))

	waitFor(t, func() bool { return sink.Len() >= 64<<10 }, "the flood never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, sink.saw.Load, "the status never reached the terminal")
	close(stop)
	awaitResult(t, done)
	return sink.String()
}

// runPausedWithStatus has a door write before, then wait for the client's
// Status hook to be asked, give its lookup a moment to reach the output,
// write after and "AFTER", and stay until the client leaves. The client types
// "\r~?" once before has reached the terminal, and leaves once its status
// and "AFTER" have.
func runPausedWithStatus(t *testing.T, before, after string, lines []string) string {
	t.Helper()
	asked := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, before)
		select {
		case <-asked:
		case <-s.Context().Done():
			return
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(s, after)
		_, _ = io.WriteString(s, "AFTER")
		<-s.Context().Done()
	})
	sink := &syncSink{}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runStatusTerminal(t, ctx, door, sink, pr, answering(lines, asked))

	waitFor(t, func() bool { return strings.Contains(sink.String(), before) }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, func() bool {
		out := sink.String()
		return strings.Contains(out, lines[0]) && strings.Contains(out, "AFTER")
	}, "the status and the session's output never both reached the terminal")
	cancel()
	awaitResult(t, done)
	return sink.String()
}

// runSplitSequenceWithStatus: the door sends "\x1b]0;tit" (an OSC split at a
// chunk boundary), pauses while the client types "\r~?", then sends "le\x07"
// and more output.
func runSplitSequenceWithStatus(t *testing.T, lines []string) string {
	t.Helper()
	return runPausedWithStatus(t, "\x1b]0;tit", "le\x07", lines)
}

// runAmbiguousStringWithStatus: the door sends "\x1bPq\x18", a DCS the
// program ended with CAN, pauses while the client types "\r~?", then sends
// "\x1b\\" and more output.
func runAmbiguousStringWithStatus(t *testing.T, lines []string) string {
	t.Helper()
	return runPausedWithStatus(t, "\x1bPq\x18", "\x1b\\", lines)
}

// runBlockedStdoutThenDetach: Stdout takes nothing, so the copy is parked in
// its first write; the client types "~?", and once the lookup has been asked,
// "~.". It hands back the Result and how long the two keys took to end Run.
func runBlockedStdoutThenDetach(t *testing.T) (Result, time.Duration) {
	t.Helper()
	// Long enough that a lookup holding the input for the turn's whole
	// bound, and the drain after it, is told apart from the drain alone.
	old := outputDrainTimeout
	outputDrainTimeout = 3 * time.Second
	t.Cleanup(func() { outputDrainTimeout = old })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "output")
		<-s.Context().Done()
	})
	sink := newBlockedSink()
	t.Cleanup(func() { close(sink.release) })
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	asked := make(chan struct{})
	done := runStatusTerminal(t, context.Background(), door, sink, pr, answering([]string{"upterm: STATUS"}, asked))

	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("the session's output never reached the terminal")
	}
	start := time.Now()
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	awaitClosed(t, asked, "the Status hook was never asked")
	_, err = pw.Write([]byte("~."))
	require.NoError(t, err)
	res := awaitResult(t, done)
	return res, time.Since(start)
}

// runIdleMidSequenceWithStatus: the door sends "\x1b[?1000h" then
// "\x1b[?1000", pauses past the status bound while the client types "\r~?",
// then sends "l". It hands back what reached the terminal and, once Released
// has closed, the client's own mode tracker.
func runIdleMidSequenceWithStatus(t *testing.T, lines []string) (string, *uio.ModeTracker) {
	t.Helper()
	old := statusSafeTimeout
	statusSafeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { statusSafeTimeout = old })
	// The door's own copy: it is the server's goroutine, which nothing here
	// orders before the cleanup above.
	bound := statusSafeTimeout
	var modes *uio.ModeTracker
	testHookTracker = func(m *uio.ModeTracker) { modes = m }
	t.Cleanup(func() { testHookTracker = nil })

	asked := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "\x1b[?1000h")
		_, _ = io.WriteString(s, "\x1b[?1000")
		select {
		case <-asked:
		case <-s.Context().Done():
			return
		}
		time.Sleep(bound + 300*time.Millisecond)
		_, _ = io.WriteString(s, "l")
		_, _ = io.WriteString(s, "AFTER")
		<-s.Context().Done()
	})
	sink := &syncSink{}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runStatusTerminal(t, ctx, door, sink, pr, answering(lines, asked))

	waitFor(t, func() bool { return strings.Contains(sink.String(), "\x1b[?1000h\x1b[?1000") }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, func() bool { return strings.Contains(sink.String(), "AFTER") }, "the continuation never reached the terminal")
	// Room for a status that was going to follow the continuation to do so.
	time.Sleep(200 * time.Millisecond)
	cancel()
	res := awaitResult(t, done)
	select {
	case <-res.Released:
	case <-time.After(testTimeout):
		t.Fatal("Released never closed")
	}
	return sink.String(), modes
}

// statusGateSink is a terminal that parks the first write containing mark
// until release is closed, and from then on, while stopAll is set, every
// later write too. Writes land in the order they arrive: each holds the
// sink while it is parked. entered closes once the marked write is parked.
type statusGateSink struct {
	mark    string
	stopAll bool
	release chan struct{}
	entered chan struct{}

	write   sync.Mutex // held for the whole of a write, parked or not
	stopped bool       // under write

	mu  sync.Mutex
	buf bytes.Buffer
}

func newStatusGateSink(mark string, stopAll bool) *statusGateSink {
	return &statusGateSink{mark: mark, stopAll: stopAll, release: make(chan struct{}), entered: make(chan struct{})}
}

func (s *statusGateSink) Write(p []byte) (int, error) {
	if !s.stopAll {
		// Only the marked write parks, and nothing waits behind it: the
		// writes that follow it land at once.
		if bytes.Contains(p, []byte(s.mark)) {
			close(s.entered)
			<-s.release
		}
		return s.take(p)
	}
	s.write.Lock()
	defer s.write.Unlock()
	if !s.stopped && bytes.Contains(p, []byte(s.mark)) {
		s.stopped = true
		close(s.entered)
	}
	if s.stopped {
		<-s.release
	}
	return s.take(p)
}

func (s *statusGateSink) take(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *statusGateSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// runBlockedStatusThenResume: Stdout parks the status's write; the session
// writes next meanwhile, and only that write would land at once; then stdout
// resumes.
func runBlockedStatusThenResume(t *testing.T, lines []string, next string) string {
	t.Helper()
	// The bound a write that does not return is waited on for.
	old := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = old })

	writeNext := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "ready")
		select {
		case <-writeNext:
		case <-s.Context().Done():
			return
		}
		_, _ = io.WriteString(s, next)
		<-s.Context().Done()
	})
	sink := newStatusGateSink(lines[0], false)
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runStatusTerminal(t, ctx, door, sink, pr, answering(lines, make(chan struct{})))

	waitFor(t, func() bool { return strings.Contains(sink.String(), "ready") }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("the status write never reached the terminal")
	}
	close(writeNext)
	// Well past the bound, so that an output given up at it has had every
	// chance to let next through.
	time.Sleep(3 * outputDrainTimeout)
	close(sink.release)
	waitFor(t, func() bool { return strings.Contains(sink.String(), next) }, "the session's output never reached the terminal")
	cancel()
	awaitResult(t, done)
	return sink.String()
}

// runBlockedStatusThenDetach: the session sets modes; the client's status
// write blocks on Stdout, as does every write after it; the client detaches
// while it is blocked, which ends the copy. It hands back the Result, the
// terminal, and what unblocks it.
func runBlockedStatusThenDetach(t *testing.T, modes string) (Result, *statusGateSink, func()) {
	t.Helper()
	old := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = old })

	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, modes)
		<-s.Context().Done()
	})
	sink := newStatusGateSink("upterm: STATUS", true)
	var once sync.Once
	unblock := func() { once.Do(func() { close(sink.release) }) }
	t.Cleanup(unblock)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	done := runStatusTerminal(t, context.Background(), door, sink, pr, answering([]string{"upterm: STATUS"}, make(chan struct{})))

	waitFor(t, func() bool { return strings.Contains(sink.String(), modes) }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("the status write never reached the terminal")
	}
	_, err = pw.Write([]byte("~."))
	require.NoError(t, err)
	res := awaitResult(t, done)
	require.Equal(t, Detached, res.Reason)
	return res, sink, unblock
}

// runStatusReleasedAfterDetach: the Status hook blocks until released; the
// client types "~?" then "~." and Run returns. It hands back the terminal and
// what releases the hook.
func runStatusReleasedAfterDetach(t *testing.T) (*syncSink, func()) {
	t.Helper()
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "ready")
		<-s.Context().Done()
	})
	asked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	status := func(context.Context) []string {
		close(asked)
		<-release
		return []string{"upterm: STATUS"}
	}
	sink := &syncSink{}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	done := runStatusTerminal(t, context.Background(), door, sink, pr, status)

	waitFor(t, func() bool { return strings.Contains(sink.String(), "ready") }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	awaitClosed(t, asked, "the Status hook was never asked")
	_, err = pw.Write([]byte("~."))
	require.NoError(t, err)
	res := awaitResult(t, done)
	require.Equal(t, Detached, res.Reason)
	return sink, func() { once.Do(func() { close(release) }) }
}

func TestStatusLinesTakeTheOutputTurn(t *testing.T) {
	// A door that writes 1 KiB chunks of 'x' without pause; the client types
	// "\r~?" mid-flood with a Status hook returning two marker lines.
	out := runFloodWithStatus(t, []string{"upterm: STATUS-ONE", "upterm: STATUS-TWO"})
	i := strings.Index(out, "upterm: STATUS-ONE\x1b[K\r\nupterm: STATUS-TWO\x1b[K\r\n")
	require.GreaterOrEqual(t, i, 0, "status lines arrive whole and together")
}

func TestStatusNeverLandsInsideASequence(t *testing.T) {
	// The door sends "\x1b]0;tit" (an OSC split at a chunk boundary), pauses
	// while the client types "\r~?", then sends "le\x07" and more output.
	out := runSplitSequenceWithStatus(t, []string{"upterm: STATUS"})
	end := strings.Index(out, "le\x07")
	st := strings.Index(out, "upterm: STATUS")
	require.True(t, end >= 0 && st > end, "the status waits for the OSC to end: %q", out)
}

func TestABlockedTerminalNeverHoldsInput(t *testing.T) {
	// Stdout takes nothing; the client types "~?" then "~.".
	res, elapsed := runBlockedStdoutThenDetach(t)
	require.Equal(t, Detached, res.Reason)
	require.Less(t, elapsed, outputDrainTimeout+2*time.Second)
}

// Past the bound the status is dropped rather than written inside the
// sequence or after cancelling it, and the program's continuation reaches the
// terminal untouched: the terminal and the tracker agree on what it did.
func TestAContinuationAfterTheBoundReachesTheTerminalIntact(t *testing.T) {
	// The door sends "\x1b[?1000h" then "\x1b[?1000", pauses past the status
	// bound while the client types "\r~?", then sends "l".
	out, modes := runIdleMidSequenceWithStatus(t, []string{"upterm: STATUS"})
	require.NotContains(t, out, "upterm: STATUS", "dropped, never written inside the sequence")
	require.NotContains(t, out, "\x18", "no CAN")
	require.Contains(t, out, "\x1b[?1000l")
	require.NotNil(t, modes)
	require.Empty(t, modes.Restore(), "terminal and tracker agree: mouse reporting is off")
}

func TestStatusWaitsOutAnAmbiguousString(t *testing.T) {
	// The door sends "\x1bPq\x18", pauses while the client types "\r~?",
	// then sends "\x1b\\" and more output.
	out := runAmbiguousStringWithStatus(t, []string{"upterm: STATUS"})
	st := strings.Index(out, "\x1b\\")
	require.GreaterOrEqual(t, st, 0, "%q", out)
	require.Greater(t, strings.Index(out, "upterm: STATUS"), st, "%q", out)
}

// A status write owns the output until it returns, not until a deadline: the
// session's next chunk waits on it rather than racing past a write still
// parked on the terminal.
func TestABlockedStatusWriteKeepsTheOutputUntilItLands(t *testing.T) {
	// Stdout blocks while the status is written; the session writes "NEXT"
	// meanwhile; then stdout resumes.
	out := runBlockedStatusThenResume(t, []string{"upterm: STATUS"}, "NEXT")
	st := strings.Index(out, "upterm: STATUS")
	require.GreaterOrEqual(t, st, 0, "%q", out)
	require.Less(t, st, strings.Index(out, "NEXT"), "no race past the parked write: %q", out)
}

// The restore on the way out takes the turn like every other writer, so it
// is never spliced after a status write that still owns the output.
func TestTheRestoreWaitsForAStatusWriteThatOwnsTheOutput(t *testing.T) {
	// The session has set the alternate screen; a status write blocks on
	// Stdout; the copy ends and the client detaches while it is blocked.
	res, stdout, unblock := runBlockedStatusThenDetach(t, "\x1b[?1049h")
	// Within the budget the restore can't take the turn: nothing interleaves,
	// and the restore comes back as Unrestored.
	require.Contains(t, string(res.Unrestored), "\x1b[?1049l")
	select {
	case <-res.Released:
		t.Fatal("Released closed while the status write was parked")
	default:
	}
	unblock()
	select {
	case <-res.Released:
	case <-time.After(testTimeout):
		t.Fatal("Released never closed after the status write returned")
	}
	out := stdout.String()
	at := strings.Index(out, "upterm: STATUS")
	require.GreaterOrEqual(t, at, 0, "the parked status write landed once unblocked")
	require.NotContains(t, out[at:], "\x1b[?1049l", "no restore bytes spliced after the status began")
}

func TestALookupFinishingAfterDetachWritesNothing(t *testing.T) {
	// The Status hook blocks until released; the client types "~?" then "~.".
	stdout, release := runStatusReleasedAfterDetach(t)
	release()
	require.Never(t, func() bool { return strings.Contains(stdout.String(), "STATUS") }, 300*time.Millisecond, 20*time.Millisecond)
}

// Without a pty the terminal's modes aren't tracked, so there is no telling
// whether text would land inside a sequence: ~? is not offered, and both
// bytes are the session's.
func TestStatusIsNotOfferedWithoutAPty(t *testing.T) {
	door := newRecordingDoor()
	d := serveDoor(t, door.handle)
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var asked atomic.Bool
	client := dialDoor(t, d)
	done := make(chan Result, 1)
	go func() {
		res, _ := (&Terminal{Stdin: pr, Stdout: io.Discard, Escape: '~',
			Status: func(context.Context) []string { asked.Store(true); return []string{"upterm: STATUS"} },
			Logger: slog.New(slog.DiscardHandler),
		}).Run(ctx, client, time.Now().Add(testTimeout))
		done <- res
	}()
	select {
	case <-door.started:
	case <-time.After(testTimeout):
		t.Fatal("the shell never started")
	}
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, func() bool { return door.taken() == "\r~?" }, "~? did not reach the session")
	require.False(t, asked.Load())
	cancel()
	awaitResult(t, done)
}

// The status is text alone. Its lines carry what others chose, a guest's SSH
// version among them, and the tracker never sees them: a sequence in one
// would leave the terminal where the tracker doesn't know it is.
func TestStatusLinesCarryNoControls(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "ready")
		<-s.Context().Done()
	})
	sink := &syncSink{}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	line := "upterm:   guest SSH-2.0-\x1b[?1049h\x1b]0;x\x07 \x9b1m \u009b2m\r\n…"
	done := runStatusTerminal(t, ctx, door, sink, pr, answering([]string{line}, make(chan struct{})))

	waitFor(t, func() bool { return sink.String() == "ready" }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	want := "ready\r\nupterm:   guest SSH-2.0-?[?1049h?]0;x? ?1m ?2m??…\x1b[K\r\n"
	waitFor(t, func() bool { return sink.String() == want }, "the status never reached the terminal as text")
	cancel()
	awaitResult(t, done)
}

// The status is text, and text is drawn as text only where the terminal is
// in neither a character nor a graphics charset: written after half of a
// UTF-8 character it would be read as the rest of it, and written while G0
// is DEC Special Graphics, or after a shift-out, it would come out as line
// pieces. The status waits for the program to finish the character, or to
// put ASCII back.
func TestStatusWaitsOutACharacterAndAGraphicsCharset(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{"half a character", "\xe2\x94", "\x80"},
		{"DEC Special Graphics in G0", "\x1b(0", "\x1b(B"},
		{"a shift-out", "\x0e", "\x0f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runPausedWithStatus(t, tc.before, tc.after, []string{"upterm: STATUS"})
			back := strings.Index(out, tc.before+tc.after)
			require.GreaterOrEqual(t, back, 0, "%q", out)
			require.Greater(t, strings.Index(out, "upterm: STATUS"), back, "%q", out)
		})
	}
}

// The status starts a line of its own, wherever the cursor was: after a shell
// prompt, its first line would otherwise follow the prompt on the same line.
func TestStatusStartsOnALineOfItsOwn(t *testing.T) {
	out := runPausedWithStatus(t, "$ ", "", []string{"upterm: STATUS"})
	require.Contains(t, out, "$ \r\nupterm: STATUS\x1b[K\r\n")
}

// Each line erases the rest of its row before its line break: what the
// program had drawn on that row, vim's intro text among it, would otherwise
// trail the line. The erase is upterm's own, written after the line's text is
// made plain, so it is not among the controls taken out of the text.
func TestEveryStatusLineClearsTheRestOfItsRow(t *testing.T) {
	lines := []string{"upterm: ONE", "upterm: TWO", "upterm: THREE\x1b[K"}
	o := &output{statusClosing: make(chan struct{})}
	_, ok := o.offerStatus(lines)
	require.True(t, ok)
	p := string(o.status.p)
	require.Equal(t, "\r\nupterm: ONE\x1b[K\r\nupterm: TWO\x1b[K\r\nupterm: THREE?[K\x1b[K\r\n", p)
	require.Equal(t, len(lines), strings.Count(p, "\x1b[K\r\n"), "every line is followed by an erase and its break: %q", p)
	require.Equal(t, len(lines)+1, strings.Count(p, "\r\n"), "the leading break and one per line, and no other: %q", p)
	require.Equal(t, len(lines), strings.Count(p, "\x1b[K"), "an erase from a line's own text is not one: %q", p)
	o.closeStatus()
}

// A dropped status costs only that press: once the program has left the
// sequence that kept it out, ~? shows the status again.
func TestStatusWorksAgainAfterADrop(t *testing.T) {
	old := statusSafeTimeout
	statusSafeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { statusSafeTimeout = old })
	// The door's own copy, for the reason runIdleMidSequenceWithStatus takes
	// one.
	bound := statusSafeTimeout

	asked := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "\x1b[?1000")
		select {
		case <-asked:
		case <-s.Context().Done():
			return
		}
		// Past the bound, so the first status is dropped before the
		// sequence ends.
		time.Sleep(bound + 300*time.Millisecond)
		_, _ = io.WriteString(s, "l")
		_, _ = io.WriteString(s, "AFTER")
		<-s.Context().Done()
	})
	var calls atomic.Int32
	status := func(context.Context) []string {
		if calls.Add(1) == 1 {
			close(asked)
			return []string{"upterm: FIRST"}
		}
		return []string{"upterm: SECOND"}
	}
	sink := &syncSink{}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runStatusTerminal(t, ctx, door, sink, pr, status)

	waitFor(t, func() bool { return strings.Contains(sink.String(), "\x1b[?1000") }, "the session's output never reached the terminal")
	_, err := pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, func() bool { return strings.Contains(sink.String(), "AFTER") }, "the sequence's end never reached the terminal")
	_, err = pw.Write([]byte("\r~?"))
	require.NoError(t, err)
	waitFor(t, func() bool { return strings.Contains(sink.String(), "upterm: SECOND") }, "the second ~? showed nothing")
	cancel()
	awaitResult(t, done)

	out := sink.String()
	require.NotContains(t, out, "upterm: FIRST", "dropped, never written inside the sequence")
	require.Greater(t, strings.Index(out, "upterm: SECOND"), strings.Index(out, "\x1b[?1000lAFTER"), "%q", out)
}

// One offer at a time: an offer made while another still waits in the slot is
// refused, and the one waiting stays, still to be written or dropped.
func TestOfferStatusRefusesAnOfferWhileOneWaits(t *testing.T) {
	o := &output{statusClosing: make(chan struct{})}
	first, ok := o.offerStatus([]string{"upterm: ONE"})
	require.True(t, ok)
	second, ok := o.offerStatus([]string{"upterm: TWO"})
	require.False(t, ok, "the slot is full")
	require.Nil(t, second)
	select {
	case <-first:
		t.Fatal("the waiting offer was let go")
	default:
	}
	require.Equal(t, "\r\nupterm: ONE\x1b[K\r\n", string(o.status.p))

	o.closeStatus()
	awaitClosed(t, first, "closing the slot did not let the waiting offer go")
}

// The restore is written whenever the turn is free, however little of the
// tail's budget is left: only a status write still holding the output is a
// reason to give it up. With the budget spent as the copy ends, the copy's
// end and the timer are ready together, many times over.
func TestTheRestoreIsNotGivenUpWhileTheTurnIsFree(t *testing.T) {
	old := outputDrainTimeout
	outputDrainTimeout = time.Nanosecond
	t.Cleanup(func() { outputDrainTimeout = old })

	for i := range 50 {
		door := serveDoor(t, func(s gssh.Session) {
			_, _ = io.WriteString(s, "\x1b[?1049h")
			_ = s.Exit(0)
		})
		logs := &syncSink{}
		res, err := (&Terminal{Stdout: io.Discard, Escape: '~',
			Pty:    &Pty{Term: "xterm", Size: termsize.Default},
			Logger: slog.New(slog.NewTextHandler(logs, nil)),
		}).Run(context.Background(), dialDoor(t, door), time.Now().Add(testTimeout))
		require.NoError(t, err)
		awaitClosed(t, res.Released, "Released never closed")
		require.NotContains(t, logs.String(), "a status write still holds the output", "run %d: no status write was ever made", i)
	}
}
