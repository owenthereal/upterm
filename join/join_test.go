package join

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestEveryOutcomeRow(t *testing.T) {
	noHost := fmt.Sprintf(upterm.BannerNoHostFormat, "abc")
	wantDeadline := func(why WaitReason) func(*testing.T, Outcome, *recorder) {
		return func(t *testing.T, out Outcome, _ *recorder) {
			var dl *DeadlineError
			require.ErrorAs(t, out.Err, &dl)
			require.Equal(t, why, dl.Why)
		}
	}
	wantErr := func(target error) func(*testing.T, Outcome, *recorder) {
		return func(t *testing.T, out Outcome, _ *recorder) { require.ErrorIs(t, out.Err, target) }
	}
	for name, tc := range map[string]struct {
		scripts []relayKnobs
		opts    []option
		check   func(*testing.T, Outcome, *recorder)
	}{
		"exit status": {[]relayKnobs{{exit: intp(7)}}, nil, func(t *testing.T, out Outcome, _ *recorder) {
			require.Equal(t, Outcome{Kind: Exited, Status: 7}, out)
		}},
		"lost, then rejoined": {[]relayKnobs{{dropAfterReady: true}, {exit: intp(0)}}, nil, func(t *testing.T, out Outcome, rec *recorder) {
			require.Equal(t, Exited, out.Kind)
			require.Equal(t, []EventKind{Joined, Lost, Waiting, Joined}, rec.kinds())
		}},
		"no host":                 {[]relayKnobs{{refuseAll: true, banner: noHost}}, nil, wantDeadline(NoHost)},
		"lookup failed":           {[]relayKnobs{{refuseAll: true, banner: upterm.BannerLookupFailed}}, nil, wantDeadline(RelayLookup)},
		"upstream unavailable":    {[]relayKnobs{{rejectSession: upterm.UpstreamUnavailable}}, nil, wantDeadline(Upstream)},
		"upstream has no session": {[]relayKnobs{{rejectSession: upterm.UpstreamNoHost}}, nil, wantDeadline(NoHost)},
		"upstream lookup failed":  {[]relayKnobs{{rejectSession: upterm.UpstreamLookupFailed}}, nil, wantDeadline(RelayLookup)},
		"unknown channel text":    {[]relayKnobs{{rejectSession: "something new"}}, nil, wantDeadline(Setup)},
		"unreachable":             {[]relayKnobs{{dropOnPublicKey: true}}, nil, wantDeadline(Unreachable)},
		"refused":                 {[]relayKnobs{{refuseAll: true}}, nil, wantErr(ErrKeysRefused)},
		"changed relay key":       {[]relayKnobs{{hostKeyChanged: true}}, nil, wantErr(ErrHostKey)},
		"upstream host key":       {[]relayKnobs{{rejectSession: upterm.UpstreamHostKeyMismatch}}, nil, wantErr(ErrUpstreamHostKey)},
		"sign fails, first join":  {[]relayKnobs{{}}, []option{withSigners(failingSigner{newSigner(t)})}, wantErr(ErrIdentity)},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			relay := newFakeRelay(t, tc.scripts...)
			tc.check(t, runJoin(t, config(t, relay, append(tc.opts, withEvents(rec))...)), rec)
		})
	}
	t.Run("~. leaves", func(t *testing.T) {
		pr, pw := io.Pipe()
		rec := &recorder{}
		done := runJoinAsync(t, context.Background(), config(t, newFakeRelay(t, relayKnobs{}), withInput(pr), withEvents(rec)))
		<-rec.held() // Joined
		_, _ = pw.Write([]byte("\r~."))
		require.Equal(t, Left, (<-done).Kind)
	})
	t.Run("cancelled is stopped", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rec := &recorder{}
		done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{}), withEvents(rec)))
		<-rec.held()
		cancel()
		require.Equal(t, Stopped, (<-done).Kind)
	})
	t.Run("sign fails on a rejoin", func(t *testing.T) {
		var n atomic.Int32
		id := Identity{
			Signers: func(context.Context) ([]ssh.Signer, func(), error) {
				if n.Add(1) == 1 {
					return []ssh.Signer{newSigner(t)}, func() {}, nil
				}
				return []ssh.Signer{failingSigner{newSigner(t)}}, func() {}, nil
			},
			Source: KeySource{Agent: 1},
		}
		rec := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{}), withIdentity(id), withEvents(rec)))
		for e := range rec.held() {
			if e.Kind == Waiting && e.Why == IdentityFailure && !e.First {
				break
			}
		}
		cancel()
		require.Equal(t, Stopped, (<-done).Kind)
	})
}

func TestTheFirstJoinDeadlineIsExact(t *testing.T) {
	for name, k := range map[string]relayKnobs{
		"no host":           {refuseAll: true, banner: fmt.Sprintf(upterm.BannerNoHostFormat, "abc")},
		"a stalled attempt": {stallHandshake: true}, // its deadline is cut to what's left
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			out := runJoin(t, config(t, newFakeRelay(t, k))) // FirstJoin 300 ms, Attempt 200 ms
			var dl *DeadlineError
			require.ErrorAs(t, out.Err, &dl)
			require.InDelta(t, 300, time.Since(start).Milliseconds(), 60)
		})
	}
	t.Run("--wait never fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rec := &recorder{}
		done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: fmt.Sprintf(upterm.BannerNoHostFormat, "abc")}), withWait(), withEvents(rec)))
		require.Never(t, func() bool { return len(done) > 0 }, time.Second, 50*time.Millisecond)
		cancel()
		require.Equal(t, Stopped, (<-done).Kind)
	})
}

func TestAKeyRefusedUpstreamIsRetriedWithoutIt(t *testing.T) {
	bad, good := newSigner(t), newSigner(t)
	relay := newFakeRelay(t, relayKnobs{acceptUpstreamOnly: good.PublicKey(), confirmRefusal: true, exit: intp(0)})
	rec := &recorder{}
	out := runJoin(t, config(t, relay, withSigners(bad, good), withEvents(rec)))
	require.Equal(t, Exited, out.Kind)
	require.Equal(t, 2, relay.connections()) // one per key, no schedule wait
	require.NotContains(t, rec.kinds(), Waiting)
	require.Equal(t, good.PublicKey().Marshal(), relay.authenticatedWith(1).Marshal())

	relay = newFakeRelay(t, relayKnobs{acceptUpstreamOnly: newSigner(t).PublicKey(), confirmRefusal: true}) // no key will do
	out = runJoin(t, config(t, relay, withSigners(bad, good)))
	require.ErrorIs(t, out.Err, ErrKeysRefused)
	require.Equal(t, 2, relay.connections())
}

func TestAnAmbiguousRefusalOfAKeyThatGotInIsNoSession(t *testing.T) {
	key := newSigner(t)
	relay := newFakeRelay(t,
		relayKnobs{dropAfterReady: true},                         // key gets in; the host goes away
		relayKnobs{acceptUpstreamOnly: newSigner(t).PublicKey()}, // UpstreamAuthFailed: refused, or no session
		relayKnobs{exit: intp(0)})                                // the host is back
	rec := &recorder{}
	out := runJoin(t, config(t, relay, withSigners(key), withEvents(rec)))
	require.Equal(t, Exited, out.Kind)
	require.Equal(t, []EventKind{Joined, Lost, Waiting, Waiting, Joined}, rec.kinds())
}

func TestAnAmbiguousRoundIsNotPermanent(t *testing.T) {
	a, b := newSigner(t), newSigner(t)
	nobody := newSigner(t).PublicKey() // a key no guest offers

	t.Run("a first join's round", func(t *testing.T) {
		// Both keys get the ambiguous text: RefusedError{Ambiguous}.
		relay := newFakeRelay(t, relayKnobs{acceptUpstreamOnly: nobody})
		out := runJoin(t, config(t, relay, withSigners(a, b)))
		var refused *RefusedError
		require.ErrorAs(t, out.Err, &refused)
		require.True(t, refused.Ambiguous)
		require.Equal(t, 2, relay.connections())
	})

	t.Run("a ready session ends the round", func(t *testing.T) {
		relay := newFakeRelay(t,
			relayKnobs{acceptUpstreamOnly: b.PublicKey()},                       // a: ambiguous, sits out
			relayKnobs{acceptUpstreamOnly: b.PublicKey(), dropAfterReady: true}, // b in; the round ends
			relayKnobs{acceptUpstreamOnly: nobody},                              // a offered again: ambiguous, sits out
			relayKnobs{acceptUpstreamOnly: nobody},                              // b: ambiguous, but b got in: no host
			relayKnobs{acceptUpstreamOnly: b.PublicKey(), exit: intp(0)})        // b, the host is back
		require.Equal(t, Exited, runJoin(t, config(t, relay, withSigners(a, b))).Kind)
		require.Equal(t, a.PublicKey().Marshal(), relay.authenticatedWith(2).Marshal())
		require.Equal(t, b.PublicKey().Marshal(), relay.authenticatedWith(4).Marshal())
		require.Equal(t, 5, relay.connections())
	})

	t.Run("an exhausted round on a rejoin waits and starts over", func(t *testing.T) {
		// The agent's keys change between sessions: b, then a.
		var n atomic.Int32
		id := Identity{
			Signers: func(context.Context) ([]ssh.Signer, func(), error) {
				if n.Add(1) == 1 {
					return []ssh.Signer{b}, func() {}, nil
				}
				return []ssh.Signer{a}, func() {}, nil
			},
			Source: KeySource{Agent: 1},
		}
		relay := newFakeRelay(t,
			relayKnobs{acceptUpstreamOnly: b.PublicKey(), dropAfterReady: true}, // b in, then dropped
			relayKnobs{acceptUpstreamOnly: nobody},                              // a: ambiguous; the round is exhausted
			relayKnobs{acceptUpstreamOnly: a.PublicKey(), exit: intp(0)})        // a offered again
		rec := &recorder{}
		require.Equal(t, Exited, runJoin(t, config(t, relay, withIdentity(id), withEvents(rec))).Kind)
		require.Equal(t, []EventKind{Joined, Lost, Waiting, Waiting, Joined}, rec.kinds())
		require.Equal(t, NoHost, rec.waits()[1].Why)
		require.Equal(t, 3, relay.connections())
	})
}

func TestAConfirmedRefusalIsPermanentForTheKey(t *testing.T) {
	a, b := newSigner(t), newSigner(t)
	relay := newFakeRelay(t,
		relayKnobs{acceptUpstreamOnly: b.PublicKey(), confirmRefusal: true},                       // a refused (stated)
		relayKnobs{acceptUpstreamOnly: b.PublicKey(), confirmRefusal: true, dropAfterReady: true}, // b in, then dropped
		relayKnobs{acceptUpstreamOnly: b.PublicKey(), confirmRefusal: true, exit: intp(0)})        // the rejoin
	require.Equal(t, Exited, runJoin(t, config(t, relay, withSigners(a, b))).Kind)
	// The rejoin never offered a again.
	require.Equal(t, b.PublicKey().Marshal(), relay.authenticatedWith(2).Marshal())
	require.Equal(t, 3, relay.connections())
}

func TestAnEntryRefusalWithoutEvidenceWaitsOnARejoin(t *testing.T) {
	for _, version := range []string{"SSH-2.0-uptermd-0.33.0", "SSH-2.0-uptermd-0.0.0+dev", "SSH-2.0-uptermd-dev"} {
		key := newSigner(t)
		relay := newFakeRelay(t,
			relayKnobs{version: version, dropAfterReady: true},
			relayKnobs{version: version, refuseAll: true}, // no banner: refused, or no session
			relayKnobs{version: version, exit: intp(0)})
		rec := &recorder{}
		out := runJoin(t, config(t, relay, withSigners(key), withEvents(rec)))
		require.Equal(t, Exited, out.Kind, version)
		require.Equal(t, []EventKind{Joined, Lost, Waiting, Waiting, Joined}, rec.kinds(), version)
	}
}

func TestNoPromptOnceTheTerminalIsTaken(t *testing.T) {
	confirm := &countingConfirm{accept: true}
	took := 0
	relay := newFakeRelay(t, relayKnobs{setupFails: true}, relayKnobs{hostKeyUnknown: true})
	out := runJoin(t, config(t, relay, withConfirm(confirm), withTakeTerminal(func() error { took++; return nil })))
	require.ErrorIs(t, out.Err, ErrHostKey)
	require.Zero(t, confirm.calls())
	require.Equal(t, 1, took)
}

func TestPromptHappensWithNoConnectionOpen(t *testing.T) {
	relay := newFakeRelay(t, relayKnobs{hostKeyUnknown: true}, relayKnobs{exit: intp(0)})
	confirm := &countingConfirm{accept: true, during: func() { require.False(t, relay.connOpen(0)) }}
	require.Equal(t, Exited, runJoin(t, config(t, relay, withConfirm(confirm))).Kind)
	require.Equal(t, 1, confirm.calls())
}

func TestPromptTimeDoesNotCountAgainstTheFirstJoin(t *testing.T) {
	relay := newFakeRelay(t, relayKnobs{hostKeyUnknown: true}, relayKnobs{exit: intp(0)})
	// The guest takes 500 ms over the fingerprint; FirstJoin is 300 ms.
	slow := &countingConfirm{accept: true, during: func() { time.Sleep(500 * time.Millisecond) }}
	require.Equal(t, Exited, runJoin(t, config(t, relay, withConfirm(slow))).Kind)
}

func TestAPromptEndsWithTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocking := &countingConfirm{block: true}
	done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{hostKeyUnknown: true}), withConfirm(blocking)))
	<-blocking.called()
	cancel()
	select {
	case out := <-done:
		require.Equal(t, Stopped, out.Kind)
	case <-time.After(50 * time.Millisecond):
		t.Fatal("a cancelled run kept waiting on the prompt")
	}
}

func TestNoOutputWhileAStatusLineIsBeingWritten(t *testing.T) {
	out := &syncSink{}
	rec := &recorder{gate: make(chan struct{}), w: out}
	relay := newFakeRelay(t, relayKnobs{output: "REPLAY", exit: intp(0)})
	done := runJoinAsync(t, context.Background(), config(t, relay, withEvents(rec), withStdout(out)))
	require.Equal(t, Joined, (<-rec.held()).Kind) // the Joined line's write is held
	require.Never(t, func() bool { return strings.Contains(out.String(), "REPLAY") }, 100*time.Millisecond, 10*time.Millisecond)
	close(rec.gate)
	require.Equal(t, Exited, (<-done).Kind)
	require.True(t, strings.HasPrefix(out.String(), "<JOINED>REPLAY"), "%q", out.String())

	// Ctrl-C while a status write is held still stops the run.
	pr, pw := io.Pipe()
	rec2 := &recorder{gate: make(chan struct{})}
	done2 := runJoinAsync(t, context.Background(),
		config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}), withEvents(rec2), withInput(pr)))
	for e := range rec2.held() {
		if e.Kind == Lost {
			break
		}
		rec2.gate <- struct{}{} // let Joined through
	}
	_, _ = pw.Write([]byte{0x03})
	require.Equal(t, Stopped, (<-done2).Kind)
}

func TestCtrlCStopsEveryStalledPhase(t *testing.T) {
	stopsWithin := func(t *testing.T, cfg Config, pw *io.PipeWriter, ready func()) {
		done := runJoinAsync(t, context.Background(), cfg)
		ready()
		_, _ = pw.Write([]byte{0x03})
		select {
		case out := <-done:
			require.Equal(t, Stopped, out.Kind)
		case <-time.After(50 * time.Millisecond):
			t.Fatal("Ctrl-C didn't stop the run")
		}
	}
	t.Run("a stalled handshake on a rejoin", func(t *testing.T) {
		pr, pw := io.Pipe()
		relay := newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{stallHandshake: true})
		cfg := config(t, relay, withInput(pr))
		cfg.Timing.Attempt = time.Hour // only Ctrl-C can end it
		stopsWithin(t, cfg, pw, func() {
			require.Eventually(t, func() bool { return relay.connections() == 2 }, testTimeout, time.Millisecond)
		})
	})
	t.Run("a stalled agent on a rejoin", func(t *testing.T) {
		pr, pw := io.Pipe()
		var n atomic.Int32
		signing := make(chan struct{})
		id := Identity{
			Signers: func(ctx context.Context) ([]ssh.Signer, func(), error) {
				if n.Add(1) == 1 {
					return []ssh.Signer{newSigner(t)}, func() {}, nil
				}
				release := make(chan struct{})
				return []ssh.Signer{blockingSigner{Signer: newSigner(t), until: release, entered: signing}}, sync.OnceFunc(func() { close(release) }), nil
			},
			Source: KeySource{Agent: 1},
		}
		cfg := config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{}), withInput(pr), withIdentity(id))
		cfg.Timing.Attempt = time.Hour
		stopsWithin(t, cfg, pw, func() { <-signing })
	})
	t.Run("a blocked Joined line", func(t *testing.T) {
		pr, pw := io.Pipe()
		rec := &recorder{gate: make(chan struct{})} // never opened
		relay := newFakeRelay(t, relayKnobs{})
		stopsWithin(t, config(t, relay, withInput(pr), withEvents(rec)), pw, func() { require.Equal(t, Joined, (<-rec.held()).Kind) })
		require.Empty(t, relay.input(0), "the Ctrl-C reached a session that wasn't ready")
	})
	t.Run("a blocked Joined line with the replay in", func(t *testing.T) {
		pr, pw := io.Pipe()
		rec := &recorder{gate: make(chan struct{})} // never opened
		stuck := newStuckWriter(t)                  // a terminal that isn't taking output, as the Joined line found
		relay := newFakeRelay(t, relayKnobs{output: "REPLAY", outputFirst: true})
		cfg := config(t, relay, withInput(pr), withEvents(rec), withStdout(stuck))
		stopsWithin(t, cfg, pw, func() { require.Equal(t, Joined, (<-rec.held()).Kind) })
		require.Zero(t, stuck.offered.Load(), "a session whose start was stopped wrote to the terminal")
	})
}

func TestAFinalOutcomeDoesNotWaitOnAParkedWrite(t *testing.T) {
	never := make(chan struct{}) // Released never closes
	relay := newFakeRelay(t, relayKnobs{})
	cfg := config(t, relay)
	cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
		return attach.Result{Reason: attach.Exited, Status: 5, Released: never, Unrestored: []byte("\x1b[?1049l")}, nil
	}
	start := time.Now()
	require.Equal(t, Outcome{Kind: Exited, Status: 5}, runJoin(t, cfg))
	require.Less(t, time.Since(start), 1500*time.Millisecond)
}

func TestAFinalOutcomeRestoresAfterTheParkedWrite(t *testing.T) {
	sink := &syncSink{}
	gate := make(chan struct{})
	cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(sink))
	cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
		released := make(chan struct{})
		go func() { // a write parked on the terminal, which lands once let go
			<-gate
			_, _ = sink.Write([]byte("PARKED"))
			close(released)
		}()
		return attach.Result{Reason: attach.Exited, Released: released, Unrestored: []byte("R")}, nil
	}
	done := runJoinAsync(t, context.Background(), cfg)
	require.Never(t, func() bool { return sink.String() != "" }, 100*time.Millisecond, 10*time.Millisecond)
	close(gate)
	require.Equal(t, Exited, (<-done).Kind)
	require.Equal(t, "PARKEDR", sink.String())
}

func TestTheNextSessionWaitsForTheLastOnesWrites(t *testing.T) {
	released := make(chan struct{})
	relay := newFakeRelay(t, relayKnobs{}, relayKnobs{})
	out := &syncSink{}
	rec := &recorder{w: out}
	cfg := config(t, relay, withStdout(out), withEvents(rec))
	var runs atomic.Int32
	cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
		if runs.Add(1) == 1 {
			return attach.Result{Reason: attach.Disconnected, Released: released, Unrestored: []byte("\x1b[?1049l")}, nil
		}
		_, _ = out.Write([]byte("NEXT"))
		done := make(chan struct{})
		close(done)
		return attach.Result{Reason: attach.Exited, Released: done}, nil
	}
	result := runJoinAsync(t, context.Background(), cfg)
	// Neither the next attempt nor the line saying the session was lost comes
	// before the last session's parked write: the line would land on the
	// screen the restore then leaves.
	require.Never(t, func() bool { return relay.connections() > 1 || len(rec.kinds()) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
	close(released)
	require.Equal(t, Exited, (<-result).Kind)
	require.Equal(t, "\x1b[?1049l<LOST><WAITING>NEXT", out.String())
}

func TestAStopStillRestoresAfterTheParkedWrite(t *testing.T) {
	t.Run("while the write is parked", func(t *testing.T) {
		sink := &syncSink{}
		gate := make(chan struct{})
		lost := make(chan struct{})
		cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(sink))
		cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
			released := make(chan struct{})
			go func() { // a write parked on the terminal, which lands once let go
				<-gate
				_, _ = sink.Write([]byte("PARKED"))
				close(released)
			}()
			close(lost)
			return attach.Result{Reason: attach.Disconnected, Released: released, Unrestored: []byte("R")}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, cfg)
		<-lost
		cancel()
		// Stopping, the run still waits, within its bound, to put the terminal back.
		require.Never(t, func() bool { return len(done) > 0 || sink.String() != "" }, 100*time.Millisecond, 10*time.Millisecond)
		close(gate)
		require.Equal(t, Stopped, (<-done).Kind)
		require.Equal(t, "PARKEDR", sink.String())
	})
	t.Run("while the restore is being written", func(t *testing.T) {
		term := &heldWriter{entered: make(chan struct{}), let: make(chan struct{})}
		cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(term))
		cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
			released := make(chan struct{})
			close(released)
			return attach.Result{Reason: attach.Disconnected, Released: released, Unrestored: []byte("R")}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, cfg)
		<-term.entered // the hand-over between sessions is writing the restore
		cancel()
		require.Never(t, func() bool { return len(done) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
		close(term.let)
		require.Equal(t, Stopped, (<-done).Kind)
		require.Equal(t, "R", term.String())
	})
}

func TestResizesBetweenSessionsAreDropped(t *testing.T) {
	first, now, stale := termsize.Size{Rows: 24, Cols: 80}, termsize.Size{Rows: 43, Cols: 132}, termsize.Size{Rows: 10, Cols: 20}
	var n atomic.Int32
	resizes := make(chan termsize.Size, 1)
	rec := &recorder{}
	relay := newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{})
	cfg := config(t, relay, withSize(func() termsize.Size {
		if n.Add(1) == 1 {
			return first
		}
		return now
	}))
	cfg.Terminal.Resizes = resizes
	cfg.Events = func(e Event) {
		if e.Kind == Lost {
			select {
			case resizes <- stale: // the terminal resized while no session had it
			default:
			}
		}
		rec.event(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runJoinAsync(t, ctx, cfg)
	for e := range rec.held() {
		if e.Kind == Joined && e.Rejoin {
			break
		}
	}
	require.Never(t, func() bool { return len(relay.windowChanges(1)) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
	cancel()
	require.Equal(t, Stopped, (<-done).Kind)
	require.Equal(t, []termsize.Size{first, now}, relay.ptySizes())
}

func TestPtySizeIsMeasuredForEachSession(t *testing.T) {
	sizes := []termsize.Size{{Rows: 24, Cols: 80}, {Rows: 43, Cols: 132}}
	var n atomic.Int32
	relay := newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{exit: intp(0)})
	runJoin(t, config(t, relay, withSize(func() termsize.Size { return sizes[min(int(n.Add(1))-1, 1)] })))
	require.Equal(t, sizes, relay.ptySizes())
}

func TestTakeTerminalOnceAndNeverBeforeAHandshake(t *testing.T) {
	took := 0
	take := withTakeTerminal(func() error { took++; return nil })
	runJoin(t, config(t, newFakeRelay(t, relayKnobs{refuseAll: true}), take))
	require.Zero(t, took)
	runJoin(t, config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{exit: intp(0)}), take))
	require.Equal(t, 1, took)
}

func TestASilentPeerIsLostNotLeft(t *testing.T) { // liveness 50 ms + 50 ms
	rec := &recorder{}
	start := time.Now()
	out := runJoin(t, config(t, newFakeRelay(t, relayKnobs{silentAfterReady: true}, relayKnobs{exit: intp(0)}), withEvents(rec)))
	require.Equal(t, Exited, out.Kind)
	require.Equal(t, []EventKind{Joined, Lost, Waiting, Joined}, rec.kinds())
	require.Less(t, time.Since(start), time.Second)
}

func TestAStalledAgentCostsAtMostTheAttempt(t *testing.T) {
	release := make(chan struct{})
	id := Identity{
		Signers: func(context.Context) ([]ssh.Signer, func(), error) {
			return []ssh.Signer{blockingSigner{Signer: newSigner(t), until: release}}, sync.OnceFunc(func() { close(release) }), nil
		},
		Source: KeySource{Agent: 1},
	}
	start := time.Now()
	out := runJoin(t, config(t, newFakeRelay(t, relayKnobs{}), withIdentity(id))) // Attempt 200 ms
	require.ErrorIs(t, out.Err, ErrIdentity)                                      // a first join stops on it
	require.Less(t, time.Since(start), 200*time.Millisecond+100*time.Millisecond)
}
