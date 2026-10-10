package join

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
		require.Equal(t, Joined, recv(t, rec.held()).Kind)
		press(pw, "\r~.")
		require.Equal(t, Left, recv(t, done).Kind)
	})
	t.Run("cancelled is stopped", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rec := &recorder{}
		done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{}), withEvents(rec)))
		require.Equal(t, Joined, recv(t, rec.held()).Kind)
		cancel()
		require.Equal(t, Stopped, recv(t, done).Kind)
	})
	t.Run("sign fails on a rejoin", func(t *testing.T) {
		good, bad := newSigner(t), failingSigner{newSigner(t)}
		var joined atomic.Bool
		id := Identity{
			// The key signs until a session has been ready, however many
			// attempts that takes, and fails from then on.
			Signers: func(context.Context) ([]ssh.Signer, func(), error) {
				if joined.Load() {
					return []ssh.Signer{bad}, func() {}, nil
				}
				return []ssh.Signer{good}, func() {}, nil
			},
			Source: KeySource{Agent: 1},
		}
		rec := &recorder{}
		cfg := config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{}), withIdentity(id), withWait())
		cfg.Events = func(e Event) {
			if e.Kind == Joined {
				joined.Store(true)
			}
			rec.event(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, cfg)
		e := rec.await(t, done, func(e Event) bool { return e.Kind == Waiting && e.Why == IdentityFailure })
		require.False(t, e.First)
		require.ErrorIs(t, e.Err, ErrIdentity)
		cancel()
		require.Equal(t, Stopped, recv(t, done).Kind)
	})
}

func TestTheFirstJoinDeadlineIsExact(t *testing.T) {
	for name, k := range map[string]relayKnobs{
		"no host":           {refuseAll: true, banner: noHostBanner},
		"a stalled attempt": {stallHandshake: true},
	} {
		t.Run(name, func(t *testing.T) {
			relay := newFakeRelay(t, k)
			cfg := config(t, relay) // FirstJoin 300 ms
			// An attempt's own deadline is an hour away: only the first join's
			// can be what ends one.
			cfg.Timing.Attempt = time.Hour
			var (
				mu        sync.Mutex
				deadlines []time.Time // each attempt's connect deadline
			)
			// The first attempt's dial: when, and with what deadline.
			type dial struct{ at, deadline time.Time }
			firstDial := make(chan dial, 1)
			cfg.Dial = func(ctx context.Context) (net.Conn, error) {
				d, _ := ctx.Deadline()
				mu.Lock()
				if len(deadlines) == 0 {
					firstDial <- dial{time.Now(), d}
				}
				deadlines = append(deadlines, d)
				mu.Unlock()
				return relay.Dial(ctx)
			}
			start := time.Now()
			done := runJoinAsync(t, context.Background(), cfg)

			// The first attempt starts between start and its dial. The first
			// join's deadline, which is the attempt's own too, is FirstJoin
			// after that start.
			first := recv(t, firstDial)
			require.False(t, first.deadline.Before(start.Add(cfg.Timing.FirstJoin)), "%v is before the first join's deadline", first.deadline)
			require.False(t, first.deadline.After(first.at.Add(cfg.Timing.FirstJoin)), "%v is after the first join's deadline", first.deadline)

			deadlineOf(t, recv(t, done))
			// A loose ceiling: the exact figure is the deadlines.
			require.Less(t, time.Since(start), cfg.Timing.FirstJoin+5*time.Second)
			// Every later attempt's connect deadline is what is left of the
			// first join's: an attempt started at 28 s of 30 gets 2 s.
			mu.Lock()
			defer mu.Unlock()
			for i, d := range deadlines {
				require.True(t, d.Equal(first.deadline), "attempt %d's deadline %v is not the first join's, %v", i, d, first.deadline)
			}
		})
	}
	t.Run("--wait never fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withWait()))
		require.Never(t, func() bool { return len(done) > 0 }, time.Second, 50*time.Millisecond)
		cancel()
		require.Equal(t, Stopped, recv(t, done).Kind)
	})
}

// A first join whose time runs out wraps the last reason it had, never what
// the cut did to the attempt it ended.
func TestATimedOutFirstJoinSaysWhatItWasWaitingOn(t *testing.T) {
	// With an attempt's own deadline an hour away, the first join's is what
	// ends the last attempt.
	cutting := func(cfg Config) Config {
		cfg.Timing.Attempt = time.Hour
		return cfg
	}
	t.Run("a setup cut by its own timer", func(t *testing.T) {
		// Terminal's setup timer and the attempt's ctx end at the same moment,
		// in either order.
		relay := newFakeRelay(t, relayKnobs{rejectSession: upterm.UpstreamUnavailable}, relayKnobs{stallSetup: true})
		require.Equal(t, Upstream, deadlineOf(t, runJoin(t, cutting(config(t, relay)))).Why)

		// With nothing waited on, it is the deadline, not the close of the
		// connection that the timer made.
		dl := deadlineOf(t, runJoin(t, cutting(config(t, newFakeRelay(t, relayKnobs{stallSetup: true})))))
		require.Equal(t, Setup, dl.Why)
		require.ErrorIs(t, dl, context.DeadlineExceeded)
	})
	t.Run("a handshake cut with nothing waited on", func(t *testing.T) {
		dl := deadlineOf(t, runJoin(t, cutting(config(t, newFakeRelay(t, relayKnobs{stallHandshake: true})))))
		require.Equal(t, Unreachable, dl.Why)
		require.ErrorIs(t, dl, context.DeadlineExceeded)
	})
	t.Run("an attempt that ended after the time ran out", func(t *testing.T) {
		// The attempt's own deadline comes before the first join's, so nothing
		// cuts it; its setup overruns both.
		const firstJoin = time.Second
		cfg := config(t, newFakeRelay(t, relayKnobs{}))
		cfg.Timing.FirstJoin = firstJoin // Attempt 200 ms
		var first time.Time              // the first session's start, after the first join's deadline was set
		cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
			if first.IsZero() {
				first = time.Now()
				return attach.Result{}, rejectedWith(upterm.UpstreamUnavailable)
			}
			<-time.After(time.Until(first.Add(firstJoin)))
			return attach.Result{}, errors.New("attach: the shell never started")
		}
		require.Equal(t, Upstream, deadlineOf(t, runJoin(t, cfg)).Why)
	})
	t.Run("keys tried again at once", func(t *testing.T) {
		for msg, why := range map[string]WaitReason{
			upterm.UpstreamKeyRefused: Setup,  // the session wouldn't start
			upterm.UpstreamAuthFailed: NoHost, // refused, or no session
		} {
			cfg := config(t, newFakeRelay(t, relayKnobs{}), withSigners(newSigner(t), newSigner(t)))
			// The session's node turns the first key away once the first
			// join's time is up, which leaves the second key untried.
			firstJoin := cfg.Timing.FirstJoin
			cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
				<-time.After(firstJoin)
				return attach.Result{}, rejectedWith(msg)
			}
			require.Equal(t, why, deadlineOf(t, runJoin(t, cfg)).Why, msg)
		}
	})
}

func TestAWallClockJumpDoesNotSlowTheSchedule(t *testing.T) {
	base := time.Now().Round(0)
	var jumped atomic.Bool
	rec := &recorder{gate: make(chan struct{})}
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withWait(), withEvents(rec))
	cfg.Timing.Wall = func() time.Time {
		if jumped.Load() {
			return base.Add(time.Hour)
		}
		return base
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runJoinAsync(t, ctx, cfg)
	require.Equal(t, Waiting, recv(t, rec.held()).Kind)
	jumped.Store(true) // the lid opens an hour later, while the join waits
	rec.gate <- struct{}{}
	next := recv(t, rec.held())
	close(rec.gate)
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)

	require.Equal(t, Waiting, next.Kind)
	require.False(t, next.Long, "an hour on the wall clock is not an hour of waiting")
	require.LessOrEqual(t, next.Next.Sub(base.Add(time.Hour)), cfg.Timing.FastCap, "the wait after the jump left the fast tier")
}

func TestNoStatusLineAfterAStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recorder{}
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withEvents(rec))
	// The run is stopped as its first wait begins: the wait reads the wall
	// clock before it tells the guest about itself.
	var once sync.Once
	cfg.Timing.Wall = func() time.Time {
		once.Do(cancel)
		return time.Now().Round(0)
	}
	require.Equal(t, Stopped, recv(t, runJoinAsync(t, ctx, cfg)).Kind)
	require.Never(t, func() bool { return len(rec.kinds()) > 0 }, 100*time.Millisecond, 10*time.Millisecond,
		"a status line was begun after the stop")
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
	var open atomic.Bool // whether the connection was open as the guest was asked
	confirm := &countingConfirm{accept: true, during: func() { open.Store(relay.connOpen(0)) }}
	require.Equal(t, Exited, runJoin(t, config(t, relay, withConfirm(confirm))).Kind)
	require.Equal(t, 1, confirm.calls())
	require.False(t, open.Load(), "the guest was asked with the connection open")
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
	recv(t, blocking.called())
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
	require.Equal(t, Joined, recv(t, rec.held()).Kind) // the Joined line's write is held
	require.Never(t, func() bool { return strings.Contains(out.String(), "REPLAY") }, 100*time.Millisecond, 10*time.Millisecond)
	close(rec.gate)
	require.Equal(t, Exited, recv(t, done).Kind)
	require.True(t, strings.HasPrefix(out.String(), "<JOINED>REPLAY"), "%q", out.String())

	// Ctrl-C while a status write is held still stops the run.
	pr, pw := io.Pipe()
	rec2 := &recorder{gate: make(chan struct{})}
	done2 := runJoinAsync(t, context.Background(),
		config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}), withEvents(rec2), withInput(pr), withWait()))
	for e := recv(t, rec2.held()); e.Kind != Lost; e = recv(t, rec2.held()) {
		rec2.gate <- struct{}{} // let Joined, or a wait before it, through
	}
	press(pw, "\x03")
	require.Equal(t, Stopped, recv(t, done2).Kind)
}

func TestCtrlCStopsEveryStalledPhase(t *testing.T) {
	stopsWithin := func(t *testing.T, cfg Config, pw *io.PipeWriter, ready func()) {
		done := runJoinAsync(t, context.Background(), cfg)
		ready()
		press(pw, "\x03")
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
		cfg := config(t, relay, withInput(pr), withWait())
		cfg.Timing.Attempt = time.Hour // only Ctrl-C can end it
		stopsWithin(t, cfg, pw, func() {
			require.Eventually(t, func() bool { return relay.connections() == 2 }, testTimeout, time.Millisecond)
		})
	})
	t.Run("a stalled agent on a rejoin", func(t *testing.T) {
		pr, pw := io.Pipe()
		good, signing := newSigner(t), make(chan struct{})
		var joined atomic.Bool
		id := Identity{
			// The key signs until a session has been ready, and then the agent
			// stops answering.
			Signers: func(ctx context.Context) ([]ssh.Signer, func(), error) {
				if !joined.Load() {
					return []ssh.Signer{good}, func() {}, nil
				}
				release := make(chan struct{})
				return []ssh.Signer{blockingSigner{Signer: good, until: release, entered: signing}}, sync.OnceFunc(func() { close(release) }), nil
			},
			Source: KeySource{Agent: 1},
		}
		cfg := config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{}), withInput(pr), withIdentity(id), withWait())
		cfg.Events = func(e Event) {
			if e.Kind == Joined {
				joined.Store(true)
			}
		}
		cfg.Timing.Attempt = time.Hour
		stopsWithin(t, cfg, pw, func() { recv(t, signing) })
	})
	t.Run("a blocked Joined line", func(t *testing.T) {
		pr, pw := io.Pipe()
		rec := &recorder{gate: make(chan struct{})} // never opened
		relay := newFakeRelay(t, relayKnobs{})
		stopsWithin(t, config(t, relay, withInput(pr), withEvents(rec), withWait()), pw, func() { require.Equal(t, Joined, recv(t, rec.held()).Kind) })
		require.Empty(t, relay.input(t, 0), "the Ctrl-C reached a session that wasn't ready")
	})
	t.Run("a blocked Joined line with the replay in", func(t *testing.T) {
		pr, pw := io.Pipe()
		rec := &recorder{gate: make(chan struct{})} // never opened
		stuck := newStuckWriter(t)                  // a terminal that isn't taking output, as the Joined line found
		relay := newFakeRelay(t, relayKnobs{output: "REPLAY", outputFirst: true})
		cfg := config(t, relay, withInput(pr), withEvents(rec), withStdout(stuck), withWait())
		stopsWithin(t, cfg, pw, func() { require.Equal(t, Joined, recv(t, rec.held()).Kind) })
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
	gate, open := newGate(t)
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
	open()
	require.Equal(t, Exited, recv(t, done).Kind)
	require.Equal(t, "PARKEDR", sink.String())
}

func TestTheNextSessionWaitsForTheLastOnesWrites(t *testing.T) {
	released, release := newGate(t)
	relay := newFakeRelay(t, relayKnobs{}, relayKnobs{})
	out := &syncSink{}
	rec := &recorder{w: out}
	// No session here is ever ready, so the first join's deadline would
	// otherwise run under the test's own waits.
	cfg := config(t, relay, withStdout(out), withEvents(rec), withWait())
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
	release()
	require.Equal(t, Exited, recv(t, result).Kind)
	require.Equal(t, "\x1b[?1049l<LOST><WAITING>NEXT", out.String())
}

func TestAStopStillRestoresAfterTheParkedWrite(t *testing.T) {
	t.Run("while the write is parked", func(t *testing.T) {
		sink := &syncSink{}
		gate, open := newGate(t)
		lost := make(chan struct{})
		cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(sink), withWait())
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
		recv(t, lost)
		cancel()
		// Stopping, the run still waits, within its bound, to put the terminal back.
		require.Never(t, func() bool { return len(done) > 0 || sink.String() != "" }, 100*time.Millisecond, 10*time.Millisecond)
		open()
		require.Equal(t, Stopped, recv(t, done).Kind)
		require.Equal(t, "PARKEDR", sink.String())
	})
	t.Run("while the restore is being written", func(t *testing.T) {
		term := &heldWriter{entered: make(chan struct{}), let: make(chan struct{})}
		cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(term), withWait())
		cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
			released := make(chan struct{})
			close(released)
			return attach.Result{Reason: attach.Disconnected, Released: released, Unrestored: []byte("R")}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, cfg)
		recv(t, term.entered) // the hand-over between sessions is writing the restore
		cancel()
		require.Never(t, func() bool { return len(done) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
		close(term.let)
		require.Equal(t, Stopped, recv(t, done).Kind)
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
	rec.await(t, done, func(e Event) bool { return e.Kind == Joined && e.Rejoin })
	require.Never(t, func() bool { return len(relay.windowChanges(1)) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)
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
	key := newSigner(t)
	id := Identity{
		// Each attempt has an agent connection of its own, which release
		// closes.
		Signers: func(context.Context) ([]ssh.Signer, func(), error) {
			release := make(chan struct{})
			return []ssh.Signer{blockingSigner{Signer: key, until: release}}, sync.OnceFunc(func() { close(release) }), nil
		},
		Source: KeySource{Agent: 1},
	}
	cfg := config(t, newFakeRelay(t, relayKnobs{}), withIdentity(id)) // Attempt 200 ms
	start := time.Now()
	select {
	case out := <-runJoinAsync(t, context.Background(), cfg):
		require.ErrorIs(t, out.Err, ErrIdentity) // a first join stops on it
		// A loose ceiling: a signature nothing ends would take the test's
		// whole timeout.
		require.Less(t, time.Since(start), cfg.Timing.Attempt+2*time.Second)
	case <-time.After(testTimeout):
		t.Fatal("a stalled agent held the attempt past its deadline")
	}
}
