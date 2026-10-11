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
		out := &syncSink{}
		done := runJoinAsync(t, context.Background(), config(t, newFakeRelay(t, relayKnobs{output: "READY"}), withInput(pr), withStdout(out)))
		// The session's output reaches the terminal only once the session has
		// the keyboard, so what is typed from then on is the session's. Typed
		// sooner, it could be join's, which takes keys only until then.
		require.Eventually(t, func() bool { return strings.Contains(out.String(), "READY") }, testTimeout, time.Millisecond)
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
		cfg.Timing.Attempt = time.Hour // no attempt fails for being slow
		cfg.Events = func(e Event) {
			if e.Kind == Joined {
				joined.Store(true)
			}
			rec.event(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := runJoinAsync(t, ctx, cfg)
		// The wait after the drop, and then the one after the rejoin's attempt.
		require.Equal(t, Unreachable, rec.await(t, done, func(e Event) bool { return e.Kind == Waiting && !e.First }).Why)
		e := rec.await(t, done, func(e Event) bool { return e.Kind == Waiting })
		require.Equal(t, IdentityFailure, e.Why)
		require.False(t, e.First)
		require.ErrorIs(t, e.Err, ErrIdentity)
		cancel()
		require.Equal(t, Stopped, recv(t, done).Kind)
	})
}

func TestTheFirstJoinDeadlineIsExact(t *testing.T) {
	for name, tc := range map[string]struct {
		knobs relayKnobs
		why   WaitReason
	}{
		"no host":           {relayKnobs{refuseAll: true, banner: noHostBanner}, NoHost},
		"a stalled attempt": {relayKnobs{stallHandshake: true}, Unreachable},
	} {
		t.Run(name, func(t *testing.T) {
			relay := newFakeRelay(t, tc.knobs)
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

			require.Equal(t, tc.why, deadlineOf(t, recv(t, done)).Why)
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

// A status line written during a first join's wait counts against its
// deadline: a terminal slow to take the line, or not taking it at all, still
// ends the join when its time runs out.
func TestAStatusLineDoesNotHoldAFirstJoinPastItsDeadline(t *testing.T) {
	t.Run("one the terminal never takes", func(t *testing.T) {
		// FirstJoin 300 ms. The gate opens only as the test ends.
		cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}))
		stuck, _ := newGate(t)
		cfg.Events = func(e Event) {
			if e.Kind == Waiting {
				<-stuck
			}
		}
		// A loose ceiling: the exact figure is the deadline's.
		ceiling := cfg.Timing.FirstJoin + 2*time.Second
		done := runJoinAsync(t, context.Background(), cfg)
		select {
		case out := <-done:
			require.Equal(t, NoHost, deadlineOf(t, out).Why)
		case <-time.After(ceiling):
			t.Fatal("a status line stuck on the terminal held the first join past its deadline")
		}
	})
	t.Run("one the terminal takes just before the deadline", func(t *testing.T) {
		relay := newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner})
		cfg := config(t, relay)
		cfg.Timing.FirstJoin = time.Second
		// An attempt's own deadline is an hour away, so the first attempt's is
		// the first join's. The first wait, unjittered and with nothing shorter
		// to cap it, is all the time the first join has left.
		cfg.Timing.Attempt = time.Hour
		cfg.Timing.FastBase, cfg.Timing.FastCap = time.Hour, time.Hour
		cfg.Timing.Jitter = func(max time.Duration) time.Duration { return max }
		var deadline time.Time
		cfg.Dial = func(ctx context.Context) (net.Conn, error) {
			if deadline.IsZero() {
				deadline, _ = ctx.Deadline()
			}
			return relay.Dial(ctx)
		}
		// The terminal takes the Waiting line 100 ms before the deadline.
		cfg.Events = func(e Event) {
			if e.Kind == Waiting {
				<-time.After(time.Until(deadline) - 100*time.Millisecond)
			}
		}
		out := runJoin(t, cfg)
		late := time.Since(deadline)
		require.Equal(t, NoHost, deadlineOf(t, out).Why)
		// What is left to wait is measured after the line, not before it: a
		// wait measured from before would end as long after the deadline as
		// the line took, about 900 ms here. The bound is loose.
		require.Less(t, late, 400*time.Millisecond, "the run ended %v after the first join's deadline", late)
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

// dialsOn makes cfg's Dial note the time of each attempt on the channel it
// returns, which holds 64.
func dialsOn(cfg *Config) <-chan time.Time {
	dialed := make(chan time.Time, 64)
	dial := cfg.Dial
	cfg.Dial = func(ctx context.Context) (net.Conn, error) {
		dialed <- time.Now()
		return dial(ctx)
	}
	return dialed
}

func TestTheRetryComesWhenTheStatusLineSaid(t *testing.T) {
	// The wait is 400 ms, and the terminal takes 200 ms over the Waiting line.
	// The wall clock stands still, so the monotonic clock alone ends the wait.
	const wait, hold = 400 * time.Millisecond, 200 * time.Millisecond
	base := time.Now().Round(0)
	rec := &recorder{gate: make(chan struct{})}
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withEvents(rec), withWait())
	cfg.Timing.FastBase, cfg.Timing.FastCap = wait, wait
	cfg.Timing.Jitter = func(max time.Duration) time.Duration { return max }
	cfg.Timing.Wall = func() time.Time { return base }
	dialed := dialsOn(&cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runJoinAsync(t, ctx, cfg)
	defer close(rec.gate)

	recv(t, dialed) // the first attempt
	line := recv(t, rec.held())
	began := time.Now() // as the line began, after the wait did
	require.Equal(t, Waiting, line.Kind)
	require.True(t, line.Next.Equal(base.Add(wait)), "the line said %v", line.Next)
	<-time.After(hold)
	rec.gate <- struct{}{}
	at := recv(t, dialed)
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)
	// The attempt comes the wait after the line began, as the line said:
	// neither the line's time later nor as soon as it is written. The bound
	// is loose.
	require.WithinDuration(t, began.Add(wait), at, hold/2, "the attempt came %v after the line began", at.Sub(began))
}

func TestAWallClockPastTheRetryDuringTheStatusLineAttemptsAtOnce(t *testing.T) {
	base := time.Now().Round(0)
	var jumped atomic.Bool
	rec := &recorder{gate: make(chan struct{})}
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withEvents(rec), withWait())
	// An hour's wait, on a wall clock the wait looks at only as it starts and
	// then an hour later: nothing but the time the line gave having passed by
	// then can bring the attempt on.
	cfg.Timing.FastBase, cfg.Timing.FastCap, cfg.Timing.WallCheck = time.Hour, time.Hour, time.Hour
	cfg.Timing.Jitter = func(max time.Duration) time.Duration { return max }
	cfg.Timing.Wall = func() time.Time {
		if jumped.Load() {
			return base.Add(2 * time.Hour)
		}
		return base
	}
	dialed := dialsOn(&cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runJoinAsync(t, ctx, cfg)
	defer close(rec.gate)

	recv(t, dialed) // the first attempt
	line := recv(t, rec.held())
	require.Equal(t, Waiting, line.Kind)
	require.True(t, line.Next.Equal(base.Add(time.Hour)), "the line said %v", line.Next)
	jumped.Store(true) // the lid opens two hours later, while the terminal takes the line
	rec.gate <- struct{}{}
	select {
	case <-dialed: // the next attempt
	case <-time.After(testTimeout):
		t.Fatal("the line was written after the time it gave, and the wait went on")
	}
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)
}

func TestNoStatusLineAfterAStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recorder{}
	// withWait: with no first-join deadline, a slow handshake can't end the
	// run before its first wait does.
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withEvents(rec), withWait())
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
	t.Run("a stalled handshake on a first join", func(t *testing.T) {
		// Nothing can prompt, so the keys are the run's before any handshake.
		pr, pw := io.Pipe()
		relay := newFakeRelay(t, relayKnobs{stallHandshake: true})
		cfg := config(t, relay, withInput(pr), withWait())
		cfg.Timing.Attempt = time.Hour // only Ctrl-C can end it
		stopsWithin(t, cfg, pw, func() {
			require.Eventually(t, func() bool { return relay.connections() == 1 }, testTimeout, time.Millisecond)
		})
	})
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

func TestAFinalOutcomeWaitsForAParkedWriteOnlySoLong(t *testing.T) {
	released, release := newGate(t) // the parked write lands only once the run is over
	sink := &syncSink{}
	cfg := config(t, newFakeRelay(t, relayKnobs{}), withStdout(sink))
	cfg.runSession = func(context.Context, *ssh.Client, time.Time) (attach.Result, error) {
		return attach.Result{Reason: attach.Exited, Status: 5, Released: released, Unrestored: []byte("\x1b[?1049l")}, nil
	}
	start := time.Now()
	require.Equal(t, Outcome{Kind: Exited, Status: 5}, runJoin(t, cfg))
	require.GreaterOrEqual(t, time.Since(start), finalBound, "the run gave the parked write less than its bound")
	require.Less(t, time.Since(start), finalBound+2*time.Second)

	// Past the bound nothing more is written, not even once the parked write
	// lets go.
	release()
	require.Never(t, func() bool { return sink.String() != "" }, 100*time.Millisecond, 10*time.Millisecond,
		"the restore was written after the run gave up on it")
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

func TestTakeTerminalRunsOnce(t *testing.T) {
	t.Run("after the first handshake, when a prompt can come", func(t *testing.T) {
		took := 0
		take := withTakeTerminal(func() error { took++; return nil })
		prompt := withConfirm(&countingConfirm{accept: true})
		runJoin(t, config(t, newFakeRelay(t, relayKnobs{refuseAll: true}), prompt, take))
		require.Zero(t, took, "the terminal was taken on a run that no handshake got through")
		runJoin(t, config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{exit: intp(0)}), prompt, take))
		require.Equal(t, 1, took)
	})
	t.Run("as the run starts, when none can", func(t *testing.T) {
		took := 0
		take := withTakeTerminal(func() error { took++; return nil })
		// A run that no handshake gets through still takes it, and before its
		// first attempt.
		cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true}), take)
		tookByDial := -1 // took, as the first attempt dials
		dial := cfg.Dial
		cfg.Dial = func(ctx context.Context) (net.Conn, error) {
			if tookByDial < 0 {
				tookByDial = took
			}
			return dial(ctx)
		}
		require.ErrorIs(t, runJoin(t, cfg).Err, ErrKeysRefused)
		require.Equal(t, 1, tookByDial, "the first attempt began with the terminal not taken")
		require.Equal(t, 1, took)

		took = 0
		runJoin(t, config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}, relayKnobs{exit: intp(0)}), take))
		require.Equal(t, 1, took)
	})
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

// keyWait is a wait that only a key can end: the run's next attempt is an
// hour away.
type keyWait struct {
	first     relayKnobs // what the relay does on the connection before the wait
	firstJoin bool       // no session has been ready: the wait is a first join's
}

// keyWaits are the waits a key ends alike: one after a session drops, and
// one in a first join, where nothing can prompt and so the keys are the run's
// from the start.
var keyWaits = map[string]keyWait{
	"after a drop":    {first: relayKnobs{dropAfterReady: true}},
	"on a first join": {first: relayKnobs{refuseAll: true, banner: noHostBanner}, firstJoin: true},
}

// start starts a run that waits as w says, and returns once it is waiting,
// with the guest's keyboard and the run's outcome. next is what the relay
// does on the connections after the first; opts apply last.
func (w keyWait) start(t *testing.T, next relayKnobs, opts ...option) (keys *io.PipeWriter, relay *fakeRelay, done <-chan Outcome) {
	t.Helper()
	pr, pw := io.Pipe()
	relay = newFakeRelay(t, w.first, next)
	rec := &recorder{}
	cfg := config(t, relay, withInput(pr), withEvents(rec), withWait())
	cfg.Timing.Attempt = time.Hour // no attempt fails for being slow
	cfg.Timing.FastBase, cfg.Timing.FastCap = time.Hour, time.Hour
	cfg.Timing.Jitter = func(max time.Duration) time.Duration { return max }
	for _, o := range opts {
		o(&cfg)
	}
	done = runJoinAsync(t, context.Background(), cfg)
	rec.await(t, done, func(e Event) bool { return e.Kind == Waiting && e.First == w.firstJoin })
	return pw, relay, done
}

func TestEnterDuringAWaitAttemptsAtOnce(t *testing.T) {
	for name, w := range keyWaits {
		t.Run(name, func(t *testing.T) {
			keys, relay, done := w.start(t, relayKnobs{exit: intp(0)})
			press(keys, "\r")
			select {
			case out := <-done:
				require.Equal(t, Exited, out.Kind)
			case <-time.After(testTimeout):
				t.Fatal("Enter didn't cut the wait short")
			}
			require.Equal(t, 2, relay.connections())
		})
	}
}

func TestKeysDuringAWaitEndTheRun(t *testing.T) {
	for wait, w := range keyWaits {
		t.Run(wait, func(t *testing.T) {
			for name, tc := range map[string]struct {
				act  func(keys *io.PipeWriter)
				want OutcomeKind
			}{
				"~. leaves":                      {func(keys *io.PipeWriter) { press(keys, "~.") }, Left},
				"Ctrl-C stops":                   {func(keys *io.PipeWriter) { press(keys, "\x03") }, Stopped},
				"the terminal going away leaves": {func(keys *io.PipeWriter) { _ = keys.Close() }, Left},
			} {
				t.Run(name, func(t *testing.T) {
					keys, relay, done := w.start(t, relayKnobs{exit: intp(0)})
					tc.act(keys)
					select {
					case out := <-done:
						require.Equal(t, tc.want, out.Kind)
					case <-time.After(testTimeout):
						t.Fatal("the key didn't end the wait")
					}
					require.Equal(t, 1, relay.connections(), "the run attempted again")
				})
			}
		})
	}
}

// The keys join reads itself have the session's escape byte: there is no
// other to set, so detaching works the same connected or not.
func TestKeysDuringAWaitTakeTheSessionsEscape(t *testing.T) {
	for name, w := range keyWaits {
		t.Run(name, func(t *testing.T) {
			keys, relay, done := w.start(t, relayKnobs{exit: intp(0)}, func(c *Config) { c.Terminal.Escape = '%' })
			press(keys, "%.")
			select {
			case out := <-done:
				require.Equal(t, Left, out.Kind)
			case <-time.After(testTimeout):
				t.Fatal("the session's escape sequence didn't leave the wait")
			}
			require.Equal(t, 1, relay.connections(), "the run attempted again")
		})
	}
}

// Once Run has returned, Input is the caller's again. The Read in progress
// takes one more chunk, which goes nowhere, and nothing reads Input after it.
func TestNothingReadsInputOnceRunHasReturned(t *testing.T) {
	keys, typed := io.Pipe()
	input := newWatchedInput(keys)
	rec := &recorder{}
	cfg := config(t, newFakeRelay(t, relayKnobs{}), withInput(input), withEvents(rec))
	cfg.inputExited = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := runJoinAsync(t, ctx, cfg)
	require.Equal(t, Joined, recv(t, rec.held()).Kind)
	recv(t, input.reading) // the reader's first Read, which nothing has been typed for
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)

	// An Enter: join, were it still reading its keys, would attempt again.
	_, err := typed.Write([]byte("\r"))
	require.NoError(t, err) // the Read in progress took it
	select {
	case <-cfg.inputExited:
	case <-time.After(testTimeout):
		t.Fatal("the reader of Input outlived Run")
	}
	require.Empty(t, input.reading, "Input was read again after Run returned")
}

func TestAnIdentityThatFailsStopsAFirstJoinAndHoldsUpARejoin(t *testing.T) {
	cause := errors.New("the agent's socket is gone")
	t.Run("a first join", func(t *testing.T) {
		id := Identity{Signers: func(context.Context) ([]ssh.Signer, func(), error) { return nil, nil, cause }}
		out := runJoin(t, config(t, newFakeRelay(t, relayKnobs{}), withIdentity(id)))
		require.Equal(t, Failed, out.Kind)
		require.IsType(t, &IdentityError{}, out.Err) // and not a DeadlineError
		require.ErrorIs(t, out.Err, ErrIdentity)
		require.ErrorIs(t, out.Err, cause)
	})
	t.Run("a rejoin", func(t *testing.T) {
		key := newSigner(t)
		var joined atomic.Bool
		id := Identity{Signers: func(context.Context) ([]ssh.Signer, func(), error) {
			if joined.Load() {
				return nil, nil, cause
			}
			return []ssh.Signer{key}, func() {}, nil
		}}
		rec := &recorder{}
		cfg := config(t, newFakeRelay(t, relayKnobs{dropAfterReady: true}), withIdentity(id), withWait())
		cfg.Timing.Attempt = time.Hour // no attempt fails for being slow
		cfg.Events = func(e Event) {
			if e.Kind == Joined {
				joined.Store(true)
			}
			rec.event(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := runJoinAsync(t, ctx, cfg)
		// The wait after the drop, and then the one after the rejoin's attempt.
		require.Equal(t, Unreachable, rec.await(t, done, func(e Event) bool { return e.Kind == Waiting && !e.First }).Why)
		e := rec.await(t, done, func(e Event) bool { return e.Kind == Waiting })
		require.Equal(t, IdentityFailure, e.Why)
		require.False(t, e.First)
		require.ErrorIs(t, e.Err, ErrIdentity)
		require.ErrorIs(t, e.Err, cause)
		cancel()
		require.Equal(t, Stopped, recv(t, done).Kind)
	})
}

func TestEventsSayWhyAndSinceWhen(t *testing.T) {
	// A wall clock that moves on a millisecond at every reading, so that no
	// two readings are the same.
	base := time.Now().Round(0)
	var ticks atomic.Int64
	rec := &recorder{}
	relay := newFakeRelay(t,
		relayKnobs{dropAfterReady: true},                  // joined, then dropped
		relayKnobs{refuseAll: true, banner: noHostBanner}, // the host isn't back yet
		relayKnobs{dropAfterReady: true},                  // rejoined, then dropped again
		relayKnobs{exit: intp(0)})
	cfg := config(t, relay, withEvents(rec), withWait())
	cfg.Timing.Attempt = time.Hour // no attempt fails for being slow
	cfg.Timing.Wall = func() time.Time { return base.Add(time.Duration(ticks.Add(1)) * time.Millisecond) }
	require.Equal(t, Exited, runJoin(t, cfg).Kind)
	require.Equal(t, []EventKind{Joined, Lost, Waiting, Waiting, Joined, Lost, Waiting, Joined}, rec.kinds())
	e := rec.all()
	joined, lost, dropWait, noHostWait, rejoined, nextWait := e[0], e[1], e[2], e[3], e[4], e[6]

	require.False(t, joined.Rejoin)
	// A drop and the wait after it are the relay being out of reach, for the
	// reason the connection went.
	require.Equal(t, Unreachable, lost.Why)
	require.Error(t, lost.Err)
	require.Equal(t, Unreachable, dropWait.Why)
	require.Equal(t, lost.Err, dropWait.Err)
	require.False(t, dropWait.First)
	// One wait, however many attempts it takes.
	require.Equal(t, NoHost, noHostWait.Why)
	require.False(t, dropWait.Since.IsZero())
	require.True(t, noHostWait.Since.Equal(dropWait.Since), "the wait began at %v, then at %v", dropWait.Since, noHostWait.Since)
	require.True(t, rejoined.Rejoin)
	require.Positive(t, rejoined.Down)
	// A session that was ready ends the wait: the next one begins anew.
	require.True(t, nextWait.Since.After(dropWait.Since), "the wait after a rejoin began at %v, the one before it at %v", nextWait.Since, dropWait.Since)
}

func TestAWaitThatHasGoneOnLongSaysSo(t *testing.T) {
	// Each Waiting call is held until the test lets it through, so the test
	// knows the next wait is reckoned only after that.
	rec := &recorder{gate: make(chan struct{})}
	cfg := config(t, newFakeRelay(t, relayKnobs{refuseAll: true, banner: noHostBanner}), withEvents(rec), withWait())
	cfg.Timing.LongAfter = 100 * time.Millisecond
	cfg.Timing.SlowWait, cfg.Timing.SlowJitter = 10*time.Millisecond, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runJoinAsync(t, ctx, cfg)
	defer close(rec.gate)

	first := recv(t, rec.held())
	began := time.Now() // after the wait began
	require.Equal(t, Waiting, first.Kind)
	require.False(t, first.Long)
	// The wait has lasted LongAfter by the time the next one is reckoned.
	<-time.After(time.Until(began.Add(cfg.Timing.LongAfter)))
	rec.gate <- struct{}{}
	next := recv(t, rec.held())
	require.Equal(t, Waiting, next.Kind)
	require.True(t, next.Long, "a wait of %v isn't long", time.Since(began))
	require.True(t, next.Since.Equal(first.Since), "a long wait is the same wait")
	cancel()
	require.Equal(t, Stopped, recv(t, done).Kind)
}

func TestARelayKeyNotTrustedEndsTheJoin(t *testing.T) {
	t.Run("the guest says no", func(t *testing.T) {
		relay := newFakeRelay(t, relayKnobs{hostKeyUnknown: true})
		confirm := &countingConfirm{}
		out := runJoin(t, config(t, relay, withConfirm(confirm)))
		require.Equal(t, Failed, out.Kind)
		var hostKey *HostKeyError
		require.ErrorAs(t, out.Err, &hostKey)
		require.True(t, hostKey.Declined)
		require.ErrorIs(t, out.Err, ErrHostKey)
		require.Equal(t, 1, confirm.calls(), "the guest was asked again")
		require.Equal(t, 1, relay.connections())
	})
	t.Run("asking fails", func(t *testing.T) {
		cause := errors.New("the terminal went away")
		relay := newFakeRelay(t, relayKnobs{hostKeyUnknown: true})
		confirm := &countingConfirm{accept: true, err: cause}
		out := runJoin(t, config(t, relay, withConfirm(confirm)))
		require.Equal(t, Failed, out.Kind)
		require.ErrorIs(t, out.Err, cause)
		require.ErrorIs(t, out.Err, ErrHostKey)
		require.Equal(t, 1, confirm.calls())
		require.Equal(t, 1, relay.connections())
	})
}

// CheckHostKey runs again at every key exchange, and one after the handshake
// can refuse the relay's key. The connection goes with it, which a session or
// its setup sees only as the connection failing: the join stops there, as it
// would at the handshake, rather than rejoining past the refusal, and with the
// terminal taken it asks nobody about the key.
func TestARelayKeyRefusedAtALaterKeyExchangeEndsTheJoin(t *testing.T) {
	unknown := fmt.Errorf("relay.test is not in known_hosts: %w", ErrHostKeyUnknown)
	changed := fmt.Errorf("relay.test has another key: %w", ErrHostKeyChanged)
	for name, tc := range map[string]struct {
		refusal error
		// stallSetup holds setup at the pty request and sends the output
		// meanwhile, so that the key exchange it sets off is what ends setup.
		stallSetup bool
	}{
		"changed, during the session": {changed, false},
		"unknown, during the session": {unknown, false},
		"changed, during setup":       {changed, true},
		"unknown, during setup":       {unknown, true},
	} {
		t.Run(name, func(t *testing.T) {
			// The relay starts a key exchange once it has sent 16 KiB, which the
			// handshake and the setup are far short of, and then sends 64 KiB.
			// A rejoin would find a session that exits.
			relay := newFakeRelay(t,
				relayKnobs{rekeyAfter: 16 << 10, output: strings.Repeat("x", 64<<10), stallSetup: tc.stallSetup},
				relayKnobs{exit: intp(0)})
			confirm := &countingConfirm{accept: true}
			cfg := config(t, relay, withConfirm(confirm), withWait())
			cfg.Timing.Attempt = time.Hour // no attempt fails for being slow
			// The handshake's key exchange accepts the key, and the next refuses it.
			var checks atomic.Int32
			cfg.CheckHostKey = func(string, net.Addr, ssh.PublicKey) error {
				if checks.Add(1) == 2 {
					return tc.refusal
				}
				return nil
			}
			out := runJoin(t, cfg)
			require.Equal(t, Failed, out.Kind, "%+v", out)
			var hostKey *HostKeyError
			require.ErrorAs(t, out.Err, &hostKey)
			require.ErrorIs(t, out.Err, ErrHostKey)
			require.ErrorIs(t, out.Err, tc.refusal)
			require.Equal(t, errors.Is(tc.refusal, ErrHostKeyChanged), hostKey.Changed)
			require.Equal(t, int32(2), checks.Load())
			require.NotEmpty(t, relay.ptySizes(), "the key was refused before the handshake had succeeded")
			require.Equal(t, 1, relay.connections(), "the join connected again")
			require.Zero(t, confirm.calls(), "the guest was asked about the key with the terminal taken")
		})
	}
}

// An exit status can only have arrived before a key exchange that then
// refused the relay's key, under keys that an exchange it trusted set up: it
// is how the session ended.
func TestAnExitStatusOutranksARelayKeyRefusedAfterIt(t *testing.T) {
	r := newRunner(context.Background(), config(t, newFakeRelay(t, relayKnobs{})))
	defer r.close()
	refusal := fmt.Errorf("relay.test has another key: %w", ErrHostKeyChanged)
	s := r.ended(&sessionEnd{res: attach.Result{Reason: attach.Exited, Status: 3}, hostKeyErr: refusal})
	require.Equal(t, finish(Outcome{Kind: Exited, Status: 3}), s)
}

func TestTakingTheTerminalFailingEndsTheJoin(t *testing.T) {
	cause := errors.New("stdin is not a terminal")
	failing := withTakeTerminal(func() error { return cause })
	t.Run("as the run starts", func(t *testing.T) {
		relay := newFakeRelay(t, relayKnobs{exit: intp(0)})
		out := runJoin(t, config(t, relay, failing))
		require.Equal(t, Failed, out.Kind)
		require.ErrorIs(t, out.Err, cause)
		require.Zero(t, relay.connections(), "the run attempted with a terminal that wasn't taken")
	})
	t.Run("after the first handshake", func(t *testing.T) {
		relay := newFakeRelay(t, relayKnobs{exit: intp(0)})
		out := runJoin(t, config(t, relay, failing, withConfirm(&countingConfirm{accept: true})))
		require.Equal(t, Failed, out.Kind)
		require.ErrorIs(t, out.Err, cause)
		require.Empty(t, relay.ptySizes(), "a session was set up on a terminal that wasn't taken")
		require.Equal(t, 1, relay.connections())
	})
}
