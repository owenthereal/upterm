package join

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// finalBound is how long the end of a run waits for the last session's
// writes, and the restore after them, to reach the terminal.
const finalBound = time.Second

// KeySource says where the guest's keys came from, so that the command can
// explain a refusal in terms the guest recognises. It is known before Run:
// the identity is prepared, and the agent listed, before the first attempt.
type KeySource struct {
	Agent, Files int  // keys from the agent, and from key files
	Generated    bool // no agent keys and no default key files: a key was generated
	Explicit     bool // the keys were named with -i
}

// Identity is the guest's keys.
type Identity struct {
	// Signers is called once per attempt, with the attempt's ctx, and returns
	// promptly once ctx ends. Every agent operation it or its signers start
	// is bound to ctx, and release, which may be nil, closes the attempt's
	// agent connection. release must be idempotent: Run arms it on ctx and
	// calls it again when the attempt returns, so an agent that stops
	// answering costs no more than the attempt's deadline. The agent is a
	// connection of its own, which closing the relay's would not end.
	//
	// An error from Signers is the guest's own identity failing, as a signer
	// that fails to sign is: a first join stops on it (ErrIdentity), and a
	// rejoin waits it out (IdentityFailure). It should return at least one
	// signer: an empty list leaves no key to offer, which ends the join as
	// refused.
	Signers func(ctx context.Context) (signers []ssh.Signer, release func(), err error)
	Source  KeySource
}

// Config is a join: the session, and the seams through which Run reaches the
// world.
type Config struct {
	Target Target
	// Dial opens a connection to the relay. It is called once per attempt,
	// with the attempt's ctx, and returns promptly once ctx ends: a stop, and
	// the attempt's deadline, wait for it.
	Dial     func(ctx context.Context) (net.Conn, error)
	Identity Identity
	// CheckHostKey decides on the relay's key without blocking on anyone: nil
	// (trusted), or an error that wraps ErrHostKeyUnknown or
	// ErrHostKeyChanged. It may record a key itself. Its hostname is
	// Target.Host, host:port, and it runs again at every key exchange, not
	// only the first. An unknown key goes to ConfirmHostKey, if the guest may
	// still be asked; any other error, ErrHostKeyChanged or not, stops the
	// join.
	CheckHostKey ssh.HostKeyCallback
	// ConfirmHostKey asks the guest about an unknown key, with no connection
	// open, and records it if they accept. It returns promptly when ctx ends.
	// It is never called once TakeTerminal has run: from then on nothing
	// prompts. Nil means an unknown key is never accepted. A "no", or an
	// error, ends the join as Failed.
	ConfirmHostKey func(ctx context.Context, hostname string, key ssh.PublicKey) (accepted bool, err error)
	// Terminal runs each session. Run sets Stdin, Pty.Size and OnReady on a
	// copy for each session, and wraps its Stdout so that nothing reaches it
	// before the guest has been told the session is ready; this one is left
	// as it is. Resizes still pending when a session starts came while no
	// session had the terminal, and are dropped: the session's pty request
	// carries the size measured then. Terminal.Escape is the session's escape
	// byte; see Escape.
	Terminal *attach.Terminal
	// Size is measured afresh for each session's pty request. Nil keeps
	// Terminal.Pty's.
	Size func() termsize.Size
	// Input is the guest's keys. Run reads it only once TakeTerminal has run,
	// and then from one goroutine, which gives each key to the session that
	// is ready or else to Run. Nil means no keys.
	Input io.Reader
	// Escape is the escape byte: at the start of a line, followed by '.', it
	// leaves. Zero disables it. It covers the keys join reads itself, while
	// no session has the keyboard; Terminal.Escape covers a session's. Set
	// both.
	Escape byte
	// TakeTerminal runs once, when a handshake first succeeds: it is where
	// the command puts the terminal in raw mode. Nil does nothing. An error
	// ends the join as Failed, with that error.
	TakeTerminal func() error
	// Events tells the guest how the join is going. It returns only once
	// whatever it wrote has been written or has failed: Run starts no attempt
	// and lets no session write while it is in progress. While the run goes
	// on, calls are serial, each starting once the last has returned. Each
	// runs on its own goroutine, so a write stuck on a terminal never keeps a
	// stop from ending the run, nor a first join's deadline, which a Waiting
	// line counts against as the rest of the wait does. Run starts no call
	// once it has stopped, but one that began as the stop landed, or that the
	// stop or the deadline abandoned, may still be writing after Run returns.
	// Nil tells nobody.
	Events func(Event)
	// Wait removes the first join's deadline.
	Wait   bool
	Timing Timing

	// runSession runs one session; nil means the session's Terminal.Run.
	// Tests replace it to stage a Result.
	runSession func(ctx context.Context, c *ssh.Client, setupBy time.Time) (attach.Result, error)
}

// OutcomeKind is how a run ended.
type OutcomeKind int

const (
	// Exited: the session sent an exit status.
	Exited OutcomeKind = iota + 1
	// Left: the guest left, with the escape sequence or by closing the
	// terminal.
	Left
	// Stopped: ctx ended, or the guest pressed Ctrl-C while no session had
	// the keyboard.
	Stopped
	// Failed: the join can't go on; Err says why.
	Failed
)

// Outcome is how a run ended.
type Outcome struct {
	Kind   OutcomeKind
	Status int // Exited
	// Err is why a run Failed. It is one of:
	//   - a *DeadlineError: a first join's time ran out, waiting on its Why;
	//   - a *RefusedError (ErrKeysRefused);
	//   - an *IdentityError (ErrIdentity), on a first join;
	//   - a *HostKeyError (ErrHostKey): a changed key, an unknown one the
	//     guest declined or couldn't be asked about, CheckHostKey's own
	//     error, or ConfirmHostKey's;
	//   - ErrUpstreamHostKey;
	//   - TakeTerminal's error, as it is;
	//   - an error naming a Config field Run needs and wasn't given.
	Err error
}

// EventKind is what an Event reports.
type EventKind int

const (
	// Joined: a session is ready. Its output follows.
	Joined EventKind = iota + 1
	// Lost: the connection to a session went away without an exit status.
	Lost
	// Waiting: the next attempt is a wait away.
	Waiting
)

// Event is a change the guest is told about.
type Event struct {
	Kind   EventKind
	Rejoin bool          // Joined: not the first
	Down   time.Duration // Joined, on a rejoin: how long the session was out of reach
	Why    WaitReason    // Lost, Waiting
	Err    error         // Lost, Waiting: the error behind Why, if any
	Since  time.Time     // Waiting: when this wait began, on the wall clock
	Next   time.Time     // Waiting: when the next attempt is due, on the wall clock
	Long   bool          // Waiting: the wait has gone on long enough to slow down
	First  bool          // Waiting: no session has been ready yet
}

// Run joins the session cfg names and stays with it until it ends: an exit
// status, the guest leaving or stopping, or a failure that waiting won't
// mend. A connection that drops is rejoined, however long that takes; a
// first join that can't get in gives up after Timing.FirstJoin, unless
// cfg.Wait.
func Run(ctx context.Context, cfg Config) Outcome {
	if err := cfg.validate(); err != nil {
		return Outcome{Kind: Failed, Err: err}
	}
	r := newRunner(ctx, cfg)
	defer r.close()
	out := r.loop()
	if r.last != nil {
		// However the run ends, the last session's writes and its restore
		// get the same bounded chance to land.
		r.last.finish()
	}
	return out
}

func (c Config) validate() error {
	switch {
	case c.Dial == nil:
		return errors.New("join: Config.Dial is required")
	case c.Identity.Signers == nil:
		return errors.New("join: Config.Identity.Signers is required")
	case c.CheckHostKey == nil:
		return errors.New("join: Config.CheckHostKey is required")
	case c.Terminal == nil:
		return errors.New("join: Config.Terminal is required")
	case c.Terminal.Stdout == nil:
		return errors.New("join: Config.Terminal.Stdout is required")
	}
	return nil
}

// runner is one Run. Its loop runs on Run's goroutine and owns everything
// below mu's fields; one other goroutine reads join's keys (see readKeys).
type runner struct {
	cfg    Config
	timing Timing
	sched  *schedule
	in     *input

	// runCtx ends with ctx, or when a key stops the run. Everything an
	// attempt or a session starts is bound to it, so cancelling it is all a
	// stop has to do.
	runCtx context.Context
	cancel context.CancelFunc

	// quit closes when Run returns; keysDone once readKeys has seen it.
	quit, keysDone chan struct{}

	mu sync.Mutex
	// cause is the key that stopped the run; zero when ctx did, or nothing
	// has.
	cause OutcomeKind
	// retry is the current wait's: Enter during a wait goes there. Nil while
	// nothing waits, when Enter does nothing.
	retry chan struct{}

	// The loop's alone.
	tookTerminal bool
	joined       bool      // a session has been ready
	deadline     time.Time // the first join's, monotonic; zero until the first attempt, and with Wait
	// since is when the current wait began on the wall clock, for the guest;
	// zero while a session is ready. waitFrom is the same moment on the
	// monotonic clock, which the schedule measures the wait by: a laptop's
	// sleep or a clock that is stepped mustn't move it into the slow tier.
	since, waitFrom time.Time
	// lastWhy and lastErr are the reason a first join last had, which its
	// DeadlineError wraps: what it last waited on, or tried again at once
	// over. Zero until it has one.
	lastWhy WaitReason
	lastErr error
	// refused holds the keys the session's node turned away, by SHA256
	// fingerprint. A session's authorized keys don't change while it runs,
	// so they stay out for the run.
	refused map[string]bool
	// sitOut holds the keys an ambiguous refusal set aside for this round.
	// It empties when a session is ready, and when a rejoin's round runs out.
	sitOut map[string]bool
	// joinedWith holds the keys that have had a session ready in this run.
	// The session's node let them in once, so an ambiguous refusal of one is
	// a session that isn't there, not a refusal.
	joinedWith map[string]bool
	// last is the hand-over of the last session that ran; nil before one has.
	last *handover
}

func newRunner(ctx context.Context, cfg Config) *runner {
	runCtx, cancel := context.WithCancel(ctx)
	timing := cfg.Timing.orDefault()
	r := &runner{
		cfg:        cfg,
		timing:     timing,
		sched:      newSchedule(timing),
		in:         newInput(cfg.Input, cfg.Escape),
		runCtx:     runCtx,
		cancel:     cancel,
		quit:       make(chan struct{}),
		keysDone:   make(chan struct{}),
		refused:    map[string]bool{},
		sitOut:     map[string]bool{},
		joinedWith: map[string]bool{},
	}
	go r.readKeys()
	return r
}

func (r *runner) close() {
	close(r.quit)
	<-r.keysDone
	r.cancel()
}

// readKeys takes join's keys for the whole run. input delivers them only
// while no session's view is active, so reading them all the time is reading
// them in every phase that has no session: waits, each step of an attempt,
// the Joined line, and the gap after a session ends. Before TakeTerminal
// nothing reads Input, and none arrive.
//
// A stop only records its cause and cancels runCtx: whatever the loop is
// blocked on is bound to it, and the loop returns once the attempt's
// goroutines have let go.
func (r *runner) readKeys() {
	defer close(r.keysDone)
	for {
		select {
		case k := <-r.in.keys():
			r.key(k)
		case <-r.quit:
			return
		}
	}
}

func (r *runner) key(k waitKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch k {
	case keyRetry:
		// During an attempt there is no wait to cut short: one is already
		// in progress.
		if r.retry != nil {
			select {
			case r.retry <- struct{}{}:
			default:
			}
		}
	case keyStop, keyLeave:
		if r.cause == 0 && r.runCtx.Err() == nil {
			r.cause = Stopped
			if k == keyLeave {
				r.cause = Left
			}
		}
		r.cancel()
	}
}

// stopped is the outcome of a run whose runCtx ended: the key that ended it,
// or Stopped for ctx.
func (r *runner) stopped() Outcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cause != 0 {
		return Outcome{Kind: r.cause}
	}
	return Outcome{Kind: Stopped}
}

func failed(err error) Outcome { return Outcome{Kind: Failed, Err: err} }

// step is what the loop does after an attempt: end the run with out, wait
// (why, err) and attempt again, or attempt again at once.
type step struct {
	done bool
	out  Outcome
	wait bool
	why  WaitReason
	err  error
}

var attemptNow = step{}

func finish(out Outcome) step { return step{done: true, out: out} }

func waitThen(why WaitReason, err error) step { return step{wait: true, why: why, err: err} }

// again attempts again at once. On a first join, why and err are the reason
// its DeadlineError wraps should the time run out before the next attempt
// has its say.
func (r *runner) again(why WaitReason, err error) step {
	if !r.joined {
		r.lastWhy, r.lastErr = why, err
	}
	return attemptNow
}

func (r *runner) loop() Outcome {
	for {
		if r.firstJoinOver() {
			// The time ran out between attempts: after one that tried again at
			// once, which left its reason, or after a prompt.
			return r.timedOut(Unreachable, context.DeadlineExceeded)
		}
		s := r.next(r.attempt())
		if s.done {
			return s.out
		}
		if s.wait {
			if out, ok := r.wait(s.why, s.err); !ok {
				return out
			}
		}
	}
}

// firstJoinOver reports whether a first join has used up its deadline.
func (r *runner) firstJoinOver() bool {
	return r.firstJoin() && !time.Now().Before(r.deadline)
}

// firstJoin reports whether the run is a first join with a deadline.
func (r *runner) firstJoin() bool { return !r.joined && !r.deadline.IsZero() }

// timedOut ends a first join whose deadline has passed. It wraps the last
// reason the join had, what it last waited on or tried again at once over,
// or, if it has none, why and err.
func (r *runner) timedOut(why WaitReason, err error) Outcome {
	if r.lastWhy != 0 {
		why, err = r.lastWhy, r.lastErr
	}
	return failed(&DeadlineError{Why: why, Err: err})
}

// attempted is how one attempt ended.
type attempted struct {
	v         verdict
	exhausted bool          // no candidate key was left to offer
	offered   []ssh.Signer  // the keys offered
	selected  ssh.PublicKey // the key whose signature got in
	hostKey   ssh.PublicKey // the relay's key, for vHostKeyUnknown
	cut       bool          // the first join's deadline ended it
	err       error         // the run can't go on
	session   *sessionEnd   // the session ran and returned a Result
}

// sessionEnd is a session that ran.
type sessionEnd struct {
	res     attach.Result
	ready   bool
	readyAt time.Time
	err     error // why the connection went: the liveness error, or the one it closed with
}

// attempt runs one attempt under its own deadline: the identity, the dial,
// the handshake and the session's setup, and then, if it gets that far, the
// session.
func (r *runner) attempt() (a attempted) {
	now := time.Now()
	if !r.cfg.Wait && !r.joined && r.deadline.IsZero() {
		r.deadline = now.Add(r.timing.FirstJoin)
	}
	by := now.Add(r.timing.Attempt)
	cutoff := r.firstJoin() && !r.deadline.After(by)
	if cutoff {
		by = r.deadline
	}
	actx, cancel := context.WithDeadline(r.runCtx, by)
	defer cancel()
	// Whether the first join's deadline is what ended the attempt is read off
	// the clock, not off actx: a dial returns on its socket's deadline, and a
	// setup on Terminal's own timer, either of which can come before actx's
	// timer has fired. next decides what a cut attempt's verdict is worth.
	defer func() { a.cut = cutoff && !time.Now().Before(by) }()

	signers, release, err := r.cfg.Identity.Signers(actx)
	if release != nil {
		// As soon as actx ends, at the deadline or with a stop, the agent's
		// connection closes, which ends a signature waiting on it. Either that
		// close never runs, or it has started and is waited for.
		released := make(chan struct{})
		stop := context.AfterFunc(actx, func() {
			defer close(released)
			release()
		})
		defer func() {
			if !stop() {
				<-released
			}
			release()
		}()
	}
	if err != nil {
		var idErr *IdentityError
		if !errors.As(err, &idErr) {
			idErr = &IdentityError{Err: err}
		}
		return attempted{v: verdict{kind: vWait, why: IdentityFailure, err: idErr}}
	}

	offered := r.candidates(signers)
	if len(offered) == 0 {
		return attempted{exhausted: true}
	}

	ev := &evidence{}
	conn, err := r.cfg.Dial(actx)
	if err != nil {
		return attempted{v: classifyConnect(err, ev), offered: offered}
	}
	lc := liveness.NewConn(conn)
	// Nothing in the handshake watches actx, so it is closed under it.
	stopClosing := context.AfterFunc(actx, func() { _ = lc.Close() })
	// The relay's key, for a prompt. The callback runs again at every key
	// exchange, so it is read only to explain a handshake that failed, as
	// the evidence is.
	var hostKey ssh.PublicKey
	check := func(host string, remote net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return r.cfg.CheckHostKey(host, remote, key)
	}
	sc, chans, reqs, err := ssh.NewClientConn(lc, r.cfg.Target.Host, clientConfig(r.cfg.Target.User, offered, check, ev))
	if err != nil {
		stopClosing()
		_ = lc.Close()
		return attempted{v: classifyConnect(err, ev), offered: offered, selected: ev.selected, hostKey: hostKey}
	}
	if !stopClosing() {
		// actx ended as the handshake finished, and the connection with it.
		_ = sc.Close()
		return attempted{v: verdict{kind: vWait, why: Unreachable, err: actx.Err()}, offered: offered}
	}
	client := ssh.NewClient(sc, chans, reqs)

	if !r.tookTerminal {
		r.tookTerminal = true
		if r.cfg.TakeTerminal != nil {
			if err := r.cfg.TakeTerminal(); err != nil {
				_ = client.Close()
				return attempted{err: err}
			}
		}
		if r.cfg.Input != nil {
			r.in.start()
		}
	}

	end, err := r.session(client, lc, ev.selected, by)
	if err != nil {
		return attempted{v: classifySetup(err, ev), offered: offered, selected: ev.selected}
	}
	return attempted{session: end, offered: offered, selected: ev.selected}
}

// candidates is signers without the keys that are refused or sitting out.
func (r *runner) candidates(signers []ssh.Signer) []ssh.Signer {
	var out []ssh.Signer
	for _, s := range signers {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		if !r.refused[fp] && !r.sitOut[fp] {
			out = append(out, s)
		}
	}
	return out
}

// session runs one session on client. An error means the shell never
// started, and Terminal has closed client.
func (r *runner) session(client *ssh.Client, lc *liveness.Conn, key ssh.PublicKey, setupBy time.Time) (*sessionEnd, error) {
	end := &sessionEnd{}
	v := r.in.session()

	term := *r.cfg.Terminal
	term.Stdin = v
	// Until the session is ready and the guest has been told, its writes go
	// nowhere: a session whose start is stopped, its Joined line still being
	// written, writes nothing at all, not even its mode restore, and so can't
	// be held up by the terminal the line is stuck on.
	out := &gatedWriter{w: term.Stdout}
	term.Stdout = out
	// The pty request carries the size measured now. A resize that arrived
	// between sessions is older than that, and would follow it.
	if term.Resizes != nil {
		drain(term.Resizes)
	}
	if term.Pty != nil {
		pty := *term.Pty
		if r.cfg.Size != nil {
			pty.Size = r.cfg.Size()
		}
		term.Pty = &pty
	}
	// Terminal writes no output until OnReady returns, and the view gets no
	// keys until it is activated: so the guest is told first, and only then
	// does the session get the screen and the keyboard.
	term.OnReady = func() {
		e := Event{Kind: Joined}
		if r.joined {
			e.Rejoin, e.Down = true, max(0, r.timing.Wall().Sub(r.since))
		}
		// The shell has started, so a first join has got in, and the deadline
		// it had for that doesn't bound the Joined line.
		if !r.emit(r.runCtx, e) {
			return
		}
		end.ready, end.readyAt = true, time.Now()
		r.ready(key)
		v.activate()
		out.open.Store(true)
	}
	run := r.cfg.runSession
	if run == nil {
		run = term.Run
	}

	// Liveness closes the connection, never runCtx: a silent peer is a
	// session lost, to be rejoined, and not the guest leaving.
	sessCtx, endSession := context.WithCancel(r.runCtx)
	watched := make(chan struct{})
	var dead error
	go func() {
		defer close(watched)
		liveness.Watch(sessCtx, r.timing.Liveness, lc.LastRead, func() error {
			_, _, err := client.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
			return err
		}, func(err error) {
			dead = err
			_ = client.Close()
		})
	}()

	res, err := run(r.runCtx, client, setupBy)
	endSession()
	<-watched
	_ = client.Close()
	_ = v.Close()
	if err != nil {
		return nil, err
	}
	end.res = res
	end.err = dead
	if end.err == nil {
		// Closed above, so this returns with whatever ended the connection
		// first.
		end.err = client.Wait()
	}
	return end, nil
}

// ready marks a session ready: its key got in, and a new round starts.
func (r *runner) ready(key ssh.PublicKey) {
	if key != nil {
		r.joinedWith[ssh.FingerprintSHA256(key)] = true
	}
	clear(r.sitOut)
	r.joined = true
	r.since = time.Time{}
}

// next decides what follows an attempt.
func (r *runner) next(a attempted) step {
	switch {
	case a.session != nil:
		return r.ended(a.session)
	case r.runCtx.Err() != nil:
		return finish(r.stopped())
	case a.err != nil:
		return finish(failed(a.err))
	case a.exhausted:
		return r.exhausted()
	}

	v := a.v
	switch v.kind {
	case vWait:
		if a.cut && v.why != IdentityFailure {
			// An attempt the first join's deadline cut short says nothing about
			// the relay or the session, and its error is the cut's own doing: a
			// closed connection, a socket's timeout. The join ends wrapping
			// what it last waited on, or else the deadline. A signer that
			// failed is the exception: whatever stopped it, the guest's own
			// identity failing is what a first join stops on (see wait).
			return finish(r.timedOut(v.why, context.DeadlineExceeded))
		}
		return waitThen(v.why, v.err)
	case vHostKeyUnknown:
		return r.unknownHostKey(v, a.hostKey)
	case vRetryNow:
		// The session's node refused the one key the entry node let in.
		// x/crypto stops offering keys at the first one the entry accepts, so
		// the rest haven't been tried: they get their turn at once.
		if a.selected == nil {
			return finish(failed(&RefusedError{}))
		}
		r.refused[ssh.FingerprintSHA256(a.selected)] = true
		// Should a first join's time run out before the next key has its
		// turn, what it met was a session that wouldn't start.
		return r.again(Setup, v.err)
	case vAmbiguous:
		if a.selected == nil {
			return finish(failed(&RefusedError{}))
		}
		fp := ssh.FingerprintSHA256(a.selected)
		if r.joinedWith[fp] {
			return waitThen(NoHost, nil)
		}
		r.sitOut[fp] = true
		// Refused, or no session: should a first join's time run out first,
		// it is taken for no session, as a rejoin takes it.
		return r.again(NoHost, nil)
	}

	// vStop. A refusal at the entry node with no evidence that it was one
	// could be a session that isn't there. On a rejoin, where a key it turned
	// away has been in before, that is what it is taken for.
	var refused *RefusedError
	if errors.As(v.err, &refused) && refused.Ambiguous && r.joined && r.offeredJoined(a.offered) {
		return waitThen(NoHost, nil)
	}
	return finish(failed(v.err))
}

func (r *runner) offeredJoined(offered []ssh.Signer) bool {
	for _, s := range offered {
		if r.joinedWith[ssh.FingerprintSHA256(s.PublicKey())] {
			return true
		}
	}
	return false
}

// exhausted decides what follows an attempt with no key left to offer.
func (r *runner) exhausted() step {
	switch {
	case !r.joined:
		return finish(failed(&RefusedError{Ambiguous: len(r.sitOut) > 0}))
	case len(r.sitOut) > 0:
		// Every key left sat out an ambiguous refusal, which a node that
		// predates the refined verdicts also gives a session that isn't
		// there. On a rejoin that is the likelier story: wait for the
		// session, and start a new round with every key.
		clear(r.sitOut)
		return waitThen(NoHost, nil)
	}
	return finish(failed(&RefusedError{}))
}

// unknownHostKey asks the guest about the relay's key, if anyone may still
// ask. The connection is already closed, and the first join's clock stops
// for as long as the guest takes.
func (r *runner) unknownHostKey(v verdict, key ssh.PublicKey) step {
	if r.tookTerminal || r.cfg.ConfirmHostKey == nil {
		return finish(failed(&HostKeyError{Err: v.err}))
	}
	start := time.Now()
	accepted, err := r.cfg.ConfirmHostKey(r.runCtx, r.cfg.Target.Host, key)
	if !r.deadline.IsZero() {
		r.deadline = r.deadline.Add(time.Since(start))
	}
	switch {
	case r.runCtx.Err() != nil:
		return finish(r.stopped())
	case err != nil:
		return finish(failed(&HostKeyError{Err: err}))
	case !accepted:
		return finish(failed(&HostKeyError{Declined: true}))
	}
	return attemptNow
}

// ended decides what follows a session that ran.
func (r *runner) ended(s *sessionEnd) step {
	r.last = r.handOver(s.res)
	switch {
	case s.res.Reason == attach.Exited:
		return finish(Outcome{Kind: Exited, Status: s.res.Status})
	case r.runCtx.Err() != nil:
		// Whatever Terminal made of it, a session that ended with the run
		// ended because Run stopped it.
		return finish(r.stopped())
	case s.res.Reason == attach.Detached:
		return finish(Outcome{Kind: Left})
	}

	// Disconnected: lost, to be rejoined.
	if s.ready {
		r.sched.ready(time.Since(s.readyAt))
	}
	r.beginWait(r.timing.Wall())
	// The terminal is handed over before the guest is told: a line written
	// while a parked write still holds the alternate screen would land there,
	// and the restore would take it away again. The wait has no bound, but a
	// stop ends it.
	select {
	case <-r.last.done:
	case <-r.runCtx.Done():
		return finish(r.stopped())
	}
	if !r.emit(r.runCtx, Event{Kind: Lost, Why: Unreachable, Err: s.err}) {
		return finish(r.stopped())
	}
	return waitThen(Unreachable, s.err)
}

// handover is a session letting go of the terminal: once its writes have
// returned (Released), the restore it left (Unrestored) is written. Nothing
// else writes to the terminal until it is done, which the next session waits
// for. Its own goroutine does the waiting, so that a run that stops meanwhile
// can still give it a bounded chance to finish.
type handover struct {
	done   chan struct{} // the restore has been written, there was none, or finish gave up on it
	gaveUp chan struct{} // closed by finish
	state  atomic.Int32
}

const (
	handoverPending int32 = iota
	handoverWriting
	handoverLate
)

func (r *runner) handOver(res attach.Result) *handover {
	h := &handover{done: make(chan struct{}), gaveUp: make(chan struct{})}
	go func() {
		defer close(h.done)
		if res.Released != nil {
			select {
			case <-res.Released:
			case <-h.gaveUp:
				return
			}
		}
		if len(res.Unrestored) > 0 && h.state.CompareAndSwap(handoverPending, handoverWriting) {
			_, _ = r.cfg.Terminal.Stdout.Write(res.Unrestored)
		}
	}()
	return h
}

// finish is the end of the run: it waits at most finalBound for h, and past
// that nothing more is written.
func (h *handover) finish() {
	logging.Within(finalBound, func() { <-h.done })
	h.state.CompareAndSwap(handoverPending, handoverLate)
	close(h.gaveUp)
}

// wait waits out a verdict before the next attempt. It returns false, with
// the outcome, if the run ends instead.
func (r *runner) wait(why WaitReason, err error) (Outcome, bool) {
	first := !r.joined
	// The guest's own identity failing won't mend by waiting: a first join
	// stops on it.
	if first && why == IdentityFailure {
		return failed(err), false
	}
	// The wait, its status line included, ends with ctx: with the run, and on
	// a first join at its deadline too. A line the terminal is slow to take
	// uses up the first join's time as the rest of the wait does, and one it
	// never takes is abandoned at the deadline, as a stop abandons it.
	ctx := r.runCtx
	var left time.Duration
	if r.firstJoin() {
		// An attempt that ended after the first join's time ran out doesn't
		// replace the reason the join was waiting on.
		if left = time.Until(r.deadline); left <= 0 {
			return r.timedOut(why, err), false
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(r.runCtx, r.deadline)
		defer cancel()
	}
	if first {
		r.lastWhy, r.lastErr = why, err
	}

	now := r.timing.Wall()
	r.beginWait(now)
	delay, long := r.sched.next(time.Since(r.waitFrom))
	if r.firstJoin() {
		delay = min(delay, left)
	}

	retry := make(chan struct{}, 1)
	r.mu.Lock()
	r.retry = retry
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.retry = nil
		r.mu.Unlock()
	}()

	e := Event{Kind: Waiting, Why: why, Err: err, Since: r.since, Next: now.Add(delay), Long: long, First: first}
	if !r.emit(ctx, e) || waitFor(ctx, r.timing, delay, retry) != nil {
		if r.runCtx.Err() != nil {
			return r.stopped(), false
		}
		// The first join's time ran out during the line or the wait after it.
		return r.timedOut(why, err), false
	}
	return Outcome{}, true
}

// beginWait notes that a wait began at wall, now, unless one is under way.
func (r *runner) beginWait(wall time.Time) {
	if r.since.IsZero() {
		r.since, r.waitFrom = wall, time.Now()
	}
}

// emit tells the guest about e, and returns once that has been written,
// or false once ctx has ended: the run's, or one that ends sooner.
func (r *runner) emit(ctx context.Context, e Event) bool {
	if r.cfg.Events == nil {
		return ctx.Err() == nil
	}
	return call(ctx, func() { r.cfg.Events(e) })
}

// call runs fn, a write to the guest's terminal, on its own goroutine, and
// waits for it to return or for ctx to end. A write stuck on a terminal that
// isn't taking output is abandoned with the process, so it never keeps
// Ctrl-C, a signal or a first join's deadline from ending the run.
func call(ctx context.Context, fn func()) bool {
	// A run that has stopped, or a first join whose time is up, starts no
	// write: the command's own last line is what follows.
	if ctx.Err() != nil {
		return false
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

// gatedWriter passes writes on to w once open, and before then drops them,
// reporting success.
type gatedWriter struct {
	w    io.Writer
	open atomic.Bool
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	if !g.open.Load() {
		return len(p), nil
	}
	return g.w.Write(p)
}

// drain takes whatever c holds without waiting for more.
func drain(c <-chan termsize.Size) {
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		default:
			return
		}
	}
}
