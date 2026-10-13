package ftests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/relaydial"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/join"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/protobuf/proto"
)

// joinTiming paces the guests here. A first join has 5 s, room for the
// handshakes a join through another node takes, two or three of them when
// keys are refused, under -race on a loaded CI runner, and still within
// joinWaitBound. The waits between attempts are short, so a guest rejoins
// within moments of a drop. An attempt gets 2 s, an SSH handshake's budget
// under -race, as redialTiming's do. Liveness is redialTiming's: no case
// relies on it to notice a drop, since a cut closes both ends, and a shorter
// one could drop a healthy connection under -race.
var joinTiming = join.Timing{
	FirstJoin: 5 * time.Second,
	FastBase:  20 * time.Millisecond,
	FastCap:   200 * time.Millisecond,
	Attempt:   2 * time.Second,
	Liveness:  liveness.Timing{Interval: redialTiming.PingInterval, Bound: redialTiming.PingBound},
}

const (
	// joinWaitBound bounds each wait on a guest: an event, a line of output,
	// a key being taken, and the run returning once stopped.
	joinWaitBound = 10 * time.Second
	// retypeAfter is how long typeUntil waits for a line's output before
	// typing the line again.
	retypeAfter = time.Second
)

// guestOpts is how joinGuest's guest differs from the default: the
// authorized client key, a relay trusted by its exact key, and no prompt.
type guestOpts struct {
	signers  []ssh.Signer   // default: ClientPrivateKey's signer
	identity *join.Identity // overrides signers: e.g. a host.GuestIdentity's
	wait     bool
	// knownHosts, when set, has the relay's key checked by host.KnownHosts
	// against this file; by default the test relay's key is trusted exactly.
	knownHosts string
	// confirm, when set, is ConfirmHostKey, and every call to it is counted.
	confirm func(ctx context.Context, hostname string, key ssh.PublicKey) (bool, error)
	timing  *join.Timing // default: joinTiming
}

// guestRun is a join.Run in progress. It dials the relay through a forwarder
// of its own, so cut can drop the guest's connection. Its sink is the
// guest's terminal: the session's output and a marker for each event, in
// the order join wrote them.
type guestRun struct {
	t        *testing.T
	sink     *syncSink
	stdin    *io.PipeWriter
	fwd      *testhelpers.Forwarder
	done     chan struct{}
	out      join.Outcome // set before done closes
	confirms atomic.Int32
}

// joinGuest starts a guest joining session at clientJoinURL, the way upterm
// join would, and stops it when the test ends.
func joinGuest(t *testing.T, clientJoinURL string, session *api.GetSessionResponse, o guestOpts) *guestRun {
	t.Helper()
	relay, err := url.Parse(clientJoinURL)
	require.NoError(t, err)
	// The target names the relay itself, which the relay's key is checked
	// for; only the dial goes through the forwarder.
	target := join.Target{Scheme: relay.Scheme, User: session.SshUser, Host: relay.Host}
	fwd := testhelpers.NewForwarder(t, relay.Host)
	dialed := &url.URL{Scheme: relay.Scheme, Host: fwd.Addr()}

	signers := o.signers
	if signers == nil {
		signers = []ssh.Signer{clientSigner(t)}
	}
	identity := fixedIdentity(signers)
	if o.identity != nil {
		identity = *o.identity
	}
	check := trustTestRelay(t)
	if o.knownHosts != "" {
		check = knownHostsCheck(o.knownHosts)
	}

	stdin, typed := io.Pipe()
	g := &guestRun{t: t, sink: newSyncSink(), stdin: typed, fwd: fwd, done: make(chan struct{})}
	cfg := join.Config{
		Target: target,
		Dial: func(ctx context.Context) (net.Conn, error) {
			conn, _, err := relaydial.Dial(ctx, dialed, target.User, true, nil)
			return conn, err
		},
		Identity:     identity,
		CheckHostKey: check,
		Terminal: &attach.Terminal{
			Stdout: g.sink,
			Pty:    &attach.Pty{Term: "xterm", Size: termsize.Size{Cols: 80, Rows: 24}},
			Escape: '~',
			Logger: testLogger,
		},
		Input:  stdin,
		Events: g.sink.event,
		Wait:   o.wait,
		Timing: joinTiming,
	}
	if o.timing != nil {
		cfg.Timing = *o.timing
	}
	if o.confirm != nil {
		cfg.ConfirmHostKey = func(ctx context.Context, hostname string, key ssh.PublicKey) (bool, error) {
			g.confirms.Add(1)
			return o.confirm(ctx, hostname, key)
		}
	}

	ctx, stop := context.WithCancel(context.Background())
	go func() {
		defer close(g.done)
		g.out = join.Run(ctx, cfg)
	}()
	// Registered after the forwarder's cleanup, so it runs first: the run
	// stops while its connection is still there to close.
	t.Cleanup(func() {
		stop()
		_ = typed.Close()
		select {
		case <-g.done:
		case <-time.After(joinWaitBound):
			t.Errorf("join.Run didn't return within %s of its stop", joinWaitBound)
		}
	})
	return g
}

// send types s at the guest's terminal. It returns once join's reader has
// taken it, which is not to say a session has.
func (g *guestRun) send(s string) {
	g.t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(g.stdin, s)
		written <- err
	}()
	select {
	case err := <-written:
		require.NoError(g.t, err, "typing %q", s)
	case <-time.After(joinWaitBound):
		g.fail(g.t, "typing %q: join didn't take it within %s", s, joinWaitBound)
	}
}

// typeUntil types line at the session, and again each retypeAfter, until want
// shows in the output, for at most joinWaitBound. join hands a session the
// keyboard only once its Joined event has been delivered, so a line typed as
// that event arrives can reach join instead, which drops it. Typing again is
// harmless for a line that only prints.
func (g *guestRun) typeUntil(t *testing.T, line, want string) {
	t.Helper()
	deadline := time.Now().Add(joinWaitBound)
	shows := func(out string, _ []join.Event) bool { return strings.Contains(out, want) }
	for {
		g.send(line + shellLineEnding())
		left := time.Until(deadline)
		if g.poll(min(retypeAfter, left), shows) {
			return
		}
		if left <= retypeAfter || g.ended() {
			g.fail(t, "typing %q: no %q in the output within %s", line, want, joinWaitBound)
		}
		t.Logf("typing %q again: no %q after %s", line, want, retypeAfter)
	}
}

// ready waits until the session has the guest's keys: a line typed reaches
// the shell, and its answer comes back.
func (g *guestRun) ready(t *testing.T) {
	t.Helper()
	n := markers.Add(1)
	g.typeUntil(t, fmt.Sprintf("echo ready-$((%d+1))", n), fmt.Sprintf("ready-%d", n+1))
}

// waitEvent waits for an event of kind k; for Joined, a rejoin's if rejoin.
func (g *guestRun) waitEvent(t *testing.T, k join.EventKind, rejoin bool) {
	t.Helper()
	g.waitEventAfter(t, sinkMark{}, k, rejoin)
}

// waitEventAfter is waitEvent counting only the events after m, so that an
// event from before a drop the test caused can't stand for one after it.
func (g *guestRun) waitEventAfter(t *testing.T, m sinkMark, k join.EventKind, rejoin bool) {
	t.Helper()
	g.waitFor(t, fmt.Sprintf("an event %s", eventMarker(join.Event{Kind: k, Rejoin: rejoin})), func(_ string, events []join.Event) bool {
		for _, e := range events[m.events:] {
			if e.Kind == k && e.Rejoin == rejoin {
				return true
			}
		}
		return false
	})
}

// instanceLine is a line the forced command in
// testJoinForcedCommandEndsOnlyTheConnection prints as it starts.
var instanceLine = regexp.MustCompile(`instance-\d+\r?\n`)

// waitInstance returns the first "instance-<pid>" line in the output after m,
// once there is one.
func (g *guestRun) waitInstance(t *testing.T, m sinkMark) string {
	t.Helper()
	var line string
	g.waitFor(t, "an instance's line", func(out string, _ []join.Event) bool {
		found := instanceLine.FindString(out[m.output:])
		line = strings.TrimSpace(found)
		return found != ""
	})
	return line
}

// mark is where the guest's terminal is now: what a wait for what follows
// counts from.
func (g *guestRun) mark() sinkMark { return g.sink.mark() }

// cut drops the guest's connection to the relay, both ends, as a network
// that went away would, and returns the mark taken just before it.
func (g *guestRun) cut() sinkMark {
	m := g.mark()
	g.fwd.Cut()
	return m
}

// outcome waits, at most within, for the run to end, and returns how it did.
func (g *guestRun) outcome(t *testing.T, within time.Duration) join.Outcome {
	t.Helper()
	select {
	case <-g.done:
		return g.out
	case <-time.After(within):
		g.fail(t, "the run didn't end within %s", within)
		return join.Outcome{}
	}
}

// kinds is the kinds of the events so far, in order.
func (g *guestRun) kinds() []join.EventKind {
	var kinds []join.EventKind
	for _, e := range g.sink.snapshotEvents() {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// confirmCalls is how many times ConfirmHostKey has been called.
func (g *guestRun) confirmCalls() int { return int(g.confirms.Load()) }

// output is everything the guest's terminal has been given so far, the
// event markers included.
func (g *guestRun) output() string { return g.sink.String() }

func (g *guestRun) ended() bool {
	select {
	case <-g.done:
		return true
	default:
		return false
	}
}

// waitFor waits until cond holds of the output and events, and fails the test
// if it doesn't within joinWaitBound, or the run ends without it.
func (g *guestRun) waitFor(t *testing.T, what string, cond func(out string, events []join.Event) bool) {
	t.Helper()
	if !g.poll(joinWaitBound, cond) {
		g.fail(t, "%s: not within %s", what, joinWaitBound)
	}
}

// poll reports whether cond comes to hold of the output and events within
// within. It looks again at each write to the sink, and gives up once the
// run has ended: nothing writes after that but a write the run abandoned.
func (g *guestRun) poll(within time.Duration, cond func(out string, events []join.Event) bool) bool {
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		changed, ok := g.sink.check(cond)
		if ok {
			return true
		}
		select {
		case <-changed:
		case <-g.done:
			_, ok := g.sink.check(cond)
			return ok
		case <-timer.C:
			return false
		}
	}
}

// fail fails the test with what the guest saw: the run's outcome if it has
// ended, its events and its output.
func (g *guestRun) fail(t *testing.T, format string, args ...any) {
	t.Helper()
	state := "is still running"
	if g.ended() {
		state = fmt.Sprintf("ended %+v", g.out)
	}
	t.Fatalf("%s; the run %s; %d confirmations; events %+v; output %q",
		fmt.Sprintf(format, args...), state, g.confirmCalls(), g.sink.snapshotEvents(), g.output())
}

// syncSink is a guest's terminal: the session's output and a marker for each
// event, written as join delivers them.
type syncSink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	events  []join.Event
	changed chan struct{} // closed, and replaced, at each write
}

func newSyncSink() *syncSink { return &syncSink{changed: make(chan struct{})} }

func (s *syncSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(p)
	s.notifyLocked()
	return len(p), nil
}

// event is join.Config.Events. Its marker goes in with the output, so that
// whether a line was written before or after the session's bytes shows.
func (s *syncSink) event(e join.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.WriteString(eventMarker(e))
	s.events = append(s.events, e)
	s.notifyLocked()
}

func (s *syncSink) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// check reports whether cond holds now, and returns the channel the next
// write closes.
func (s *syncSink) check(cond func(out string, events []join.Event) bool) (<-chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed, cond(s.buf.String(), s.events)
}

// sinkMark is a point in a sink: how many events, and how many bytes of
// output, it held then.
type sinkMark struct{ events, output int }

func (s *syncSink) mark() sinkMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sinkMark{events: len(s.events), output: s.buf.Len()}
}

func (s *syncSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncSink) snapshotEvents() []join.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]join.Event(nil), s.events...)
}

// eventMarker is what the sink records for e.
func eventMarker(e join.Event) string {
	switch {
	case e.Kind == join.Joined && e.Rejoin:
		return "<REJOINED>"
	case e.Kind == join.Joined:
		return "<JOINED>"
	case e.Kind == join.Lost:
		return "<LOST>"
	case e.Kind == join.Waiting:
		return "<WAITING>"
	}
	return fmt.Sprintf("<EVENT %d>", e.Kind)
}

// fixedIdentity offers signers on every attempt.
func fixedIdentity(signers []ssh.Signer) join.Identity {
	return join.Identity{
		Signers: func(context.Context) ([]ssh.Signer, func(), error) { return signers, nil, nil },
		Source:  join.KeySource{Files: len(signers)},
	}
}

// trustTestRelay is a CheckHostKey that trusts the test relays' key and
// nothing else. They present it in a certificate.
func trustTestRelay(t *testing.T) ssh.HostKeyCallback {
	want := parseKey(t, ServerPublicKeyContent)
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if cert, ok := key.(*ssh.Certificate); ok {
			key = cert.Key
		}
		if !bytes.Equal(key.Marshal(), want.Marshal()) {
			return fmt.Errorf("%w: %s is not the test relay's key", join.ErrHostKeyChanged, ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

// knownHostsCheck is a CheckHostKey on host.KnownHosts.Check against file,
// whose refusals match join's sentinels as well as the host package's, and
// keep the host package's text.
func knownHostsCheck(file string) ssh.HostKeyCallback {
	kh := host.KnownHosts{File: file, Stdout: io.Discard}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh.Check(hostname, remote, key)
		switch {
		case errors.Is(err, host.ErrUnknownHostKey):
			return &relayKeyRefusal{err: err, as: join.ErrHostKeyUnknown}
		case errors.Is(err, host.ErrHostKeyChanged):
			return &relayKeyRefusal{err: err, as: join.ErrHostKeyChanged}
		}
		return err
	}
}

// relayKeyRefusal is KnownHosts.Check's refusal, err, as join's sentinel as.
type relayKeyRefusal struct{ err, as error }

func (e *relayKeyRefusal) Error() string   { return e.err.Error() }
func (e *relayKeyRefusal) Unwrap() []error { return []error{e.err, e.as} }

// autoYes is a ConfirmHostKey that accepts every key.
func autoYes(context.Context, string, ssh.PublicKey) (bool, error) { return true, nil }

// relayHostOf is the name the relay at rawURL has in known_hosts: join checks
// the relay's key for the target's host:port, so [127.0.0.1]:port.
func relayHostOf(rawURL string) string { return knownhosts.Normalize(mustParseURL(rawURL).Host) }

func writeTempKnownHosts(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func parseKey(t *testing.T, authorizedKey string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	require.NoError(t, err)
	return key
}

// otherPublicKey is a key no relay has, as an authorized_keys line.
func otherPublicKey(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newTestSigner(t).PublicKey())))
}

// newTestSigner is a key of the test's own, which no host authorizes.
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// clientSigner is the key a gated session authorizes: ClientPrivateKey's.
func clientSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(ClientPrivateKeyContent))
	require.NoError(t, err)
	return signer
}

// silentAgentSocket is an SSH agent's socket whose agent accepts every
// connection and never answers on it.
func silentAgentSocket(t *testing.T) string {
	t.Helper()
	// A short directory: a unix socket's path is limited in length.
	dir, err := os.MkdirTemp("", "ag")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
	require.NoError(t, err)

	var mu sync.Mutex
	var conns []net.Conn
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-accepting
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return ln.Addr().String()
}

// shareOpen shares a session on hostURL that any key may join, with opts
// applied to its host, and returns it. The host closes when the test ends.
func shareOpen(t *testing.T, hostURL, hostNodeAddr string, opts ...func(*Host)) *api.GetSessionResponse {
	t.Helper()
	h := &Host{
		Command:         getTestShell(),
		PrivateKeys:     []string{HostPrivateKey},
		AdminSocketFile: setupAdminSocket(t),
	}
	for _, opt := range opts {
		opt(h)
	}
	return shareHost(t, h, hostURL, hostNodeAddr)
}

// shareGated is shareOpen with ClientPublicKeyContent the one key authorized.
func shareGated(t *testing.T, hostURL, hostNodeAddr string) *api.GetSessionResponse {
	t.Helper()
	return shareOpen(t, hostURL, hostNodeAddr, func(h *Host) { h.PermittedClientPublicKey = ClientPublicKeyContent })
}

// testJoinRefusedAcrossNodesStops checks that a guest whose key the host
// doesn't authorize stops refused, and doesn't wait, even with --wait. Where
// the entry node completes the handshake and the route has a hop, the session's
// node states the refusal (upterm-hop: key refused, which the entry node passes
// on as "upstream refused the key"), and so it is definitive. Otherwise the
// guest's handshake is with the node that holds the authorized keys, which
// refuses the key while authenticating, and a dev build's version line is no
// evidence that the refusal was of the key rather than of a missing session.
func testJoinRefusedAcrossNodesStops(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	g := joinGuest(t, clientJoinURL, shareGated(t, hostURL, hostNodeAddr),
		guestOpts{signers: []ssh.Signer{newTestSigner(t)}, wait: true})
	out := g.outcome(t, 5*time.Second)
	require.Equal(t, join.Failed, out.Kind)
	require.ErrorIs(t, out.Err, join.ErrKeysRefused)
	require.NotContains(t, g.kinds(), join.Waiting)
	var refused *join.RefusedError
	require.ErrorAs(t, out.Err, &refused)
	if entryNodeCompletesHandshake(hostURL, clientJoinURL) {
		require.False(t, refused.Ambiguous, "the session's node stated the refusal")
	} else {
		require.True(t, refused.Ambiguous, "a refusal at authentication, from a relay whose version is no evidence")
	}
}

// testJoinSecondKeyGetsInAcrossNodes checks that of a guest's two keys, the
// first unauthorized, the second gets in. Through another node over ssh,
// the entry node lets the first key through and the session's node refuses
// it when the session opens, so the guest attempts again at once without it.
func testJoinSecondKeyGetsInAcrossNodes(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	g := joinGuest(t, clientJoinURL, shareGated(t, hostURL, hostNodeAddr),
		guestOpts{signers: []ssh.Signer{newTestSigner(t), clientSigner(t)}})
	g.waitEvent(t, join.Joined, false)
	g.typeUntil(t, "echo joined-$((1+1))", "joined-2")
}

// testJoinExitsWithTheSessionsStatus checks that when the session's command
// exits, the guest's run ends with its status.
func testJoinExitsWithTheSessionsStatus(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	g := joinGuest(t, clientJoinURL, shareOpen(t, hostURL, hostNodeAddr), guestOpts{})
	g.waitEvent(t, join.Joined, false)
	g.ready(t)
	g.send("exit 7" + shellLineEnding())
	require.Equal(t, join.Outcome{Kind: join.Exited, Status: 7}, g.outcome(t, 5*time.Second))
}

// testJoinAuthorizedUnauthorizedAndKeyless checks that on a session with an
// authorized key, that key joins and another is refused; on an open
// session, a guest with no key of its own joins with a generated one.
func testJoinAuthorizedUnauthorizedAndKeyless(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	gated := shareGated(t, hostURL, hostNodeAddr)
	joinGuest(t, clientJoinURL, gated, guestOpts{}).waitEvent(t, join.Joined, false)
	refused := joinGuest(t, clientJoinURL, gated, guestOpts{signers: []ssh.Signer{newTestSigner(t)}})
	require.ErrorIs(t, refused.outcome(t, 5*time.Second).Err, join.ErrKeysRefused)

	generated, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	joinGuest(t, clientJoinURL, shareOpen(t, hostURL, hostNodeAddr), guestOpts{signers: generated}).
		waitEvent(t, join.Joined, false)
}

// testJoinUnknownIDFailsAtTheDeadline checks that a session ID no relay knows
// waits as for a host that hasn't connected, and fails at the first join's
// deadline. Every topology and protocol ends the same way on relays
// that pass the next hop's verdict on: raw ssh into an embedded multi-node
// relay used to get the next hop's "unable to authenticate", while ws there
// always got the destination's banner (see TestBanner). The deadline is the
// thing under test, so it is 500 ms here rather than joinTiming's.
func testJoinUnknownIDFailsAtTheDeadline(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	session := shareOpen(t, hostURL, hostNodeAddr)
	bogus := proto.Clone(session).(*api.GetSessionResponse)
	bogus.SshUser = strings.Replace(session.SshUser, session.SessionId, "nosuchsession", 1)
	timing := joinTiming
	timing.FirstJoin = 500 * time.Millisecond
	start := time.Now()
	out := joinGuest(t, clientJoinURL, bogus, guestOpts{timing: &timing}).outcome(t, 5*time.Second)
	require.Equal(t, join.Failed, out.Kind)
	var dl *join.DeadlineError
	require.ErrorAs(t, out.Err, &dl)
	require.Equal(t, join.NoHost, dl.Why)
	require.Less(t, time.Since(start), timing.FirstJoin+time.Second)
}

// testJoinWithASilentAgentAndAnAuthorizedFile checks, end to end, that an
// agent that accepts a connection and never answers is skipped once its
// listing's time is up, and the key file, which the session authorizes,
// joins.
func testJoinWithASilentAgentAndAnAuthorizedFile(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	session := shareGated(t, hostURL, hostNodeAddr)
	g, err := host.NewGuestIdentity(context.Background(), host.GuestIdentityOptions{
		AgentSocket:  silentAgentSocket(t),
		AgentTimeout: 200 * time.Millisecond,
		Files:        []string{ClientPrivateKey},
	})
	require.NoError(t, err)
	id := join.Identity{Signers: g.Signers, Source: g.Source()}
	joinGuest(t, clientJoinURL, session, guestOpts{identity: &id}).waitEvent(t, join.Joined, false)
}

// testJoinRejoinNeverTrustsANewRelayKey checks that a rejoin checks the
// relay's key against known_hosts as a first join does, and never asks about
// it: a key known_hosts no longer trusts stops the run, though a prompt was
// possible before the first join. A relay trusted through an
// @cert-authority line needs an authority of its own:
// testJoinRejoinTrustsTheRelaysAuthority.
func testJoinRejoinNeverTrustsANewRelayKey(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	session := shareOpen(t, hostURL, hostNodeAddr)
	relayLine := func(key string) string {
		return knownhosts.Line([]string{relayHostOf(clientJoinURL)}, parseKey(t, key)) + "\n"
	}

	// (a) a changed key stops the rejoin, without a prompt.
	kh := writeTempKnownHosts(t, relayLine(ServerPublicKeyContent))
	g := joinGuest(t, clientJoinURL, session, guestOpts{knownHosts: kh, confirm: autoYes})
	g.waitEvent(t, join.Joined, false)
	require.NoError(t, os.WriteFile(kh, []byte(relayLine(otherPublicKey(t))), 0o600))
	g.cut()
	out := g.outcome(t, 5*time.Second)
	var hk *join.HostKeyError
	require.ErrorAs(t, out.Err, &hk)
	require.True(t, hk.Changed)
	require.Zero(t, g.confirmCalls())

	// (b) a key no longer known stops the rejoin, without a prompt.
	kh = writeTempKnownHosts(t, relayLine(ServerPublicKeyContent))
	g = joinGuest(t, clientJoinURL, session, guestOpts{knownHosts: kh, confirm: autoYes})
	g.waitEvent(t, join.Joined, false)
	require.NoError(t, os.WriteFile(kh, nil, 0o600))
	g.cut()
	require.ErrorIs(t, g.outcome(t, 5*time.Second).Err, join.ErrHostKey)
	require.Zero(t, g.confirmCalls())
}

// testJoinForcedCommandEndsOnlyTheConnection checks that a guest's forced
// command starts again on each rejoin, and when it exits, the guest's run
// ends with its status while the session carries on.
func testJoinForcedCommandEndsOnlyTheConnection(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string) {
	if runtime.GOOS == "windows" {
		t.Skip("the forced command is a POSIX shell script")
	}
	session := shareOpen(t, hostURL, hostNodeAddr, func(h *Host) {
		h.ForceCommand = []string{"sh", "-c", `echo "instance-$$"; read x; exit 3`}
	})
	g := joinGuest(t, clientJoinURL, session, guestOpts{})
	first := g.waitInstance(t, sinkMark{})
	m := g.cut()
	g.waitEventAfter(t, m, join.Joined, true)
	require.NotEqual(t, first, g.waitInstance(t, m), "a new instance on the rejoin")
	// The instance's line came after the session had the keyboard, so this
	// reaches its read.
	g.send("\n")
	require.Equal(t, join.Outcome{Kind: join.Exited, Status: 3}, g.outcome(t, 5*time.Second))
	// The session carries on: another guest still joins.
	joinGuest(t, clientJoinURL, session, guestOpts{}).waitEvent(t, join.Joined, false)
}

// testJoinRejoinsAfterTheHostsTunnelDrops checks that when the host's tunnel
// drops, the guest rejoins by itself once the host has redialled. The
// guest's terminal is put back, off the alternate screen, before it is told
// the session was lost.
func testJoinRejoinsAfterTheHostsTunnelDrops(t *testing.T, mode routing.Mode, protocol string) {
	if runtime.GOOS == "windows" {
		t.Skip("the session is driven with POSIX shell commands")
	}
	relay := newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, relay, redialTiming)
	g := joinGuest(t, relay.joinURL(protocol), h.first, guestOpts{})
	g.waitEvent(t, join.Joined, false)
	// The markers are computed, so the shell's echo of the typed line can't
	// match them: the line shows "$((40+2))x", the output "42x".
	g.typeUntil(t, `printf '\033[?1049h'; echo $((40+2))x`, "42x")
	m := g.mark()
	h.fwd.Cut() // the host's tunnel drops; the host redials the same relay
	g.waitEventAfter(t, m, join.Joined, true)
	out := g.output()[m.output:]
	restore, lost := strings.Index(out, "\x1b[?1049l"), strings.Index(out, "<LOST>")
	require.GreaterOrEqual(t, restore, 0, "no mode restore at all: %q", out)
	require.GreaterOrEqual(t, lost, 0, "no Lost marker: %q", out)
	require.Less(t, restore, lost, "the terminal is put back before the status line: %q", out)
	g.typeUntil(t, "echo $((50+8))y", "58y")
}

// testJoinRejoinTrustsTheRelaysAuthority checks that a relay whose
// certificate a trusted authority signed is trusted on the first join and
// again on the rejoin after a drop, and nobody is asked.
// The relay's certificate is signed by an authority of its own, and
// known_hosts holds only that authority's line, so nothing but the authority
// can trust the relay.
func testJoinRejoinTrustsTheRelaysAuthority(t *testing.T, mode routing.Mode, protocol string) {
	ca := newTestSigner(t)
	relay := newRedialRelay(t, mode, withHostCertAuthority(ca))
	joinURL := relay.joinURL(protocol)
	session := shareOpen(t, joinURL, relay.NodeAddr())
	kh := writeTempKnownHosts(t, "@cert-authority "+knownhosts.Line([]string{relayHostOf(joinURL)}, ca.PublicKey())+"\n")
	g := joinGuest(t, joinURL, session, guestOpts{knownHosts: kh, confirm: autoYes})
	g.waitEvent(t, join.Joined, false)
	g.waitEventAfter(t, g.cut(), join.Joined, true)
	require.Zero(t, g.confirmCalls())
}
