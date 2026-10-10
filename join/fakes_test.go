package join

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testTimeout bounds every wait a test makes on a run.
const testTimeout = 10 * time.Second

// noHostBanner is the banner of a relay that has no host for session abc.
var noHostBanner = fmt.Sprintf(upterm.BannerNoHostFormat, "abc")

// recv receives from c, failing the test if nothing arrives within
// testTimeout.
func recv[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(testTimeout):
		t.Fatal("nothing arrived in time")
		var zero T
		return zero
	}
}

// fakeRelay is a relay that serves each connection with its own relayKnobs,
// for a run that connects more than once.
type fakeRelay struct {
	scripts []relayKnobs
	addr    string

	mu     sync.Mutex
	dialed []*relayConn // join's side of each connection, in the order dialed
	seen   []*connLog   // the relay's side, in the order accepted
}

// newFakeRelay serves connection i with scripts[min(i, len(scripts)-1)].
func newFakeRelay(t *testing.T, scripts ...relayKnobs) *fakeRelay {
	t.Helper()
	require.NotEmpty(t, scripts)
	r := &fakeRelay{scripts: scripts}
	hostKey := newSigner(t)
	r.addr = listen(t, func(i int, conn net.Conn) { r.script(i).serve(conn, hostKey, r.log(i)) })
	return r
}

func (r *fakeRelay) script(i int) relayKnobs { return r.scripts[min(i, len(r.scripts)-1)] }

// log is connection i's record, created on first use.
func (r *fakeRelay) log(i int) *connLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.seen) <= i {
		r.seen = append(r.seen, &connLog{})
	}
	return r.seen[i]
}

// Dial is a Config.Dial. Attempts are sequential, so the order dialed is the
// order accepted, and connection i is the same connection on both sides.
func (r *fakeRelay) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rc := &relayConn{Conn: c, i: len(r.dialed)}
	r.dialed = append(r.dialed, rc)
	return rc, nil
}

// checkHostKey is a Config.CheckHostKey that says what the knobs of the
// connection being checked say.
func (r *fakeRelay) checkHostKey(host string, remote net.Addr, _ ssh.PublicKey) error {
	addr, ok := remote.(relayAddr)
	if !ok {
		return fmt.Errorf("fixture: %v is not a connection the fake relay dialed", remote)
	}
	k := r.script(addr.conn)
	switch {
	case k.hostKeyUnknown:
		return fmt.Errorf("%s: %w", host, ErrHostKeyUnknown)
	case k.hostKeyChanged:
		return fmt.Errorf("%s: %w", host, ErrHostKeyChanged)
	}
	return nil
}

func (r *fakeRelay) connections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dialed)
}

// authenticatedWith is the key connection i authenticated with; nil if none.
func (r *fakeRelay) authenticatedWith(i int) ssh.PublicKey {
	l := r.log(i)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.key
}

// connOpen reports whether join's side of connection i is still open. It is
// join's side because the relay learns of a close only some time after it.
func (r *fakeRelay) connOpen(i int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return i < len(r.dialed) && !r.dialed[i].closed.Load()
}

// ptySizes is the size of every pty request, in order.
func (r *fakeRelay) ptySizes() []termsize.Size {
	r.mu.Lock()
	seen := append([]*connLog(nil), r.seen...)
	r.mu.Unlock()
	var sizes []termsize.Size
	for _, l := range seen {
		l.mu.Lock()
		sizes = append(sizes, l.ptys...)
		l.mu.Unlock()
	}
	return sizes
}

// windowChanges is every window change connection i's session received.
func (r *fakeRelay) windowChanges(i int) []termsize.Size {
	l := r.log(i)
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]termsize.Size(nil), l.windows...)
}

// input is everything connection i's session received, once its input has
// ended; the test fails if that takes longer than testTimeout.
func (r *fakeRelay) input(t *testing.T, i int) string {
	t.Helper()
	l := r.log(i)
	recv(t, l.inputEnded())
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.input.String()
}

// relayConn is join's side of one connection: it notes its close, and its
// RemoteAddr says which connection it is, for checkHostKey.
type relayConn struct {
	net.Conn
	i      int
	closed atomic.Bool
}

func (c *relayConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *relayConn) RemoteAddr() net.Addr { return relayAddr{Addr: c.Conn.RemoteAddr(), conn: c.i} }

// relayAddr is the relay's address on connection conn.
type relayAddr struct {
	net.Addr
	conn int
}

type option func(*Config)

// config is a Config on relay: a Terminal on a syncSink, one generated signer,
// CheckHostKey per the knobs, Escape '~', an Input nobody types on, and short
// timings.
func config(t *testing.T, relay *fakeRelay, opts ...option) Config {
	t.Helper()
	// Nothing is ever written, so a Read blocks: an empty reader would be EOF,
	// which is the guest's terminal going away.
	idle, _ := io.Pipe()
	cfg := Config{
		Target:       Target{Scheme: "ssh", User: "abc", Host: relay.addr},
		Dial:         relay.Dial,
		CheckHostKey: relay.checkHostKey,
		Terminal:     &attach.Terminal{Stdout: &syncSink{}, Pty: &attach.Pty{Term: "xterm"}, Escape: '~'},
		Input:        idle,
		Escape:       '~',
		Timing: Timing{
			FastBase:  10 * time.Millisecond,
			FastCap:   40 * time.Millisecond,
			FirstJoin: 300 * time.Millisecond,
			Attempt:   200 * time.Millisecond,
			Liveness:  liveness.Timing{Interval: 50 * time.Millisecond, Bound: 50 * time.Millisecond},
			WallCheck: 10 * time.Millisecond,
		},
	}
	withSigners(newSigner(t))(&cfg)
	cfg.Identity.Source = KeySource{Generated: true}
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

func withSigners(signers ...ssh.Signer) option {
	return func(c *Config) {
		c.Identity.Signers = func(context.Context) ([]ssh.Signer, func(), error) { return signers, func() {}, nil }
	}
}

func withIdentity(id Identity) option { return func(c *Config) { c.Identity = id } }

func withConfirm(confirm *countingConfirm) option {
	return func(c *Config) { c.ConfirmHostKey = confirm.confirm }
}

func withTakeTerminal(take func() error) option { return func(c *Config) { c.TakeTerminal = take } }

func withEvents(rec *recorder) option { return func(c *Config) { c.Events = rec.event } }

func withStdout(w io.Writer) option { return func(c *Config) { c.Terminal.Stdout = w } }

func withInput(r io.Reader) option { return func(c *Config) { c.Input = r } }

func withSize(size func() termsize.Size) option { return func(c *Config) { c.Size = size } }

func withWait() option { return func(c *Config) { c.Wait = true } }

// runJoin runs cfg to its outcome, failing the test if that takes longer than
// testTimeout.
func runJoin(t *testing.T, cfg Config) Outcome {
	t.Helper()
	select {
	case out := <-runJoinAsync(t, context.Background(), cfg):
		return out
	case <-time.After(testTimeout):
		t.Fatal("the run didn't end")
		return Outcome{}
	}
}

// runJoinAsync starts cfg under ctx; its outcome arrives on the channel.
func runJoinAsync(t *testing.T, ctx context.Context, cfg Config) <-chan Outcome {
	t.Helper()
	done := make(chan Outcome, 1)
	go func() { done <- Run(ctx, cfg) }()
	return done
}

// recorder is an Events sink. With gate set, each call waits for one receive
// from gate: a send lets one call through, a close lets every call through.
// held (buffered, 64) delivers each event as its call begins. w, when set,
// also gets "<KIND>" (e.g. "<JOINED>") written for each event as its call is
// let through, so its order against the session's output is visible.
type recorder struct {
	gate chan struct{}
	w    io.Writer

	once   sync.Once
	heldc  chan Event
	mu     sync.Mutex
	events []Event
}

func (r *recorder) init() { r.once.Do(func() { r.heldc = make(chan Event, 64) }) }

func (r *recorder) event(e Event) {
	r.init()
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	// Dropped once the buffer is full: a test that doesn't read held must not
	// be what holds a run up.
	select {
	case r.heldc <- e:
	default:
	}
	if r.gate != nil {
		<-r.gate
	}
	if r.w != nil {
		_, _ = io.WriteString(r.w, "<"+kindNames[e.Kind]+">")
	}
}

var kindNames = map[EventKind]string{Joined: "JOINED", Lost: "LOST", Waiting: "WAITING"}

func (r *recorder) held() <-chan Event {
	r.init()
	return r.heldc
}

func (r *recorder) kinds() []EventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	kinds := make([]EventKind, len(r.events))
	for i, e := range r.events {
		kinds[i] = e.Kind
	}
	return kinds
}

// await returns the first event that match accepts, of those not yet taken
// from held. It fails the test if the run ends, with its outcome on done,
// before such an event, or if none comes within testTimeout.
func (r *recorder) await(t *testing.T, done <-chan Outcome, match func(Event) bool) Event {
	t.Helper()
	timeout := time.After(testTimeout)
	for {
		select {
		case e := <-r.held():
			if match(e) {
				return e
			}
		case out := <-done:
			// The event may have come before the end did.
			for len(r.held()) > 0 {
				if e := <-r.held(); match(e) {
					return e
				}
			}
			t.Fatalf("the run ended (%+v) before the event it was to send", out)
		case <-timeout:
			t.Fatal("the event didn't come")
		}
	}
}

// all is every event, in order.
func (r *recorder) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// waits is every Waiting event, in order.
func (r *recorder) waits() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var waits []Event
	for _, e := range r.events {
		if e.Kind == Waiting {
			waits = append(waits, e)
		}
	}
	return waits
}

// countingConfirm is a ConfirmHostKey. block: wait for ctx. during: runs
// inside the call. err: what the call fails with.
type countingConfirm struct {
	accept, block bool
	during        func()
	err           error

	once    sync.Once
	calledc chan struct{}
	n       atomic.Int32
}

func (c *countingConfirm) init() { c.once.Do(func() { c.calledc = make(chan struct{}) }) }

func (c *countingConfirm) confirm(ctx context.Context, _ string, _ ssh.PublicKey) (bool, error) {
	c.init()
	if c.n.Add(1) == 1 {
		close(c.calledc)
	}
	if c.during != nil {
		c.during()
	}
	if c.block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return c.accept, c.err
}

func (c *countingConfirm) calls() int { return int(c.n.Load()) }

// called closes when the first call begins.
func (c *countingConfirm) called() <-chan struct{} {
	c.init()
	return c.calledc
}

// blockingSigner's Sign closes entered (if set), blocks until until is
// closed, then fails, as an attemptAgent's signature does when its
// connection is closed.
type blockingSigner struct {
	ssh.Signer
	until   <-chan struct{}
	entered chan struct{}
}

// entering closes each entered channel once, however many signatures wait on
// it: blockingSigner is copied by value, so the Once can't live in it.
var entering sync.Map // chan struct{} -> *sync.Once

func (s blockingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	if s.entered != nil {
		once, _ := entering.LoadOrStore(s.entered, new(sync.Once))
		once.(*sync.Once).Do(func() { close(s.entered) })
	}
	<-s.until
	return nil, errors.New("the agent's connection was closed")
}

func intp(i int) *int { return &i }

// newGate returns a gate and the func that opens it. The gate opens when the
// test ends, too, so that nothing parked on it outlives the test.
func newGate(t *testing.T) (gate <-chan struct{}, open func()) {
	c := make(chan struct{})
	open = sync.OnceFunc(func() { close(c) })
	t.Cleanup(open)
	return c, open
}

// press types keys on w, the guest's keyboard, without waiting for them to
// be read.
func press(w io.Writer, keys string) {
	go func() { _, _ = io.WriteString(w, keys) }()
}

// rejectedWith is the error Terminal.Run returns for a session channel the
// relay rejected with msg.
func rejectedWith(msg string) error {
	return fmt.Errorf("attach: %w", &ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: msg})
}

// deadlineOf is the DeadlineError out ended with.
func deadlineOf(t *testing.T, out Outcome) *DeadlineError {
	t.Helper()
	var dl *DeadlineError
	require.ErrorAs(t, out.Err, &dl, "%+v", out)
	return dl
}

// stuckWriter is a terminal that has stopped taking output: each Write blocks
// until the test ends. It counts the bytes it was offered.
type stuckWriter struct {
	offered atomic.Int64
	until   chan struct{}
}

func newStuckWriter(t *testing.T) *stuckWriter {
	w := &stuckWriter{until: make(chan struct{})}
	t.Cleanup(func() { close(w.until) })
	return w
}

func (w *stuckWriter) Write(p []byte) (int, error) {
	w.offered.Add(int64(len(p)))
	<-w.until
	return len(p), nil
}

// heldWriter is a terminal that is slow to take output: entered closes as
// the first Write begins, and every Write waits for let.
type heldWriter struct {
	syncSink
	entered, let chan struct{}
	once         sync.Once
}

func (w *heldWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.let
	return w.syncSink.Write(p)
}

// syncSink is a Stdout that a test can read while the run writes it.
type syncSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
