package server

import (
	"bytes"
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

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	// waitingMessage stands in for what an authority shows a guest whose key
	// it is waiting to see approved.
	waitingMessage = "Approve this SSH key\nOpen the authority's page and enter:\n\n    Q7MN-4K6P\n\nNo terminal access is granted on this connection.\n"
	// expiredMessage and approvedMessage are a screen's expired and approved
	// texts.
	expiredMessage  = "This code has expired. Ask for another.\n"
	approvedMessage = "This key was approved. Connect again.\n"
	// waitingUser is the claimed user a waiting guest types.
	waitingUser = claimPrefix + "add-ABC234"
)

// approval is a waiting screen as a fake authority holds it. Await reports
// each wait as it starts, and waits until the test decides it or its context
// ends, reporting that too. Once its context's deadline has passed, it ends
// with expired.
type approval struct {
	expires time.Time
	expired string
	waits   chan context.Context
	decide  chan awaitOutcome
	left    chan error
}

type awaitOutcome struct {
	target Target
	err    error
}

func newApproval(expires time.Time) *approval {
	return &approval{expires: expires, expired: expiredMessage, waits: make(chan context.Context, 16), decide: make(chan awaitOutcome), left: make(chan error, 16)}
}

func (a *approval) await(ctx context.Context) (Target, error) {
	a.waits <- ctx
	select {
	case o := <-a.decide:
		return o.target, o.err
	case <-ctx.Done():
		a.left <- ctx.Err()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Target{}, &WaitingEnded{Text: []byte(a.expired)}
		}
		return Target{}, ctx.Err()
	}
}

// waiting is the admission of a guest left waiting on a, shown message.
func (a *approval) waiting(message string) Admission {
	return Admission{Verdict: VerdictWaiting, Message: []byte(message), Waiting: &WaitingScreen{ExpiredMessage: []byte(a.expired), ApprovedMessage: []byte(approvedMessage), Expires: a.expires, Await: a.await}}
}

// waitingOn leaves every guest waiting on a, shown message, bound to the user
// it typed and the key it proved.
func waitingOn(message string, a *approval) func(context.Context, *Guest, GuestRequest) (Admission, error) {
	return func(_ context.Context, g *Guest, req GuestRequest) (Admission, error) {
		admission := a.waiting(message)
		admission.Waiting.OfferID = fixtureAccountID
		admission.Waiting.AttemptID = externalSessionID
		admission.Waiting.Address = req.User
		admission.Waiting.KeyFingerprint = g.Fingerprint
		return admission, nil
	}
}

// awaiting is the context of the next wait on a's decision.
func (a *approval) awaiting(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-a.waits:
		return ctx
	case <-time.After(10 * time.Second):
		t.Fatal("nothing waited on the screen")
		return nil
	}
}

// ended is why the next wait on a's decision ended without one.
func (a *approval) ended(t *testing.T) error {
	t.Helper()
	select {
	case err := <-a.left:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("a wait on the screen went on")
		return nil
	}
}

// decideIt hands o to the wait on a's decision.
func (a *approval) decideIt(t *testing.T, o awaitOutcome) {
	t.Helper()
	select {
	case a.decide <- o:
	case <-time.After(10 * time.Second):
		t.Fatal("nothing waited for the decision")
	}
}

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// waitingShell is a guest's shell started on a waiting screen: it has been
// shown the authority's message and is waiting on the screen.
type waitingShell struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  *syncBuffer
	// wait is the context of its wait.
	wait context.Context
}

// startWaitingShell starts a shell on guest, with terminal when it is set,
// and returns once it waits on a's decision. typed is written to it before
// its shell starts.
func startWaitingShell(t *testing.T, guest *ssh.Client, a *approval, message string, terminal *ptyRequestMsg, typed string) *waitingShell {
	t.Helper()
	sess, err := guest.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	stderr := &syncBuffer{}
	sess.Stderr = stderr
	want := message
	if terminal != nil {
		require.NoError(t, sess.RequestPty(terminal.Term, int(terminal.Rows), int(terminal.Columns), ssh.TerminalModes{ssh.ECHO: 0}))
		want = crlf(message)
	}
	if typed != "" {
		_, err = io.WriteString(stdin, typed)
		require.NoError(t, err)
	}
	require.NoError(t, sess.Shell())
	requireRead(t, stdout, want)
	return &waitingShell{session: sess, stdin: stdin, stdout: stdout, stderr: stderr, wait: a.awaiting(t)}
}

// rest is everything else the shell writes to stdout, until it exits, and
// how it exits.
func (s *waitingShell) rest(t *testing.T) (string, error) {
	t.Helper()
	type result struct {
		out []byte
		err error
	}
	ended := make(chan result, 1)
	go func() {
		out, _ := io.ReadAll(s.stdout)
		ended <- result{out, s.session.Wait()}
	}()
	select {
	case r := <-ended:
		return string(r.out), r.err
	case <-time.After(10 * time.Second):
		t.Fatal("the shell went on")
		return "", nil
	}
}

// ptyRequest is the terminal a test guest asks for, and the one the host is
// asked for.
func ptyRequest(rows, columns uint32) *ptyRequestMsg {
	return &ptyRequestMsg{Term: "xterm-256color", Columns: columns, Rows: rows, Width: columns * 8, Height: rows * 8,
		Modes: string(append(ssh.Marshal(struct {
			Op  byte
			Val uint32
		}{ssh.ECHO, 0}), 0))}
}

// terminalHost is a delegated host's end of its guests' sessions as a
// terminal's host sees them: it records the terminal each session asks for,
// each resize, each request and everything typed, and its shell says it has
// started and exits 7 once its guest types "bye".
type terminalHost struct {
	mu        sync.Mutex
	terminals []ptyRequestMsg
	resizes   []windowChangeMsg
	requests  []string
	typed     bytes.Buffer
	// ended counts the sessions that have closed.
	ended   atomic.Int32
	workers sync.WaitGroup
}

// hostStarted is what a terminalHost's shell says first.
const hostStarted = "host shell started\n"

// registerTerminalHost registers a host current on ts for externalSessionID,
// with a terminalHost taking its guests, and returns the target that is its
// registration, allowing a shell.
func registerTerminalHost(t *testing.T, ts *delegatedTestServer) (*terminalHost, Target) {
	t.Helper()
	host := newProven(t)
	client := dialHost(t, ts.addr, ts.signer, nil)
	ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	require.True(t, ok, "%q", body)
	ln, err := client.Listen("unix", host.id())
	require.NoError(t, err)
	h := &terminalHost{}
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil }}
	config.AddHostKey(host.key)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	h.workers.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			h.workers.Go(func() { h.serve(conn, config) })
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		joined := make(chan struct{})
		go func() { defer close(joined); h.workers.Wait() }()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Error("the guests' host did not stop")
		}
	})
	return h, Target{AccountID: fixtureAccountID, SessionID: externalSessionID, RoutingID: host.id(), RunPublicKey: host.key.PublicKey(), Capabilities: []string{"shell"}}
}

func (h *terminalHost) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	h.workers.Go(func() { ssh.DiscardRequests(reqs) })
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "no")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		h.workers.Go(func() { h.session(ch, requests) })
	}
}

func (h *terminalHost) session(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer h.ended.Add(1)
	defer func() { _ = ch.Close() }()
	for r := range requests {
		h.mu.Lock()
		h.requests = append(h.requests, r.Type)
		switch r.Type {
		case "pty-req":
			var m ptyRequestMsg
			if ssh.Unmarshal(r.Payload, &m) == nil {
				h.terminals = append(h.terminals, m)
			}
		case "window-change":
			var m windowChangeMsg
			if ssh.Unmarshal(r.Payload, &m) == nil {
				h.resizes = append(h.resizes, m)
			}
		}
		h.mu.Unlock()
		_ = r.Reply(true, nil)
		if r.Type == "shell" {
			h.workers.Go(func() { h.shell(ch) })
		}
	}
}

func (h *terminalHost) shell(ch ssh.Channel) {
	_, _ = io.WriteString(ch, hostStarted)
	buf := make([]byte, 32<<10)
	for {
		n, err := ch.Read(buf)
		h.mu.Lock()
		h.typed.Write(buf[:n])
		bye := bytes.HasSuffix(h.typed.Bytes(), []byte("bye\n"))
		h.mu.Unlock()
		if bye {
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
			_ = ch.Close()
			return
		}
		if err != nil {
			return
		}
	}
}

func (h *terminalHost) seen() ([]ptyRequestMsg, []windowChangeMsg, []string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ptyRequestMsg(nil), h.terminals...), append([]windowChangeMsg(nil), h.resizes...),
		append([]string(nil), h.requests...), h.typed.String()
}

func waitingGuest(t *testing.T, ts *delegatedTestServer) *ssh.Client {
	t.Helper()
	guest, _, err := dialDelegatedGuestAs(t, ts.addr, waitingUser, openSSHVersion, newProven(t).key)
	require.NoError(t, err)
	return guest
}

func TestWaitingRestrictedChannels(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	a := newApproval(time.Now().Add(10 * time.Minute))
	authority.admitWith(waitingOn(waitingMessage, a))
	guest := waitingGuest(t, ts)
	sess, err := guest.NewSession()
	require.NoError(t, err)
	for _, kind := range []string{"exec", "subsystem", "env", "x11-req", "auth-agent-req@openssh.com"} {
		ok, err := sess.SendRequest(kind, true, nil)
		require.NoError(t, err)
		require.False(t, ok, kind)
	}
	_, err = guest.NewSession()
	require.Error(t, err)
	_, err = guest.Dial("tcp", "127.0.0.1:22")
	require.Error(t, err)
	_, err = guest.Listen("tcp", "127.0.0.1:0")
	require.Error(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	requireRead(t, stdout, crlf(waitingMessage))
	a.awaiting(t)
	require.Empty(t, host.guests.guests())
	require.NoError(t, guest.Close())
	require.ErrorIs(t, a.ended(t), context.Canceled)
}

func TestWaitingExecRefused(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	a := newApproval(time.Now().Add(time.Minute))
	authority.admitWith(waitingOn(waitingMessage, a))
	guest := waitingGuest(t, ts)
	sess, err := guest.NewSession()
	require.NoError(t, err)
	require.Error(t, sess.Start("uptime"))
	require.Empty(t, a.waits)
}

func TestWaitingForwardingBeforeSession(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	a := newApproval(time.Now().Add(time.Minute))
	authority.admitWith(waitingOn(waitingMessage, a))
	guest := waitingGuest(t, ts)
	_, err := guest.Dial("tcp", "127.0.0.1:22")
	require.Error(t, err, "a waiting screen accepted forwarding")
}

func TestWaitingInputDiscarded(t *testing.T) {
	for _, terminal := range []*ptyRequestMsg{nil, ptyRequest(24, 80)} {
		t.Run(fmt.Sprint(terminal != nil), func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority)
			host, target := registerTerminalHost(t, ts)
			a := newApproval(time.Now().Add(time.Minute))
			authority.admitWith(waitingOn(waitingMessage, a))
			guest := waitingGuest(t, ts)
			shell := startWaitingShell(t, guest, a, waitingMessage, terminal, "before-shell\n")
			_, err := io.WriteString(shell.stdin, "before-approval\n")
			require.NoError(t, err)
			drained := make(chan error, 1)
			go func() {
				_, err := io.CopyN(shell.stdin, strings.NewReader(strings.Repeat("x", 2<<20)), 2<<20)
				drained <- err
			}()
			select {
			case err := <-drained:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("waiting input was not discarded")
			}
			ok, err := shell.session.SendRequest("exec", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			a.decideIt(t, awaitOutcome{target: target})
			rest, err := shell.rest(t)
			require.NoError(t, err)
			want := approvedMessage
			if terminal != nil {
				want = crlf(want)
			}
			require.Equal(t, want, rest)
			terms, resizes, requests, typed := host.seen()
			require.Empty(t, terms)
			require.Empty(t, resizes)
			require.Empty(t, requests)
			require.Empty(t, typed)
		})
	}
}

func TestWaitingEnds(t *testing.T) {
	for _, reason := range []string{"denied", "expired", "disconnect", "sanitized"} {
		t.Run(reason, func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority)
			a := newApproval(time.Now().Add(time.Minute))
			authority.admitWith(waitingOn(waitingMessage, a))
			guest := waitingGuest(t, ts)
			shell := startWaitingShell(t, guest, a, waitingMessage, nil, "")
			if reason == "disconnect" {
				require.NoError(t, guest.Close())
				require.ErrorIs(t, a.ended(t), context.Canceled)
				return
			}
			message, want := "This code can't be approved. Ask for another.\n", ""
			switch reason {
			case "expired":
				message = expiredMessage
			case "sanitized":
				message, want = "This \x1b[31mcode\x07 can't\r be approved.\x9b\n", "This �[31mcode� can't� be approved.�\n"
			}
			if want == "" {
				want = message
			}
			a.decideIt(t, awaitOutcome{err: &WaitingEnded{Text: []byte(message)}})
			rest, err := shell.rest(t)
			requireExit(t, err, 1)
			require.Equal(t, want, rest)
		})
	}
}

func TestWaitingGuestClosure(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprint(force), func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority)
			a := newApproval(time.Now().Add(time.Minute))
			waiting := waitingOn(waitingMessage, a)
			guests := make(chan *Guest, 1)
			authority.admitWith(func(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
				guests <- g
				return waiting(ctx, g, req)
			})
			guest := waitingGuest(t, ts)
			startWaitingShell(t, guest, a, waitingMessage, nil, "")
			g := <-guests
			require.Nil(t, g.Home(), "a waiting guest was bound to a home")
			if force {
				g.ForceClose()
			} else {
				g.Close()
			}
			require.ErrorIs(t, a.ended(t), context.Canceled)
			requireDone(t, g, time.Second)
		})
	}
}

// A waiting screen is bound to the user the guest typed, byte for byte: one
// that names another user refuses the guest, and one that names it is shown.
func TestWaitingBindsToTheTypedUser(t *testing.T) {
	for _, address := range []string{waitingUser, waitingUser[:len(waitingUser)-1] + "5", waitingUser + " ", strings.ToUpper(waitingUser)} {
		t.Run(address, func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority)
			a := newApproval(time.Now().Add(time.Minute))
			waiting := waitingOn(waitingMessage, a)
			authority.admitWith(func(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
				admission, err := waiting(ctx, g, req)
				admission.Waiting.Address = address
				return admission, err
			})
			guest, _, err := dialDelegatedGuestAs(t, ts.addr, waitingUser, openSSHVersion, newProven(t).key)
			if address != waitingUser {
				require.Error(t, err, "a screen for %q was shown to %q", address, waitingUser)
				return
			}
			require.NoError(t, err)
			startWaitingShell(t, guest, a, waitingMessage, nil, "")
		})
	}
}

func TestWaitingOfferBinding(t *testing.T) {
	for _, invalid := range []string{"offer", "attempt", "key", "expiry", "await", "expired message", "approved message"} {
		t.Run(invalid, func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority)
			a := newApproval(time.Now().Add(time.Minute))
			valid := waitingOn(waitingMessage, a)
			authority.admitWith(func(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
				admission, err := valid(ctx, g, req)
				switch invalid {
				case "offer":
					admission.Waiting.OfferID = ""
				case "attempt":
					admission.Waiting.AttemptID = ""
				case "key":
					admission.Waiting.KeyFingerprint = publicKeyFingerprint(newProven(t).key.PublicKey())
				case "expiry":
					admission.Waiting.Expires = time.Now()
				case "await":
					admission.Waiting.Await = nil
				case "expired message":
					admission.Waiting.ExpiredMessage = nil
				case "approved message":
					admission.Waiting.ApprovedMessage = nil
				}
				return admission, err
			})
			_, _, err := dialDelegatedGuestAs(t, ts.addr, waitingUser, openSSHVersion, newProven(t).key)
			require.Error(t, err)
		})
	}
}

func TestWaitingExpiredBeforeShell(t *testing.T) {
	client, peer := forwardTestPair(t, nil, nil)
	guest := ssh.NewClient(client.conn, client.channels, client.requests)
	t.Cleanup(func() { _ = guest.Close() })
	// Establish the real SSH transport first, then start the screen with an
	// expired offer. Handshake and key generation speed can't decide expiry.
	a := newApproval(time.Now().Add(-time.Second))
	g := &guestConn{ctx: t.Context(), guest: &Guest{ConnectionID: "expired-screen"}, admission: a.waiting(waitingMessage)}
	ended := make(chan error, 1)
	go func() { ended <- (&SSHRouting{}).serveWaiting(g, peer, 10*time.Second) }()
	session, err := guest.NewSession()
	require.NoError(t, err)
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.Shell())
	output, err := io.ReadAll(stdout)
	require.NoError(t, err)
	requireExit(t, session.Wait(), 1)
	require.Equal(t, a.expired, string(output))
	require.Empty(t, a.waits, "an expired screen started a wait")
	require.NoError(t, <-ended)
}

// A screen is taken until the moment it expires, and not at it; the relay
// keeps it at most 10 minutes from the verdict, and keeps an expiry before
// then as it is.
func TestWaitingExpiryBoundaries(t *testing.T) {
	now := time.Now()
	screen := func(expires time.Time) *WaitingScreen {
		return &WaitingScreen{OfferID: fixtureAccountID, AttemptID: externalSessionID, Address: waitingUser, KeyFingerprint: "SHA256:k",
			ExpiredMessage: []byte(expiredMessage), ApprovedMessage: []byte(approvedMessage), Expires: expires,
			Await: func(context.Context) (Target, error) { return Target{}, nil }}
	}
	require.False(t, validWaiting(screen(now), waitingUser, "SHA256:k", now), "a screen was taken at its expiry")
	require.True(t, validWaiting(screen(now.Add(time.Nanosecond)), waitingUser, "SHA256:k", now), "a screen was refused before its expiry")
	require.Equal(t, now.Add(maxWaiting), frozenWaiting(screen(now.Add(maxWaiting)), now).Expires)
	require.Equal(t, now.Add(maxWaiting), frozenWaiting(screen(now.Add(maxWaiting+time.Nanosecond)), now).Expires, "a screen was kept past 10 minutes")
	require.Equal(t, now.Add(time.Minute), frozenWaiting(screen(now.Add(time.Minute)), now).Expires)
	require.Equal(t, 10*time.Minute, maxWaiting)

	// The relay keeps texts of its own.
	w := screen(now.Add(time.Minute))
	frozen := frozenWaiting(w, now)
	w.ExpiredMessage[0], w.ApprovedMessage[0] = 'x', 'x'
	require.Equal(t, expiredMessage, string(frozen.ExpiredMessage))
	require.Equal(t, approvedMessage, string(frozen.ApprovedMessage))
}

// A screen whose expiry is more than 10 minutes after the verdict is kept
// only 10 minutes: the wait on it ends then.
func TestWaitingScreenLastsAtMostTenMinutes(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	a := newApproval(time.Now().Add(time.Hour))
	waiting := waitingOn(waitingMessage, a)
	decided := make(chan time.Time, 1)
	authority.admitWith(func(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
		admission, err := waiting(ctx, g, req)
		decided <- time.Now()
		return admission, err
	})
	guest := waitingGuest(t, ts)
	shell := startWaitingShell(t, guest, a, waitingMessage, nil, "")
	after := time.Now()
	at := <-decided
	deadline, ok := shell.wait.Deadline()
	require.True(t, ok, "the wait has no deadline")
	require.False(t, deadline.Before(at.Add(10*time.Minute)) || deadline.After(after.Add(10*time.Minute)),
		"the screen lasts %v from the verdict, not 10 minutes", deadline.Sub(at))
}

// stallingWrites is a listener whose connections stop sending once stalling
// is set, as a guest's transport does when the guest stops reading and the
// buffers between them fill: every write from then on blocks until the
// connection is closed. stalled is closed once a write blocks, and closed
// once the connection is.
type stallingWrites struct {
	net.Listener
	stalling atomic.Bool
	stalled  chan struct{}
	closed   chan struct{}
	once     sync.Once
	stallOne sync.Once
}

func newStallingWrites(t *testing.T) *stallingWrites {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return &stallingWrites{Listener: ln, stalled: make(chan struct{}), closed: make(chan struct{})}
}

func (l *stallingWrites) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &stallingWritesConn{Conn: c, owner: l}, nil
}

type stallingWritesConn struct {
	net.Conn
	owner *stallingWrites
}

func (c *stallingWritesConn) Write(b []byte) (int, error) {
	if c.owner.stalling.Load() {
		c.owner.stallOne.Do(func() { close(c.owner.stalled) })
		<-c.owner.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *stallingWritesConn) Close() error {
	c.owner.once.Do(func() { close(c.owner.closed) })
	return c.Conn.Close()
}

// A waiting screen's guest that keeps asking and stops reading blocks the
// screen as it answers. Its transport is still closed a grace after the
// screen expires, and with it the guest's delegated work ends.
func TestWaitingGuestCutOffAtExpiry(t *testing.T) {
	authority := &fakeAuthority{}
	a := newApproval(time.Now().Add(time.Second))
	authority.admitWith(waitingOn(waitingMessage, a))
	ln := newStallingWrites(t)
	proxy, addr, _, signer := stockTestProxyOn(t, ln, 4*time.Second, &stockTestDialer{}, enabledIngress(authority, nil))
	guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: waitingUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(newProven(t).key)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = guest.Close() })
	shell := startWaitingShell(t, guest, a, waitingMessage, ptyRequest(24, 80), "")
	_, g := proxy.delegated.Counts()
	require.Equal(t, 1, g, "a waiting guest isn't counted")

	ln.stalling.Store(true)
	go func() {
		_, _ = shell.session.SendRequest("window-change", true, ssh.Marshal(&windowChangeMsg{Columns: 100, Rows: 30}))
	}()
	select {
	case <-ln.stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("the screen never answered the guest")
	}
	select {
	case <-ln.closed:
	case <-time.After(time.Until(a.expires) + waitingGrace + 3*time.Second):
		t.Fatal("a waiting guest that stopped reading outlived its screen's expiry")
	}
	require.Eventually(t, func() bool { _, g := proxy.delegated.Counts(); return g == 0 }, 5*time.Second, 10*time.Millisecond, "the cut-off guest is still counted")
}

// When a waiting screen ends while its guest has pipelined more requests on
// the session than the connection holds for it, those requests are drained
// until the connection closes them, and the screen ends: its connection's
// handler returns, the guest is no longer counted, and a drain returns.
// Ending, the screen may take in a request still waiting or notice its end
// first, by chance, and only the second leaves requests undelivered; so each
// way it ends is tried several times, side by side.
func TestWaitingScreenEndsWithPipelinedRequests(t *testing.T) {
	for _, ending := range []string{"expiry", "drain"} {
		t.Run(ending, func(t *testing.T) {
			for attempt := range 8 {
				t.Run(fmt.Sprint(attempt), func(t *testing.T) {
					t.Parallel()
					expires := time.Now().Add(time.Minute)
					if ending == "expiry" {
						expires = time.Now().Add(time.Second)
					}
					authority := &fakeAuthority{}
					a := newApproval(expires)
					authority.admitWith(waitingOn(waitingMessage, a))
					ln := newStallingWrites(t)
					proxy, addr, reg, signer := stockTestProxyOn(t, ln, 4*time.Second, &stockTestDialer{}, enabledIngress(authority, nil))
					guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: waitingUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(newProven(t).key)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
					require.NoError(t, err)
					t.Cleanup(func() { _ = guest.Close() })
					shell := startWaitingShell(t, guest, a, waitingMessage, ptyRequest(24, 80), "")

					// The screen blocks answering the guest, which goes on
					// sending: more than the connection holds for the
					// session.
					ln.stalling.Store(true)
					go func() {
						_, _ = shell.session.SendRequest("window-change", true, ssh.Marshal(&windowChangeMsg{Columns: 100, Rows: 30}))
					}()
					select {
					case <-ln.stalled:
					case <-time.After(5 * time.Second):
						t.Fatal("the screen never answered the guest")
					}
					for range 64 {
						_, err := shell.session.SendRequest("env", false, ssh.Marshal(struct{ Name, Value string }{"LANG", "C"}))
						require.NoError(t, err)
					}

					if ending == "drain" {
						// Long enough for the relay to have taken in what
						// the guest sent.
						time.Sleep(200 * time.Millisecond)
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						require.NoError(t, proxy.delegated.Drain(ctx), "a drain waited on a screen that had ended")
					}
					require.Eventually(t, func() bool { _, g := proxy.delegated.Counts(); return g == 0 }, time.Until(expires)+waitingGrace+5*time.Second, 10*time.Millisecond, "the screen's guest is still counted")
					require.Eventually(t, func() bool {
						active, _ := gatherValue(t, reg, "test_server_routing_active_connections_count", nil)
						return active == 0
					}, 5*time.Second, 10*time.Millisecond, "the screen's connection never ended")
				})
			}
		})
	}
}

// A waiting guest that never starts the screen's shell, with no session or
// with a session that never asks for one, is cut off a grace after the
// screen expires too, well before the handshake's stage would end it.
func TestWaitingGuestWithoutAShellCutOffAtExpiry(t *testing.T) {
	for _, opens := range []bool{false, true} {
		t.Run(map[bool]string{false: "no session", true: "no shell"}[opens], func(t *testing.T) {
			t.Parallel()
			authority := &fakeAuthority{}
			a := newApproval(time.Now().Add(time.Second))
			authority.admitWith(waitingOn(waitingMessage, a))
			ln := newStallingWrites(t)
			// A stage of 10 s, far past the screen's expiry and grace.
			proxy, addr, _, signer := stockTestProxyOn(t, ln, 20*time.Second, &stockTestDialer{}, enabledIngress(authority, nil))
			guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: waitingUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(newProven(t).key)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
			require.NoError(t, err)
			t.Cleanup(func() { _ = guest.Close() })
			if opens {
				sess, err := guest.NewSession()
				require.NoError(t, err)
				t.Cleanup(func() { _ = sess.Close() })
			}
			_, g := proxy.delegated.Counts()
			require.Equal(t, 1, g, "a waiting guest isn't counted")
			select {
			case <-ln.closed:
			case <-time.After(time.Until(a.expires) + waitingGrace + 2*time.Second):
				t.Fatal("a waiting guest that started no shell outlived its screen's expiry")
			}
			require.Eventually(t, func() bool { _, g := proxy.delegated.Counts(); return g == 0 }, 2*time.Second, 10*time.Millisecond, "the cut-off guest is still counted")
		})
	}
}
