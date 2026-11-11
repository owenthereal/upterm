package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/internal/termtext"
	"github.com/owenthereal/upterm/upterm"
	gossh "golang.org/x/crypto/ssh"
)

// Guest is a guest's connection to a relay with an authority composed, as the
// relay authenticated it: by a key whose signature the guest made over this
// very connection. The relay makes one only once that signature has
// verified, so an unsigned query for a key never makes one. It is also how
// the authority ends the connection, at whatever stage it is.
type Guest struct {
	Origin GuestOrigin
	// Key is the key the guest proved it holds: the key a certificate is for,
	// when the guest presented one.
	Key gossh.PublicKey
	// Fingerprint is Key's SHA256 fingerprint: "SHA256:" and unpadded base64.
	Fingerprint string
	// ConnectionID names this admission: a random UUID the relay mints for the
	// connection as authenticated by Key. A guest that goes on to offer
	// another key on the same connection is another admission, with another
	// ID.
	ConnectionID string
	// Source is the address the connection came from as the relay's own
	// listener reports it, never as the guest says: behind a PROXY-protocol
	// front end, the one that front end vouches for.
	Source net.Addr

	conn *guestConn
	// refused is set once the authority has refused this admission. The
	// connection is then no longer this guest's to close: it may go on to be
	// admitted with another key, as another guest.
	refused atomic.Bool
}

// Close ends the connection: it cancels every stage the guest is in, which
// each stage answers by closing what it holds, and closes the guest's
// transport too while the guest is still authenticating. A guest being
// forwarded has its connection and the relay's own to the host closed
// together, at once, with no drain of what the host had sent; a decision
// still pending, a message being shown or a waiting screen ends with the
// guest's connection. ForceClose differs only in closing the guest's
// transport at every stage. Close returns at once, never waiting on the
// guest, the host or the authority. Once the authority has refused the guest
// it closes nothing.
func (g *Guest) Close() {
	if !g.refused.Load() {
		g.conn.close()
	}
}

// ForceClose closes the connection's transports, the guest's and the relay's
// own to the host, at once, however the guest, the host or the authority are
// blocked: every channel the connection carries goes with them. It returns at
// once. Once the authority has refused the guest it closes nothing.
func (g *Guest) ForceClose() {
	if !g.refused.Load() {
		g.conn.forceClose()
	}
}

// Done is closed once the connection has ended and the relay holds nothing
// more of it.
func (g *Guest) Done() <-chan struct{} { return g.conn.done }

// Verdict is what Authority.Admit decided about a guest.
type Verdict int

const (
	// VerdictDeny refuses the guest's key as a relay refuses any key it
	// doesn't know, and tells the guest nothing else. It is the zero value.
	VerdictDeny Verdict = iota
	// VerdictAllow admits the guest to its Target and nothing else.
	VerdictAllow
	// VerdictMessage accepts the guest's key into a session that shows it
	// Message, exits 1 and reaches no host.
	VerdictMessage
	// VerdictWaiting accepts the guest's key into a session that shows it
	// Message and waits on Waiting. Approval closes the screen and requires a
	// new connection; no target or forwarding is authorized.
	VerdictWaiting
)

// GuestRequest is what a guest asked for.
type GuestRequest struct {
	// User is the SSH user exactly as the guest typed it.
	User string
	// Home is the registration the guest's session ID led to, as its home
	// reported it; nil for a claimed user.
	Home Home
}

// Admission is Authority.Admit's decision about a guest. VerdictMessage and
// VerdictWaiting are only ever a claimed user's: for a relay session ID they
// are taken as VerdictDeny, and so is any admission that doesn't hold
// together.
type Admission struct {
	// AllowUntil and Sequence bind the authority's allow to the home's
	// assertion: an allow is refused once AllowUntil has passed, until the
	// moment forwarding begins, and one without a Sequence is refused.
	// Sequence must be 1 or 2. A home on another node takes it as the least
	// sequence of the held checks Home.Confirm makes over the hop, which
	// number from 2, so with a larger one the first Confirm fails.
	AllowUntil time.Time
	Sequence   uint64
	Verdict    Verdict
	// Target is where VerdictAllow admits the guest. It is fixed for the life
	// of the connection: a later decision can only keep it or end it.
	Target Target
	// Message is what VerdictMessage, or VerdictWaiting's screen, shows the
	// guest, as text lines ending in line feeds. The relay writes it as it
	// is, except that it writes a carriage return before each line feed to a
	// guest that asked for a terminal, as a terminal's own line discipline
	// would, and replaces anything else unprintable, so no part of it can
	// control the guest's terminal.
	Message []byte
	// Waiting is what VerdictWaiting waits on.
	Waiting *WaitingScreen
}

// Target is the one delegated registration an admission allows: its
// account and external session, the routing ID it registered and the run key
// its proof verified. The relay forwards the guest only to that route, and
// only to the registration of that session that proved that key, and
// requires the host there to present the key.
type Target struct {
	Registration RegistrationRef
	AccountID    string
	SessionID    string
	RoutingID    string
	RunPublicKey gossh.PublicKey
	// Capabilities is what the guest may do there, of "shell", "exec",
	// "sftp" and "direct-tcpip". The relay refuses every channel and request
	// outside them; an unknown name allows nothing.
	Capabilities []string
}

// valid reports whether t names a delegated registration at all.
func (t Target) valid() bool {
	ref := t.Registration
	return validUUID(t.AccountID) && validUUID(t.SessionID) && t.RunPublicKey != nil && ref.Authority == AuthorityDelegated && validGateRegistration(gateRegistration(ref)) == nil && t.AccountID == ref.AccountID && t.SessionID == ref.SessionID && t.RoutingID == ref.RoutingID && len(ref.RunPublicKeys) == 1 && bytes.Equal(t.RunPublicKey.Marshal(), ref.RunPublicKeys[0])
}

// sessionUser is the shape of a relay session ID as a guest types it: the 20
// letters and digits the relay names a session by, optionally followed by a
// colon and a node address in base64url, which may be empty and may be
// padded.
var sessionUser = regexp.MustCompile(`^[A-Za-z0-9]{20}(:[A-Za-z0-9_-]*={0,2})?$`)

// isSessionUser reports whether user is a relay session ID. Such a user is
// never offered to the authority's Claims, whatever the routing mode.
func isSessionUser(user string) bool { return sessionUser.MatchString(user) }

// errGuestRefused is the refusal of a guest the authority didn't admit. A
// guest is told only that its key was refused.
var errGuestRefused = errors.New("the relay's authority did not admit the key")

// errGuestUnknown refuses a guest whose user is no relay session ID and no
// user the authority claims.
var errGuestUnknown = errors.New("the user names no session on this relay")

// errGuestHop refuses, as a guest's key, a certificate a relay node minted,
// which only another relay node holds.
var errGuestHop = errors.New("a relay certificate is no guest's key")

// errGuestRoute is an allowed target the relay has no usable route to.
var errGuestRoute = errors.New("the allowed target has no route on this relay")

// errGuestClosed is a guest closed, or whose host's route was withdrawn,
// before its forwarding started.
var errGuestClosed = errors.New("the guest's admission ended before forwarding began")

// guestConn is one guest's connection on the composed path: what its
// admission decided, and what closing it takes at each stage.
type guestConn struct {
	mu            sync.Mutex
	home          Home
	upstream      *upstreamConn
	authenticated bool
	raw           net.Conn
	// ctx is every stage's: the authority's decision, the upstream and the
	// message session. It ends when the connection is closed either way, the
	// relay stops, or the connection ends.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// Written by the key callback during the handshake, and read once it is
	// complete. guest is set once the guest was allowed, or is to be shown a
	// message or a waiting screen.
	guest     *Guest
	admission Admission
}

func newGuestConn(ctx context.Context, raw net.Conn) *guestConn {
	g := &guestConn{raw: raw, done: make(chan struct{})}
	g.ctx, g.cancel = context.WithCancel(ctx)
	return g
}

// close ends every stage the guest is in. Each stage's own reaction to its
// context is what closes it in order; see Guest.Close.
func (g *guestConn) close() {
	g.cancel()
	g.mu.Lock()
	authenticating := !g.authenticated
	g.mu.Unlock()
	if authenticating {
		_ = g.raw.Close()
	}
}

// forceClose closes the guest's transport as well, which the relay's own
// connection to the host follows, from its context's watcher.
func (g *guestConn) forceClose() {
	g.cancel()
	_ = g.raw.Close()
}

// end is the connection's end, once the relay has released all of it.
func (g *guestConn) end() {
	g.cancel()
	if g.upstream != nil {
		g.upstream.Close()
	}
	close(g.done)
}

// composedGuest reports whether conn is a guest the composed path admits:
// any connection but a host's, once an authority is composed.
func (a proxyAuth) composedGuest(conn gossh.ConnMetadata) bool {
	return a.authority != nil && string(conn.ClientVersion()) != upterm.HostSSHClientVersion
}

// guestKey is what the composed path takes a guest offering offered as
// conn's user to be asking for: the key it offers, the one a certificate is
// for, and whether its user is one the authority claims rather than a relay
// session ID. It reads nothing and asks the authority only whether it claims
// the user, as it also answers unsigned queries. A user that is neither, and
// any user but a session ID while the authority is dark, names no session,
// and is refused; so is a certificate a relay node minted.
func (a proxyAuth) guestKey(conn gossh.ConnMetadata, offered gossh.PublicKey) (gossh.PublicKey, bool, error) {
	claimed := false
	if !isSessionUser(conn.User()) {
		if !a.AuthorityEnabled || !a.authority.Claims(conn.User()) {
			return nil, false, errGuestUnknown
		}
		claimed = true
	}
	key := offered
	if cert, ok := offered.(*gossh.Certificate); ok {
		if a.isHopAuthority(cert.SignatureKey) || signerAuthority(a.Signers, cert.SignatureKey) {
			return nil, false, errGuestHop
		}
		key = cert.Key
	}
	return key, claimed, nil
}

// sameKey reports whether a and b are the one key, as the same encoding: a
// certificate is not the key it is for.
func sameKey(a, b gossh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// serveDelegatedGuest serves a guest the composed path accepted that isn't a
// local session's: to its allowed target's host, with the message it is to be
// shown instead, or waiting on its screen. A guest allowed to a target the
// relay can't reach is shown what the authority says of that.
func (p *SSHRouting) serveDelegatedGuest(ctx context.Context, g *guestConn, peer sshPeer, stage time.Duration, inst *routingInstruments) error {
	if g.ctx.Err() != nil {
		// Closed as it authenticated.
		endSSHPeer(peer)
		return errGuestClosed
	}
	if g.admission.Verdict == VerdictWaiting {
		return p.serveWaiting(g, peer, stage)
	}
	message := g.admission.Message
	if g.admission.Verdict == VerdictAllow {
		if g.upstream != nil {
			upstream := g.upstream
			defer upstream.Close()
			if p.beforeForward != nil {
				p.beforeForward()
			}
			if g.ctx.Err() != nil || g.home == nil || !g.home.Held() || !time.Now().Before(g.admission.AllowUntil) {
				return errGuestClosed
			}
			inst.authenticatedClient.Add(1)
			return forwardSSHWithin(g.ctx, peer, upstream.sshPeer, abortConnection, inst.stalledChannelAborts, nil, newGuestCapabilities(g.admission.Target.Capabilities))
		}
		p.logger().Info("an allowed guest could not reach its target", "error", errGuestRoute, "connection-id", g.guest.ConnectionID)
		unreachableCtx, cancel := context.WithTimeout(g.ctx, stage)
		message = p.Auth.authority.Unreachable(unreachableCtx, g.guest, g.admission.Target)
		cancel()
	}
	messageCtx, cancel := context.WithTimeout(g.ctx, stage)
	defer cancel()
	serveGuestMessage(messageCtx, peer, message)
	return nil
}

// endSSHPeer closes peer's connection, and answers what its mux still
// delivers so that the mux can shut down.
func endSSHPeer(peer sshPeer) {
	_ = peer.conn.Close()
	var requests sync.WaitGroup
	requests.Go(func() {
		for range peer.requests {
		}
	})
	for channel := range peer.channels {
		_ = channel.Reject(gossh.ConnectionFailed, sshPeerDisconnected)
	}
	requests.Wait()
}

// serveGuestMessage serves a guest that may be shown message and nothing
// else, until its one session ends, ctx ends or the connection does. The
// guest may open exactly one session channel and ask it for a terminal and
// resize it. Its shell writes message to stdout, its exec writes it to
// stderr, and either exits 1. Every other channel, every subsystem,
// forwarding in either direction, agent forwarding, X11 and environment
// variables are refused, and nothing reaches a host. It closes the
// connection, and joins all it started, before it returns.
func serveGuestMessage(ctx context.Context, peer sshPeer, message []byte) {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = peer.conn.Close()
		// Answered so that the mux can shut down.
		for channel := range peer.channels {
			_ = channel.Reject(gossh.ConnectionFailed, sshPeerDisconnected)
		}
		workers.Wait()
	}()
	// Closing the transport is what releases a write to a guest that has
	// stopped reading, so it happens here and not after one.
	workers.Go(func() {
		<-ctx.Done()
		_ = peer.conn.Close()
	})
	workers.Go(func() {
		for request := range peer.requests {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	})
	sessionDone := make(chan struct{})
	opened := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-sessionDone:
			return
		case channel, ok := <-peer.channels:
			if !ok {
				return
			}
			if opened || channel.ChannelType() != "session" {
				_ = channel.Reject(gossh.Prohibited, "not permitted")
				continue
			}
			opened = true
			session, requests, err := channel.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer close(sessionDone)
				serveMessageSession(session, requests, message)
			})
		}
	}
}

// serveMessageSession is serveGuestMessage's one session channel.
func serveMessageSession(session gossh.Channel, requests <-chan *gossh.Request, message []byte) {
	terminal := false
	for request := range requests {
		switch request.Type {
		case "pty-req", "window-change":
			terminal = terminal || request.Type == "pty-req"
			replyRequest(request, true)
		case "shell", "exec":
			replyRequest(request, true)
			var out io.Writer = session
			if request.Type == "exec" {
				out = session.Stderr()
			}
			exitShowing(session, requests, out, message, terminal)
			return
		default:
			replyRequest(request, false)
		}
	}
}

// exitShowing ends a restricted session: it writes message to out, the
// session's stdout or stderr, as termtext.Sanitize words it for a terminal
// or for none, exits 1 and closes the session, and returns once the guest has
// closed its end too.
func exitShowing(session gossh.Channel, requests <-chan *gossh.Request, out io.Writer, message []byte, terminal bool) {
	exitShowingStatus(session, requests, out, message, terminal, 1)
}

func exitShowingStatus(session gossh.Channel, requests <-chan *gossh.Request, out io.Writer, message []byte, terminal bool, status uint32) {
	_, _ = out.Write(termtext.Sanitize(message, terminal))
	_, _ = session.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
	_ = session.CloseWrite()
	_ = session.Close()
	// Until the guest closes its end too, which it does once it has read
	// everything before it: closing the connection sooner can cost it what
	// it had not read yet.
	for range requests {
	}
}

func replyRequest(request *gossh.Request, ok bool) {
	if request.WantReply {
		_ = request.Reply(ok, nil)
	}
}

// guestCapabilities holds an admitted guest's forwarding to the capabilities
// its admission named.
type guestCapabilities struct{ shell, exec, sftp, directTCPIP bool }

func newGuestCapabilities(names []string) guestCapabilities {
	var c guestCapabilities
	for _, name := range names {
		switch name {
		case "shell":
			c.shell = true
		case "exec":
			c.exec = true
		case "sftp":
			c.sftp = true
		case "direct-tcpip":
			c.directTCPIP = true
		}
	}
	return c
}

// OpenChannel allows a session for any of the session capabilities, and a
// direct TCP/IP channel for its own. No other channel is a guest's to open.
func (c guestCapabilities) OpenChannel(channelType string) bool {
	switch channelType {
	case "session":
		return c.shell || c.exec || c.sftp
	case "direct-tcpip":
		return c.directTCPIP
	}
	return false
}

// Request allows, on a session, the shell, exec and the sftp subsystem for
// their capabilities and the requests that only shape one, and globally only
// keepalives. Agent forwarding, X11, other subsystems and remote forwarding
// are never a guest's, and a direct TCP/IP channel carries no requests.
func (c guestCapabilities) Request(channelType string, r *gossh.Request) bool {
	switch channelType {
	case "":
		return r.Type == upterm.OpenSSHKeepAliveRequestType || r.Type == "no-more-sessions@openssh.com"
	case "session":
		switch r.Type {
		case "shell":
			return c.shell
		case "exec":
			return c.exec
		case "subsystem":
			var subsystem struct{ Name string }
			return c.sftp && gossh.Unmarshal(r.Payload, &subsystem) == nil && subsystem.Name == "sftp"
		case "pty-req", "window-change", "env", "signal", "break", "eow@openssh.com", upterm.OpenSSHKeepAliveRequestType:
			return true
		}
	}
	return false
}
