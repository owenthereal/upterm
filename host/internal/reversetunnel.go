package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/internal/httpproxy"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	// authFailurePrefix heads the one error x/crypto produces when it runs out
	// of authentication methods:
	//
	//	ssh: unable to authenticate, attempted methods %v, no supported methods remain
	//
	// (v0.57.0, ssh/client_auth.go:154), where %v is the ordered list of RFC
	// 4252 method names that were tried: "[none]" when the unauthenticated
	// probe was all that got attempted, "[none publickey]" once a key was
	// offered and refused.
	//
	// The head is matched, not either whole sentence. Matching the "[none]"
	// one in full is what this used to do, and it meant the commoner failure
	// by far — a key offered to a relay whose --authorized-keys does not list
	// it — matched nothing, never became a PermissionDeniedError, and reached
	// the user as a raw "ssh dial error: ssh: handshake failed: ..." (#562).
	// A prefix keeps any list x/crypto may grow classified as the permission
	// denial it is; the list is then read for which of the two things to say
	// happened, and a list too unfamiliar to read falls back to the claim that
	// holds either way — that no identity was offered.
	authFailurePrefix = "ssh: unable to authenticate, attempted methods "

	// publicKeyMethod is what x/crypto records for ssh.PublicKeys, and its
	// presence in that list is the only evidence that an identity actually
	// reached the relay. Holding keys is not offering them: a server that does
	// not allow publickey leaves the list at "[none]" however many the host
	// had, so the signer count alone cannot tell the two apart.
	publicKeyMethod = "publickey"

	// listenerCloseGrace bounds how long closing the forwarded listener waits
	// on the relay before the transport is taken out from under it.
	//
	// That Close sends cancel-streamlocal-forward and waits for the reply, and
	// x/crypto answers global requests in order: a relay that accepted the
	// session but never answered an earlier request — a keepalive, say — leaves
	// the wait with nothing that can ever wake it. Shutdown closes this
	// listener from a run.Group interrupt, so the wait held up the whole
	// teardown: no final publication, no Release, and `session info` still
	// reporting a ready session on a name nothing will give back.
	//
	// Closing costs at most twice this: the wait on the relay, then the same
	// again on the transport that was closed to end it.
	listenerCloseGrace = 5 * time.Second
)

type ReverseTunnel struct {
	*ssh.Client

	Host    *url.URL
	Signers []ssh.Signer
	// HostKey is the key the embedded sshd presents. Its public half is what
	// the relay is told to expect on every guest's upstream hop; Signers
	// authenticate this tunnel and are used for nothing else.
	HostKey ssh.Signer
	// SessionSecret, when set, makes Establish prove to the relay that this
	// host holds HostKey, so the session is registered under an ID derived
	// from the key and this secret rather than a random one. Generation orders
	// this registration against earlier ones under the same ID, and must be at
	// least 1 alongside a secret.
	//
	// The relay treats a proven registration as one whose host can reconnect,
	// and may close its tunnel on that basis: set it only for a host that does.
	SessionSecret  []byte
	Generation     uint64
	AuthorizedKeys []ssh.PublicKey
	// KeepAlive is how long the relay may be silent: probed after Interval,
	// given up on after Interval+Bound. A field left zero takes
	// liveness.DefaultTiming's.
	KeepAlive liveness.Timing
	// RequireDerivedID makes Establish a redial's: a relay that answers a
	// proven registration with an ID not derived from HostKey fails it with
	// ErrRelayUnsupported, before a listener is requested for an ID no guest
	// knows. Without it, that answer is a first connection's, which goes on
	// with ReconnectSupported false.
	RequireDerivedID bool
	// ProxyURL, when non-nil, is the HTTP proxy to connect to Host through.
	ProxyURL        *url.URL
	HostKeyCallback ssh.HostKeyCallback
	Logger          *slog.Logger

	// ln is the forwarded listener, wrapped so that closing it is bounded by
	// listenerCloseGrace rather than by the relay's willingness to answer.
	ln net.Listener

	// conn is the connection the last dial produced, which Wait reports on.
	// Nil until a handshake succeeds.
	conn *connection

	// stopKeepAlive ends the goroutine Establish starts. Nil until then.
	stopKeepAlive context.CancelFunc

	// What the relay did with the last successful Establish's proof.
	reconnectSupported bool
	sessionKeyRedial   bool
}

// ErrRelayUnsupported is a redial answered as a relay without proofs answers:
// with a random ID, under which no guest could find the session.
var ErrRelayUnsupported = errors.New("the relay answered with a session ID not derived from this host's key")

// errNeverConnected is what Wait says of a tunnel whose dial or handshake
// never produced a connection.
var errNeverConnected = errors.New("reverse tunnel: never connected")

// CreateSessionRefusedError is the relay refusing the registration, with the
// reason it gave: a refused proof, a newer registration, a store that failed.
type CreateSessionRefusedError struct{ Body string }

func (e *CreateSessionRefusedError) Error() string {
	return "could not initialize session: " + e.Body
}

// ForwardRefusedError is the relay registering the session but refusing the
// listener its guests would be forwarded to.
type ForwardRefusedError struct{ Err error }

func (e *ForwardRefusedError) Error() string {
	if e.Err == nil {
		return "unable to create reverse tunnel"
	}
	return "unable to create reverse tunnel: " + e.Err.Error()
}

func (e *ForwardRefusedError) Unwrap() error { return e.Err }

// connection is one dial's SSH client, and why it ended.
type connection struct {
	client *ssh.Client
	// silenced is the keepalive's verdict on a relay that went silent,
	// recorded before it closes client, so that Wait reports the silence
	// rather than the EOF its own close produced. It is the one case in which
	// liveness, not the connection, ended it.
	silenced atomic.Pointer[error]

	// why is the verdict, worked out once by the first wait and handed to
	// every later one, so that they all give the same answer.
	once sync.Once
	why  error
}

func (c *connection) wait() error {
	c.once.Do(func() {
		c.why = c.client.Wait()
		if silenced := c.silenced.Load(); silenced != nil {
			c.why = *silenced
		}
	})
	return c.why
}

// Wait blocks until the tunnel's connection has ended, and says why: the
// keepalive's error, wrapping liveness.ErrSilent, if the relay went silent and
// the keepalive closed it; otherwise what ended the SSH connection. Every call
// gives the same answer, and a tunnel that never connected says so at once. It
// is safe from several goroutines, and after Close.
func (c *ReverseTunnel) Wait() error {
	if c.conn == nil {
		return errNeverConnected
	}
	return c.conn.wait()
}

// ReconnectSupported reports whether the relay honoured the proof, by
// registering the session under the ID derived from HostKey and SessionSecret.
// A relay that predates proofs ignores one and issues a random ID, and a
// tunnel that sent none never asked.
func (c *ReverseTunnel) ReconnectSupported() bool {
	return c.reconnectSupported
}

// SessionKeyRedial reports whether the relay also lets the session key alone
// authenticate a redial. It is only ever true where ReconnectSupported is.
func (c *ReverseTunnel) SessionKeyRedial() bool {
	return c.sessionKeyRedial
}

// Close releases whatever Establish took, and works on a tunnel that never
// established anything. Establish gives up at three different points — the
// dial, the session request, the listen — and each leaves a different subset
// of these set; a Close that assumed the successful one would turn a failed
// dial into a nil dereference in the caller's teardown.
//
// It is bounded: closing ln goes through the wrapper, which gives the relay
// listenerCloseGrace and then closes the client itself.
func (c *ReverseTunnel) Close() {
	// Stopped before the client is closed, so the keepalive cannot start a
	// probe into a connection that is going away, nor report its close as a
	// relay gone silent.
	if c.stopKeepAlive != nil {
		c.stopKeepAlive()
	}
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if c.Client != nil {
		_ = c.Client.Close()
	}
}

// Listener returns the forwarded listener the guest server serves on, wrapped
// so that whoever closes it — Shutdown, from an interrupt — cannot be left
// waiting on a relay that has stopped replying.
func (c *ReverseTunnel) Listener() net.Listener {
	return c.ln
}

// Establish is one bounded attempt: ctx bounds everything until it returns —
// the dial, the handshake, signing, the session request and the listen — and
// nothing after. The tunnel it returns outlives ctx, and on any failure it
// leaves no connection open.
func (c *ReverseTunnel) Establish(ctx context.Context) (*server.CreateSessionResponse, error) {
	// What the relay did with a previous Establish's proof says nothing about
	// this one, and a failure must not go on reporting it.
	c.reconnectSupported, c.sessionKeyRedial = false, false

	if c.HostKey == nil {
		return nil, errors.New("reverse tunnel: HostKey is required")
	}

	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	baseLogger := c.Logger
	if baseLogger == nil {
		baseLogger = slog.Default()
	}

	var (
		auths          []ssh.AuthMethod
		authorizedKeys [][]byte
	)
	if len(c.Signers) > 0 {
		// SSH only tries the first auth method of each type, so group all keys.
		auths = append(auths, ssh.PublicKeys(c.Signers...))
	}
	// The relay checks the embedded sshd's key against this list on every
	// guest's upstream hop (server/sshproxy.go, hostKeyCb). The identities
	// are deliberately absent: the relay learns them from the handshake, and
	// nothing may treat this list as who the host is.
	hostPublicKeys := [][]byte{ssh.MarshalAuthorizedKey(c.HostKey.PublicKey())}
	for _, ak := range c.AuthorizedKeys {
		authorizedKeys = append(authorizedKeys, ssh.MarshalAuthorizedKey(ak))
	}

	config := &ssh.ClientConfig{
		User:          user.Username,
		Auth:          auths,
		ClientVersion: upterm.HostSSHClientVersion,
		// Enforce a restricted set of algorithms for security
		// TODO: make this configurable if necessary
		HostKeyAlgorithms: []string{
			ssh.CertAlgoED25519v01,
			ssh.CertAlgoRSASHA512v01,
			ssh.CertAlgoRSASHA256v01,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
		},
		HostKeyCallback: c.HostKeyCallback,
	}

	raw, addr, err := c.dial(ctx, user.Username)
	if err != nil {
		// The signers, not the auths built from them: auths holds one
		// publickey method however many keys went into it, and it is the keys
		// a refusal has to be reported in terms of.
		return nil, sshDialError(c.Host, c.ProxyURL, len(c.Signers), err)
	}

	// ctx's end closes the connection until Establish returns. Nothing past
	// the dial takes a context — the handshake, a signer, a request already on
	// the wire — and closing the connection is what fails each of them.
	stopDeadline := context.AfterFunc(ctx, func() { _ = raw.Close() })

	// Wrapped beneath the SSH transport, so that every byte the relay sends
	// is what the keepalive judges it by.
	lc := liveness.NewConn(raw)
	ncc, chans, reqs, err := ssh.NewClientConn(lc, addr, config)
	if err != nil {
		cancelled := !stopDeadline()
		// NewClientConn has closed it already; this says so here.
		_ = raw.Close()
		if cancelled {
			// ctx's close is what failed the handshake: the cause is the
			// cancel or the deadline, and no network advice applies.
			return nil, fmt.Errorf("%w: %w", ctx.Err(), err)
		}
		return nil, sshDialError(c.Host, c.ProxyURL, len(c.Signers), err)
	}
	// The client this listener and this keepalive belong to, kept apart from
	// the field. A second Establish replaces the field, and either of them
	// acting on the replacement would close a connection that is not the one
	// it is nursing.
	client := ssh.NewClient(ncc, chans, reqs)
	conn := &connection{client: client}
	c.Client, c.conn = client, conn

	// fail ends this attempt's connection along with it. When ctx's close
	// already ran, that close is what failed the step, and the error says so.
	// Only then: a cancel that merely coincides with a failure of its own
	// must not hide it.
	fail := func(err error) (*server.CreateSessionResponse, error) {
		cancelled := !stopDeadline()
		_ = client.Close()
		if cancelled {
			err = fmt.Errorf("%w: %w", ctx.Err(), err)
		}
		return nil, err
	}

	req := &server.CreateSessionRequest{
		HostUser:             user.Username,
		HostPublicKeys:       hostPublicKeys,
		ClientAuthorizedKeys: authorizedKeys,
	}
	if c.SessionSecret != nil {
		// Signed over this connection's SSH session ID, which the relay reads
		// back from the certificate its proxy minted for this same connection,
		// so a proof captured here is worthless on any other.
		proof, err := registration.Sign(c.HostKey, client.SessionID(), c.SessionSecret, c.Generation)
		if err != nil {
			return fail(fmt.Errorf("error signing session proof: %w", err))
		}
		req.SessionSecret, req.Generation, req.HostKeyProof = c.SessionSecret, c.Generation, proof
	}

	sessResp, err := createSession(client, req)
	if err != nil {
		return fail(fmt.Errorf("error creating session: %w", err))
	}

	// Honoured only if the ID is the derived one: a relay without proofs
	// ignores the fields and answers with a random ID, and says nothing else.
	reconnectSupported := c.SessionSecret != nil &&
		sessResp.SessionID == registration.ID(c.HostKey.PublicKey(), c.SessionSecret)
	if c.SessionSecret != nil && !reconnectSupported && c.RequireDerivedID {
		// Before the listen: closing the connection cancels a registration
		// under an ID no guest knows, and no forward is ever requested for it.
		return fail(fmt.Errorf("error creating session: %w", ErrRelayUnsupported))
	}

	ln, err := client.Listen("unix", sessResp.SessionID)
	if err != nil {
		return fail(&ForwardRefusedError{Err: err})
	}

	// The attempt is over, and the tunnel outlives its context. A stop that
	// finds the close already started lost the race to ctx: the connection is
	// closing under the tunnel, which is a failure, not a tunnel to return.
	if !stopDeadline() {
		_ = client.Close()
		return nil, ctx.Err()
	}

	// This generation's keepalive, built before the listener that has to be
	// able to stop it.
	//
	// On the tunnel's own lifetime, not the attempt's: ctx ends with the
	// attempt, and the tunnel goes on. Close and closeClient are what stop it.
	//
	// A second Establish on the same tunnel replaces the first keepalive
	// rather than orphaning it: overwriting the cancel would leave the
	// previous goroutine with nothing able to stop it, which is the bug this
	// field exists to fix, one level up.
	if c.stopKeepAlive != nil {
		c.stopKeepAlive()
	}
	keepAliveCtx, stopKeepAlive := context.WithCancel(context.WithoutCancel(ctx))
	c.stopKeepAlive = stopKeepAlive

	// Closing the client is how both the listener and the keepalive give up on
	// the relay: it is the only thing that fails a request already on the
	// wire.
	//
	// The keepalive is stopped first so its ctx ends before the client does:
	// a probe already in flight then fails because ctx was cancelled, not
	// because the relay went quiet, and Watch does not report it as a dead
	// relay.
	//
	// Both the cancel and the client are this generation's, read here rather
	// than off the tunnel when the closure runs. Reading the field instead
	// would let a listener left over from an earlier Establish cancel the
	// current keepalive — killing a live tunnel's liveness check on its way to
	// closing a connection that is no longer the one it was nursing.
	closeClient := func() {
		stopKeepAlive()
		_ = client.Close()
	}
	c.ln = newBoundedListener(ln, listenerCloseGrace, closeClient)

	// The relay is alive while its bytes arrive, whatever they are; a probe
	// only prompts a relay that has gone quiet.
	go liveness.Watch(keepAliveCtx, c.KeepAlive.OrDefault(), lc.LastRead, func() error {
		_, _, err := client.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		return err
	}, func(err error) {
		// Only silence is liveness's own verdict. A probe fails only on a
		// connection that has already ended, and Wait reports that in the
		// connection's words. Recorded before the close, so that Wait
		// reports the silence and not the EOF the close is about to produce.
		if errors.Is(err, liveness.ErrSilent) {
			conn.silenced.Store(&err)
		}
		// Once, at the point of giving up. Logging every interval said the
		// same thing about the same dead connection until the session ended,
		// which buried whatever else the host had to say.
		baseLogger.Error("relay stopped responding, closing the tunnel", "error", err)
		// The guest server is parked in Accept on a tunnel that no longer
		// carries anything. Closing the client is what makes Serve return, so
		// OnGuestServerStopped runs and the session is published as
		// disconnected instead of sitting at ready with nobody able to reach
		// it.
		closeClient()
	})

	c.reconnectSupported = reconnectSupported
	c.sessionKeyRedial = reconnectSupported && sessResp.SessionKeyRedial

	return sessResp, nil
}

// dial opens the connection the SSH transport runs over, under ctx, and returns
// the address the host-key callback is shown for it: Host's host:port for
// ssh://, and the same for ws://, whose port `upterm host` appends to portless
// server URLs — known_hosts checking requires host:port and keys the entry as
// [host]:443. Only the dial URL inside ws drops it.
func (c *ReverseTunnel) dial(ctx context.Context, username string) (net.Conn, string, error) {
	switch {
	case isWSScheme(c.Host.Scheme):
		u, _ := url.Parse(c.Host.String()) // clone
		u.User = url.UserPassword(username, "")
		conn, err := ws.NewWSConnContext(ctx, u, false, c.ProxyURL)
		return conn, u.Host, err
	case c.ProxyURL != nil:
		conn, err := httpproxy.Dial(ctx, c.ProxyURL, c.Host.Host)
		return conn, c.Host.Host, err
	default:
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", c.Host.Host)
		return conn, c.Host.Host, err
	}
}

func createSession(client *ssh.Client, req *server.CreateSessionRequest) (*server.CreateSessionResponse, error) {
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, b)
	if err != nil {
		return nil, fmt.Errorf("error initializing session: %w", err)
	}
	if !ok {
		return nil, &CreateSessionRefusedError{Body: string(body)}
	}

	var resp server.CreateSessionResponse
	if err := proto.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshaling created session: %w", err)
	}

	return &resp, nil
}

// boundedListener is a forwarded listener whose Close cannot outlive twice the
// grace: once waiting on the relay, once waiting on the transport it forces
// when the relay does not answer. Accept and Addr are the wrapped listener's
// own: only Close is a request-response with the relay, and only Close is at
// risk.
type boundedListener struct {
	net.Listener

	grace time.Duration
	// force fails whatever the inner Close is waiting for. Closing the SSH
	// client is the only thing that can: the request is already on the wire,
	// and x/crypto offers no way to abandon the wait for its reply.
	force func()
}

func newBoundedListener(ln net.Listener, grace time.Duration, force func()) net.Listener {
	return &boundedListener{Listener: ln, grace: grace, force: force}
}

// Close returns what the forwarded listener returned, or says that even
// forcing the transport did not free it. Either way it returns.
//
// The inner Close runs on its own goroutine because there is nothing to cancel
// it with: it is parked either on the mutex x/crypto serialises global
// requests with, or on the reply channel for its own. Closing the transport
// ends both — the mux loop closes that channel on its way out, and every
// pending request returns EOF — so the result is collected afterwards rather
// than guessed at. That collection gets the same grace and no more: it is
// released by an implementation detail of x/crypto, and this is the teardown
// path, where continuing on a bad answer beats waiting for a good one.
func (l *boundedListener) Close() error {
	closed := make(chan error, 1)
	go func() { closed <- l.Listener.Close() }()

	select {
	case err := <-closed:
		return err
	case <-time.After(l.grace):
	}

	l.force()

	select {
	case err := <-closed:
		return err
	case <-time.After(l.grace):
		// The goroutine is abandoned holding the listener, and nothing else.
		return fmt.Errorf("ssh: forwarded listener still open %s after its transport was closed", l.grace)
	}
}

func isWSScheme(scheme string) bool {
	return scheme == "ws" || scheme == "wss"
}

// PermissionDeniedError is a relay that would not authenticate this host.
//
// It says which of the two ways that happened, because they are different
// problems: a host that offered nothing has no identity for the relay to have
// rejected, while a host whose keys were all refused has keys this relay does
// not accept. x/crypto's own error stays reachable through Unwrap for anything
// that wants the handshake's words instead.
type PermissionDeniedError struct {
	host string
	// identities is how many keys were offered and refused; 0 means none was
	// offered at all. It comes from the caller rather than from err, which
	// lists methods and not keys — ssh.PublicKeys is a single "publickey"
	// entry however many signers it carries. That makes it the count the dial
	// went in with rather than the count that reached the wire: x/crypto skips
	// a signer with no signature algorithm in common with the server, and one
	// skipped that way is counted here as offered. Nothing closer is available
	// to count, and the answer — this relay will not take these keys — is the
	// same either way.
	identities int
	err        error
}

func (e *PermissionDeniedError) Error() string {
	// No advice on what to do next. Which key would be accepted is the relay
	// operator's to answer, and a guess at it printed on every refused start
	// would be wrong more often than not.
	var detail string
	switch {
	case e.identities == 1:
		detail = "the 1 identity offered was refused"
	case e.identities > 1:
		detail = fmt.Sprintf("the %d identities offered were refused", e.identities)
	default:
		detail = "no identity was offered"
	}
	return fmt.Sprintf("%s: Permission denied (publickey); %s.", e.host, detail)
}

func (e *PermissionDeniedError) Unwrap() error { return e.err }

// sshDialError turns a failed dial into what the host prints, where identities
// is how many keys the dial had to offer.
func sshDialError(host *url.URL, proxyURL *url.URL, identities int, err error) error {
	if strings.Contains(err.Error(), authFailurePrefix) {
		denied := &PermissionDeniedError{
			host: host.String(),
			err:  err,
		}
		// Only when a key actually went out: the count is the caller's, but
		// whether anything was offered is the handshake's to say.
		if attemptedPublicKey(err.Error()) {
			denied.identities = identities
		}
		return denied
	}

	dialErr := fmt.Errorf("ssh dial error: %w", err)

	// A direct ssh:// dial that failed to reach the host on a machine which
	// defines a proxy is the shape of "egress is proxy-only". upterm does not
	// read those variables for ssh:// servers, the same as OpenSSH, so nothing
	// in the error connects the failure to the proxy the user knows they are
	// behind — and in an agent sandbox, whatever reads this error is what has
	// to work out the next move.
	//
	// Gated on the failure actually being a network one. Everything else this
	// wraps happens after the connection succeeded — a host-key mismatch, a
	// declined prompt, an algorithm mismatch — where a proxy cannot be the
	// cause and the advice would trail a security warning it has nothing to do
	// with.
	if proxyURL == nil && !isWSScheme(host.Scheme) && isNetworkError(err) {
		// Probed with the port, not just the hostname: NO_PROXY entries may be
		// port-specific, and the lookup fills in the scheme's default port for
		// anything that arrives without one — so a bare hostname would be
		// asked about :443 and sail straight past an exemption for :22.
		if envProxy, name := envProxyFor(host.Host); envProxy != nil {
			if envProxy.Scheme == "http" {
				// Exported, not merely assigned: a shell variable would not
				// reach the retried process, and this is read after the
				// original command has already failed.
				return fmt.Errorf("%w; %s is set, but upterm does not use the proxy "+
					"environment for ssh:// servers, the same as OpenSSH — to go through it, "+
					"run: export UPTERM_PROXY=\"$%s\" (which keeps the credentials out of "+
					"the process list), or pass --proxy", dialErr, name, name)
			}
			// Copying it would only trade this error for "only http:// proxies
			// are supported", so the other transport is the one to name. It is
			// offered as a route rather than a promise: whether this particular
			// value serves a ws:// or wss:// dial is gorilla's business, not
			// something to assert on its behalf.
			//
			// The example keeps the host already configured and changes only
			// the scheme. Naming upterm's public relay would silently move the
			// session onto someone else's deployment, which is rarely what a
			// custom --server was chosen for.
			return fmt.Errorf("%w; %s is set, but upterm does not use the proxy "+
				"environment for ssh:// servers, the same as OpenSSH, and --proxy takes "+
				"only http:// values — a ws:// or wss:// server does read the environment, "+
				"e.g. --server %s", dialErr, name, httpproxy.WebSocketServerURL(host.Hostname()))
		}
	}

	return dialErr
}

// attemptedPublicKey reports whether x/crypto's list of attempted methods says
// a key was put in front of the server.
//
// The list is the %v of a []string, so it is read only as far as the closing
// bracket: past it lie the rest of x/crypto's sentence and whatever wrapped
// the error, and a method name found there was not a method that was tried.
// A list that does not parse — a shape this does not know — reads as no key
// offered, which is the claim that stays true either way.
func attemptedPublicKey(msg string) bool {
	_, list, ok := strings.Cut(msg, authFailurePrefix)
	if !ok {
		return false
	}
	if end := strings.IndexByte(list, ']'); end >= 0 {
		list = list[:end]
	}
	return slices.Contains(strings.Fields(strings.TrimPrefix(list, "[")), publicKeyMethod)
}

// isNetworkError reports whether err is a failure to establish or hold the
// connection, as opposed to one the SSH exchange itself produced.
func isNetworkError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// proxyFromEnvironment is how the environment is consulted. A variable because
// the real one answers from a sync.Once populated at its first call in the
// process, which a test cannot then influence with t.Setenv.
var proxyFromEnvironment = http.ProxyFromEnvironment

// envProxyFor reports the proxy the environment would use to reach authority,
// which is a host:port, and the variable that supplied it.
//
// Asking the question this way rather than reading the variables directly is
// what makes the advice safe to give. A proxy that is set but does not apply
// comes back nil, and there are three ways that happens, each of which would
// otherwise produce a wrong suggestion:
//
//   - NO_PROXY exempts this host. The user has said they do not want it
//     proxied, so proposing that they route it through one anyway contradicts
//     their own configuration — and the dial failure is then almost certainly
//     something else.
//   - The value does not parse. Copying it would swap this error for a flag
//     rejection, and no transport would fare better.
//   - Only the variable for the other scheme is set, which is not the one a
//     dial to this host would consult.
//
// The value is inspected only for its scheme and never retained: it may carry
// credentials.
func envProxyFor(authority string) (proxy *url.URL, name string) {
	// https first: it is what a wss:// server, the busier of the two
	// suggestions, would consult.
	for _, scheme := range []string{"https", "http"} {
		u, err := proxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: scheme, Host: authority}})
		if err != nil || u == nil || u.Hostname() == "" {
			continue
		}
		return u, proxyEnvVarName(scheme)
	}
	return nil, ""
}

// proxyEnvVarName names the variable that supplied scheme's proxy, preferring
// whichever spelling is actually set. The lowercase ones are what most shells
// and curl write; on Windows the two name the same variable, so the uppercase
// one is simply what gets reported.
func proxyEnvVarName(scheme string) string {
	upper := strings.ToUpper(scheme) + "_PROXY"
	if os.Getenv(upper) == "" && os.Getenv(scheme+"_proxy") != "" {
		return scheme + "_proxy"
	}
	return upper
}
