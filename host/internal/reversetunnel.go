package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os/user"
	"strings"
	"time"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	publickeyAuthError = "ssh: unable to authenticate, attempted methods [none]"

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
	listenerCloseGrace = 5 * time.Second
)

type ReverseTunnel struct {
	*ssh.Client

	Host              *url.URL
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	KeepAliveDuration time.Duration
	// ProxyURL, when non-nil, is the HTTP proxy to connect to Host through.
	ProxyURL        *url.URL
	HostKeyCallback ssh.HostKeyCallback
	Logger          *slog.Logger

	// ln is the forwarded listener, wrapped so that closing it is bounded by
	// listenerCloseGrace rather than by the relay's willingness to answer.
	ln net.Listener

	// stopKeepAlive ends the goroutine Establish starts. Nil until then.
	stopKeepAlive context.CancelFunc
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
	// Stopped before the client is closed, so the ticker cannot start a ping
	// into a connection that is going away.
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

func (c *ReverseTunnel) Establish(ctx context.Context) (*server.CreateSessionResponse, error) {
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
		publicKeys     [][]byte
		authorizedKeys [][]byte
	)
	if len(c.Signers) > 0 {
		// SSH only tries the first auth method of each type, so group all keys.
		auths = append(auths, ssh.PublicKeys(c.Signers...))
	}
	for _, signer := range c.Signers {
		publicKeys = append(publicKeys, ssh.MarshalAuthorizedKey(signer.PublicKey()))
	}
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

	if isWSScheme(c.Host.Scheme) {
		u, _ := url.Parse(c.Host.String()) // clone
		u.User = url.UserPassword(user.Username, "")
		c.Client, err = ws.NewSSHClient(u, config, false, c.ProxyURL)
	} else if c.ProxyURL != nil {
		c.Client, err = c.dialSSHViaProxy(ctx, config)
	} else {
		c.Client, err = ssh.Dial("tcp", c.Host.Host, config)
	}

	if err != nil {
		return nil, sshDialError(c.Host.String(), err)
	}

	sessResp, err := c.createSession(user.Username, publicKeys, authorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	ln, err := c.Listen("unix", sessResp.SessionID)
	if err != nil {
		return nil, fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

	// The client this listener and this keepalive belong to, read once. A
	// second Establish replaces the field, and either of them acting on the
	// replacement would close a connection that is not the one it is nursing.
	client := c.Client
	// Closing the client is how both of them give up on the relay: it is the
	// only thing that fails a request already on the wire. Nil-safe like
	// Close, since every teardown path here has to survive a tunnel that never
	// finished establishing.
	closeClient := func() {
		if client != nil {
			_ = client.Close()
		}
	}
	c.ln = newBoundedListener(ln, listenerCloseGrace, closeClient)

	// make sure connection is alive
	//
	// On the tunnel's own lifetime, not the caller's. ctx belongs to the
	// session, which outlives a tunnel that is closed before it ends, and
	// Close had no way to stop this: the ticker went on pinging a closed
	// client and logging an error every interval for the rest of the session.
	//
	// A second Establish on the same tunnel replaces the first keepalive
	// rather than orphaning it: overwriting the cancel would leave the
	// previous goroutine with nothing able to stop it, which is the bug this
	// field exists to fix, one level up.
	if c.stopKeepAlive != nil {
		c.stopKeepAlive()
	}
	keepAliveCtx, stopKeepAlive := context.WithCancel(ctx)
	c.stopKeepAlive = stopKeepAlive
	go keepAlive(keepAliveCtx, c.KeepAliveDuration, func() error {
		// TODO: ping with session ID
		_, _, err := client.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		return err
	}, func(err error) {
		// Once, at the point of giving up. Logging every interval said the
		// same thing about the same dead connection until the session ended,
		// which buried whatever else the host had to say.
		baseLogger.Error("relay stopped answering keepalives, closing the tunnel", "error", err)
		// The guest server is parked in Accept on a tunnel that no longer
		// carries anything. Closing the client is what makes Serve return, so
		// OnGuestServerStopped runs and the session is published as
		// disconnected instead of sitting at ready with nobody able to reach
		// it.
		closeClient()
	})

	return sessResp, nil
}

// dialSSHViaProxy connects to an ssh:// server through c.ProxyURL.
func (c *ReverseTunnel) dialSSHViaProxy(ctx context.Context, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, proxyDialTimeout)
	defer cancel()

	conn, err := dialHTTPProxy(dialCtx, c.ProxyURL, c.Host.Host)
	if err != nil {
		return nil, err
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, c.Host.Host, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

func (c *ReverseTunnel) createSession(user string, hostPublicKeys [][]byte, clientAuthorizedKeys [][]byte) (*server.CreateSessionResponse, error) {
	req := &server.CreateSessionRequest{
		HostUser:             user,
		HostPublicKeys:       hostPublicKeys,
		ClientAuthorizedKeys: clientAuthorizedKeys,
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	ok, body, err := c.SendRequest(upterm.ServerCreateSessionRequestType, true, b)
	if err != nil {
		return nil, fmt.Errorf("error initializing session: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("could not initialize session: %s", body)
	}

	var resp server.CreateSessionResponse
	if err := proto.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshaling created session: %w", err)
	}

	return &resp, nil
}

// boundedListener is a forwarded listener whose Close cannot outlive the
// grace. Accept and Addr are the wrapped listener's own: only Close is a
// request-response with the relay, and only Close is at risk.
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

// Close returns what the forwarded listener returned, having waited at most
// the grace for the relay to answer before forcing the transport.
//
// The inner Close runs on its own goroutine because there is nothing to cancel
// it with: it is parked either on the mutex x/crypto serialises global
// requests with, or on the reply channel for its own. Closing the transport
// ends both — the mux loop closes that channel on its way out, and every
// pending request returns EOF — so the result is still collected afterwards
// rather than guessed at.
func (l *boundedListener) Close() error {
	closed := make(chan error, 1)
	go func() { closed <- l.Listener.Close() }()

	timer := time.NewTimer(l.grace)
	defer timer.Stop()

	select {
	case err := <-closed:
		return err
	case <-timer.C:
		l.force()
		return <-closed
	}
}

// keepAlive pings the relay every d until ctx ends or the tunnel is gone.
//
// Each ping is bounded by d, because a ping is a global request whose reply
// comes from the relay's mux loop: a relay that has stopped serving that loop
// leaves SendRequest waiting on a channel nothing will write to, and an
// unbounded wait there is both a goroutine parked for the rest of the session
// and — since the next tick would queue behind it — a tunnel whose death
// nothing notices.
//
// onDead is called at most once, and only for a tunnel that actually failed. A
// ctx that ends is this host's own teardown and says nothing about the relay.
func keepAlive(ctx context.Context, d time.Duration, ping func() error, onDead func(error)) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		err := pingWithin(ctx, d, ping)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			onDead(err)
			return
		}
	}
}

// pingWithin runs one ping and waits at most d for its result.
//
// On a timeout the goroutine is abandoned rather than waited for: it is parked
// in exactly the place this bound exists to escape, and it ends when the
// caller tears the transport down, which is what onDead does. Its channel is
// buffered so that send cannot be what keeps it alive.
func pingWithin(ctx context.Context, d time.Duration, ping func() error) error {
	result := make(chan error, 1)
	go func() { result <- ping() }()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case err := <-result:
		return err
	case <-timer.C:
		return fmt.Errorf("no reply to keepalive within %s", d)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isWSScheme(scheme string) bool {
	return scheme == "ws" || scheme == "wss"
}

type PermissionDeniedError struct {
	host string
	err  error
}

func (e *PermissionDeniedError) Error() string {
	return fmt.Sprintf("%s: Permission denied (publickey).", e.host)
}

func (e *PermissionDeniedError) Unwrap() error { return e.err }

func sshDialError(host string, err error) error {
	if strings.Contains(err.Error(), publickeyAuthError) {
		return &PermissionDeniedError{
			host: host,
			err:  err,
		}
	}

	return fmt.Errorf("ssh dial error: %w", err)
}
