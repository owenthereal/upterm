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

	ln net.Listener

	// stopKeepAlive ends the goroutine Establish starts. Nil until then.
	stopKeepAlive context.CancelFunc
}

// Close releases whatever Establish took, and works on a tunnel that never
// established anything. Establish gives up at three different points — the
// dial, the session request, the listen — and each leaves a different subset
// of these set; a Close that assumed the successful one would turn a failed
// dial into a nil dereference in the caller's teardown.
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

	c.ln, err = c.Listen("unix", sessResp.SessionID)
	if err != nil {
		return nil, fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

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
	go keepAlive(keepAliveCtx, c.KeepAliveDuration, func() {
		// TODO: ping with session ID
		_, _, err := c.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		if err != nil {
			baseLogger.Error("error pinging server", "error", err)
		}
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

func keepAlive(ctx context.Context, d time.Duration, fn func()) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
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
