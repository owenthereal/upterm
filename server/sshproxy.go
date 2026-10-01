package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	HandshakeTimeout    time.Duration
	HostSigners         []ssh.Signer
	Signers             []ssh.Signer
	NodeAddr            string
	AuthorizedKeysFiles []string
	ConnDialer          connDialer
	SessionManager      *SessionManager
	Logger              *slog.Logger
	MetricsProvider     provider.Provider

	routing *SSHRouting
	mux     sync.Mutex
	// stopped records a Shutdown that arrived before Serve; see sshd.stopped.
	stopped bool
}

func (r *sshProxy) Shutdown() error {
	r.mux.Lock()
	defer r.mux.Unlock()

	r.stopped = true

	if r.routing != nil {
		return r.routing.Shutdown()
	}

	return nil
}

func (r *sshProxy) Serve(ln net.Listener) error {
	authorizedKeys, err := loadAuthorizedKeys(r.AuthorizedKeysFiles)
	if err != nil {
		// Serve owns ln once it is handed over, and Shutdown can only close what
		// routing has recorded -- which has not happened yet. Returning without
		// releasing it here leaves the port bound for the life of the process.
		_ = ln.Close()
		return err
	}

	r.mux.Lock()
	if r.stopped {
		r.mux.Unlock()
		_ = ln.Close()
		return ErrListnerClosed
	}
	r.routing = &SSHRouting{
		HostSigners:      r.HostSigners,
		HandshakeTimeout: r.HandshakeTimeout,
		Auth: &proxyAuth{
			HostSigners:    r.HostSigners,
			Signers:        r.Signers,
			SessionManager: r.SessionManager,
			ConnDialer:     r.ConnDialer,
			NodeAddr:       r.NodeAddr,
			authorizedKeys: authorizedKeys,
			Logger:         r.Logger.With("component", "auth"),
		},
		MetricsProvider: r.MetricsProvider,
		Logger:          r.Logger,
	}
	r.mux.Unlock()

	return r.routing.Serve(ln)
}

// What a guest is told when the relay can't take it to a session, ahead of the
// refusal itself, which says nothing more than that authentication failed.
const (
	bannerNoHost = "upterm: no host is connected for session %s right now. " +
		"If it is reconnecting, this same ssh command will work again once it's back. " +
		"Try again in a few seconds.\n"
	bannerLookupFailed = "upterm: the relay can't look up sessions right now. Try again shortly.\n"
)

// lookupError marks a refusal that came from reading the guest's session, not
// from judging the guest, so the guest can be told why it was turned away.
type lookupError struct{ err error }

func (e *lookupError) Error() string { return e.err.Error() }
func (e *lookupError) Unwrap() error { return e.err }

// bannerFor is the banner to send with err, the refusal of meta's connection,
// or "" for none. Only a failed lookup of the guest's session earns one: the
// session isn't stored (its host may be reconnecting, and about to store it
// again) or the store couldn't say. Refusing the guest itself, a key the
// session doesn't admit say, sends none, and neither does a host's connection.
// sessionID is the one meta's user names.
func bannerFor(meta ssh.ConnMetadata, sessionID string, err error) string {
	var lookup *lookupError
	if string(meta.ClientVersion()) == upterm.HostSSHClientVersion || !errors.As(err, &lookup) {
		return ""
	}
	var missing *ErrSessionNotFound
	if errors.As(err, &missing) {
		return fmt.Sprintf(bannerNoHost, sessionID)
	}
	return bannerLookupFailed
}

// errUpstreamHostKeyMismatch is returned by the upstream HostKeyCallback below.
// A sentinel rather than an ad-hoc error so the failure can be recognized after
// x/crypto has wrapped it, and reported to the peer by identity, not by text.
var errUpstreamHostKeyMismatch = errors.New("ssh: host key mismatch")

type proxyAuth struct {
	NodeAddr       string
	authorizedKeys map[string]struct{} // SHA256 fingerprints; nil disables the gate
	SessionManager *SessionManager
	ConnDialer     connDialer
	Signers        []ssh.Signer
	HostSigners    []ssh.Signer

	Logger *slog.Logger
}

func (a proxyAuth) checkAuthorizedKeys(conn ssh.ConnMetadata, pk ssh.PublicKey) error {
	if a.authorizedKeys == nil {
		return nil
	}

	// Only HOST connections (uptermd hosts registering with the proxy) are gated by authorized_keys.
	if string(conn.ClientVersion()) != upterm.HostSSHClientVersion {
		return nil
	}

	fp := publicKeyFingerprint(pk)
	if _, ok := a.authorizedKeys[fp]; ok {
		a.Logger.Info("access granted", "fingerprint", fp)
		return nil
	}

	a.Logger.Warn("access denied", "fingerprint", fp)
	return fmt.Errorf("public key is not authorized")
}

// isOwnAuthority reports whether key is one of this relay's signing keys, and
// so may vouch for a certificate's AuthRequest. Only the relay mints them.
//
// Signers, not HostSigners: Signers is what newUserCertSigners signs with. A
// cross-node hop arrives carrying a certificate a neighbour minted, which this
// recognizes because the nodes of a cluster share these keys -- as the sideway
// branch of prepare's host key callback already requires of HostSigners, which
// is cloned from Signers.
func (a proxyAuth) isOwnAuthority(key ssh.PublicKey) bool {
	return signerAuthority(a.Signers, key)
}

// publicKeyFingerprint returns the SHA256 fingerprint of the underlying
// public key, unwrapping any SSH certificate. authorized_keys files contain
// raw key entries, but hosts authenticating with a CertSigner (commonly
// supplied by ssh-agent) present a certificate; matching must be done on
// the underlying key identity, not the certificate blob.
func publicKeyFingerprint(pk ssh.PublicKey) string {
	if cert, ok := pk.(*ssh.Certificate); ok {
		pk = cert.Key
	}
	return utils.FingerprintSHA256(pk)
}

// loadAuthorizedKeys reads the configured authorized_keys files once at
// startup and returns the set of SHA256 fingerprints permitted to register
// as hosts. Returns nil when paths is empty, signaling that the gate is
// disabled. Edits to the files require restarting uptermd to take effect.
func loadAuthorizedKeys(paths []string) (map[string]struct{}, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	fps := make(map[string]struct{})
	for _, path := range paths {
		rest, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read authorized_keys %s: %w", path, err)
		}

		for len(rest) > 0 {
			pk, _, _, next, perr := ssh.ParseAuthorizedKey(rest)
			if perr != nil {
				// No more parseable keys (trailing comments, blanks, or junk).
				break
			}
			rest = next
			fps[publicKeyFingerprint(pk)] = struct{}{}
		}
	}
	return fps, nil
}

// preparedRoute is one upstream attempt's plan, taken from one snapshot of the
// session: where to dial, which host key to expect there, and the route to
// compare against if it fails. Taking all three from one read is what keeps the
// dial target and the host key it must present from disagreeing.
type preparedRoute struct {
	id     *api.Identifier   // the dial target
	route  Route             // node and generation, for the refresh comparison
	config *ssh.ClientConfig // credentials, and the host-key policy for that target
}

// upstreamTarget is where one read of the session sends a connection, before
// any credentials are attached.
type upstreamTarget struct {
	id    *api.Identifier
	route Route
	// local is the session when it lives on this node: its authorized keys
	// decide who may join, and its host keys are the ones the upstream must
	// present. A host's upstream, and a hop to another node, must present the
	// relay's own; that node checks the guest itself.
	local *Session
}

// admits reports whether key may join the session t leads to.
func (t *upstreamTarget) admits(key ssh.PublicKey) bool {
	return t.local == nil || t.local.IsClientKeyAllowed(key)
}

// authenticate decides who an offered key speaks for, without reading the
// session store: the user's format, the authorized_keys gate on hosts, and the
// identity a certificate this relay minted carries. The key it returns is the
// one a session's authorized keys are checked against.
func (a proxyAuth) authenticate(conn ssh.ConnMetadata, pk ssh.PublicKey) (*AuthRequest, ssh.PublicKey, error) {
	if string(conn.ClientVersion()) == upterm.HostSSHClientVersion {
		if conn.User() == "" {
			return nil, nil, fmt.Errorf("empty session ID for host connection")
		}
	} else if _, _, err := a.SessionManager.GetEncodeDecoder().Decode(conn.User()); err != nil {
		return nil, nil, fmt.Errorf("invalid SSH user format: %w", err)
	}
	checker := UserCertChecker{
		IsUserAuthority: a.isOwnAuthority,
		UserKeyFallback: func(user string, key ssh.PublicKey) (ssh.PublicKey, error) {
			return key, nil
		},
	}

	// Gate registration based on authorized_keys before any cert/upstream work.
	if err := a.checkAuthorizedKeys(conn, pk); err != nil {
		return nil, nil, err
	}

	auth, key, err := checker.Authenticate(conn.User(), pk)
	// A certificate this relay did not mint is not a credential, it is just a
	// key the peer holds: an ssh-agent's own CA certificate arrives this way.
	// Authorizing cert.Key rather than refusing keeps who may join unchanged,
	// and the authorized-key check is what then decides. A malformed
	// AuthRequest from a signer we do trust is a different matter and is not
	// tolerated.
	if errors.Is(err, errCertNotSignedByHost) || errors.Is(err, errCertUntrustedAuthority) {
		err = nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error checking user cert: %w", err)
	}

	// Use the public-key if a key can't be parsed from cert
	if key == nil {
		key = pk
	}

	if auth == nil {
		auth = &AuthRequest{
			ClientVersion: string(conn.ClientVersion()),
			RemoteAddr:    conn.RemoteAddr().String(),
			AuthorizedKey: ssh.MarshalAuthorizedKey(key),
		}
	}

	return auth, key, nil
}

// authorize decides whether an offered key may proceed, and resolves where its
// upstream goes. Stock SSH calls this for unsigned public-key queries as well,
// and a successful query does not count against MaxAuthTries, so it must stay
// cheap: no certificate minting, no upstream connection, and at most one read
// of the session.
func (a proxyAuth) authorize(conn ssh.ConnMetadata, pk ssh.PublicKey) (*AuthRequest, *upstreamTarget, error) {
	auth, key, err := a.authenticate(conn, pk)
	if err != nil {
		return nil, nil, err
	}

	target, err := a.resolve(conn)
	if err != nil {
		return nil, nil, err
	}
	// TODO: simplify auth key validation by moving it to host validation only
	if !target.admits(key) {
		return nil, nil, fmt.Errorf("public key not allowed")
	}

	return auth, target, nil
}

// resolve finds where conn's upstream goes, reading the session at most once.
// A host's goes to this node's sshd. A guest's goes to the node its session is
// on: in Consul mode the store says which, and the same read supplies the rest
// of the route; in embedded mode the user names it, and only a session on this
// node is read, from this node's own store.
func (a proxyAuth) resolve(conn ssh.ConnMetadata) (*upstreamTarget, error) {
	user := conn.User()
	if string(conn.ClientVersion()) == upterm.HostSSHClientVersion {
		return &upstreamTarget{id: &api.Identifier{Id: user, Type: api.Identifier_HOST}}, nil
	}

	sessionID, nodeAddr, sess, err := a.SessionManager.lookupSSHUser(user)
	if err != nil {
		return nil, &lookupError{fmt.Errorf("error resolving SSH user %s: %w", user, err)}
	}
	if sess != nil {
		return a.targetOf(sess), nil
	}

	target := &upstreamTarget{
		id:    &api.Identifier{Id: sessionID, NodeAddr: nodeAddr, Type: api.Identifier_CLIENT},
		route: Route{NodeAddr: nodeAddr},
	}
	if nodeAddr == a.NodeAddr {
		if target.local, err = a.SessionManager.GetSession(sessionID); err != nil {
			return nil, &lookupError{err}
		}
	}
	return target, nil
}

// targetOf is where sess, one snapshot of a guest's session, sends the guest.
func (a proxyAuth) targetOf(sess *Session) *upstreamTarget {
	target := &upstreamTarget{
		id:    &api.Identifier{Id: sess.ID, NodeAddr: sess.NodeAddr, Type: api.Identifier_CLIENT},
		route: Route{NodeAddr: sess.NodeAddr, Generation: sess.Generation},
	}
	if sess.NodeAddr == a.NodeAddr {
		target.local = sess
	}
	return target
}

// plan completes target into an attempt that presents creds.
func (a proxyAuth) plan(conn ssh.ConnMetadata, target *upstreamTarget, creds []ssh.AuthMethod) *preparedRoute {
	hostKeyCb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if target.local == nil {
			// check host keys for sideway connections
			for _, s := range a.HostSigners {
				if utils.KeysEqual(key, s.PublicKey()) {
					return nil
				}
			}
		} else {
			for _, pk := range target.local.HostPublicKeys {
				if utils.KeysEqual(key, pk) {
					return nil
				}
			}
		}

		return errUpstreamHostKeyMismatch
	}

	return &preparedRoute{
		id:     target.id,
		route:  target.route,
		config: &ssh.ClientConfig{User: conn.User(), HostKeyCallback: hostKeyCb, Auth: creds},
	}
}

// prepare mints upstream credentials for a key whose ownership the client has
// already proven, and plans the first attempt with them. It re-runs
// authorization so the decision and the attempt cannot disagree, and takes the
// attempt's dial target, host-key policy and route from the one session read
// that authorization made; that costs one extra session lookup, on success
// only. It does not open a connection.
func (a proxyAuth) prepare(conn ssh.ConnMetadata, pk ssh.PublicKey) (*preparedRoute, error) {
	auth, target, err := a.authorize(conn, pk)
	if err != nil {
		return nil, err
	}

	signers, err := a.newUserCertSigners(conn, auth)
	if err != nil {
		return nil, fmt.Errorf("error creating cert signers: %w", err)
	}

	return a.plan(conn, target, []ssh.AuthMethod{ssh.PublicKeys(signers...)}), nil
}

// prepareFrom plans an attempt from sess, a snapshot of pk's session, with
// creds, the credentials of an attempt prepare planned: the certificates in
// them were minted as the client authenticated, and outlast the upstream
// stage. It authorizes pk against sess as authorize does against its own read,
// and reads nothing itself, so a watch that replaces or removes the cache entry
// meanwhile changes nothing about the attempt.
func (a proxyAuth) prepareFrom(conn ssh.ConnMetadata, pk ssh.PublicKey, sess *Session, creds []ssh.AuthMethod) (*preparedRoute, error) {
	_, key, err := a.authenticate(conn, pk)
	if err != nil {
		return nil, err
	}

	target := a.targetOf(sess)
	if !target.admits(key) {
		return nil, fmt.Errorf("public key not allowed")
	}

	return a.plan(conn, target, creds), nil
}

// canRefresh reports whether conn's upstream may be retried on a refreshed
// route: only a guest's, and only in Consul mode, where the store says which
// node a session is on and the cache answering for it can trail a host's move.
// A host's upstream is this node's sshd, and an embedded-mode user names its
// node itself.
func (a proxyAuth) canRefresh(conn ssh.ConnMetadata) bool {
	return string(conn.ClientVersion()) != upterm.HostSSHClientVersion &&
		a.SessionManager.GetRoutingMode() == routing.ModeConsul
}

// refresh reads pk's session again, skipping the cache, once an attempt on
// attempted has failed, and plans one more attempt if the session has moved
// since: a host can reconnect to another node, or register again, before the
// watch tells this one. It reads under ctx, which is what is left of the
// upstream stage.
func (a proxyAuth) refresh(ctx context.Context, conn ssh.ConnMetadata, pk ssh.PublicKey, attempted *preparedRoute) (*preparedRoute, bool) {
	logger := a.Logger.With("session", attempted.id.Id,
		"attempted_node", attempted.route.NodeAddr, "attempted_generation", attempted.route.Generation)
	fresh, moved, err := a.SessionManager.RefreshRoute(ctx, conn.User(), attempted.route)
	if err != nil {
		logger.Info("could not refresh the route", "error", err)
		return nil, false
	}

	logger = logger.With("node", fresh.NodeAddr, "generation", fresh.Generation)
	if !moved {
		logger.Info("refreshed the route; it has not moved")
		return nil, false
	}
	next, err := a.prepareFrom(conn, pk, fresh, attempted.config.Auth)
	if err != nil {
		logger.Info("refreshed the route; it no longer admits the key", "error", err)
		return nil, false
	}

	logger.Info("refreshed the route; retrying on it")
	return next, true
}

func (a proxyAuth) newUserCertSigners(conn ssh.ConnMetadata, auth *AuthRequest) ([]ssh.Signer, error) {
	var certSigners []ssh.Signer
	for _, s := range a.Signers {
		ucs := UserCertSigner{
			SessionID:   string(conn.SessionID()),
			User:        conn.User(),
			AuthRequest: auth,
		}

		cs, err := ucs.SignCert(s)
		if err != nil {
			return nil, err
		}

		certSigners = append(certSigners, cs)
	}

	return certSigners, nil
}
