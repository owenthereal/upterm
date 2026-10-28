package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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
	HopSigners          []ssh.Signer
	HopTrusted          []ssh.PublicKey
	NodeTrusted         []ssh.PublicKey
	RefuseHostKeyHops   bool
	NodeAddr            string
	AuthorizedKeysFiles []string
	ConnDialer          connDialer
	SessionManager      *SessionManager
	Logger              *slog.Logger
	MetricsProvider     provider.Provider

	// hostActivity is where hosts' connections to this proxy are recorded, for
	// the node's sshd to judge them by. Server always builds one and shares it
	// with the sshd. Nil only where a test builds the proxy alone.
	hostActivity *hostActivity

	// listener is which of the node's SSH listeners this proxy serves, and so
	// where a guest that connects to it directly entered the fleet. The zero
	// value, the shared listener, establishes no entry point.
	listener listenerKind

	// instruments are the routing metrics this proxy counts into, shared by
	// every SSH proxy of a Server. Nil has the proxy register its own.
	instruments *routingInstruments

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
			HostSigners:       r.HostSigners,
			Signers:           r.Signers,
			HopSigners:        r.HopSigners,
			HopTrusted:        r.HopTrusted,
			NodeTrusted:       r.NodeTrusted,
			RefuseHostKeyHops: r.RefuseHostKeyHops,
			SessionManager:    r.SessionManager,
			ConnDialer:        r.ConnDialer,
			NodeAddr:          r.NodeAddr,
			listener:          r.listener,
			authorizedKeys:    authorizedKeys,
			Logger:            r.Logger.With("component", "auth"),
		},
		MetricsProvider: r.MetricsProvider,
		Logger:          r.Logger,
		hostActivity:    r.hostActivity,
		instruments:     r.instruments,
	}
	r.mux.Unlock()

	return r.routing.Serve(ln)
}

// lookupError marks a refusal that came from reading the guest's session, not
// from judging the guest, so the guest can be told why it was turned away.
type lookupError struct{ err error }

func (e *lookupError) Error() string { return e.err.Error() }
func (e *lookupError) Unwrap() error { return e.err }

// hopRefusal marks a key refused to another relay node, which presents it on a
// guest's behalf, so that node can be told, and tell its guest why.
type hopRefusal struct{ err error }

func (e *hopRefusal) Error() string { return e.err.Error() }
func (e *hopRefusal) Unwrap() error { return e.err }

// undecodableUser marks a guest's user that an embedded-mode relay can't
// decode. Such a user carries the session's node as well as its ID, so one that
// doesn't decode names no session at all: most likely the ID alone, or part of
// the user the host shared, which the guest can be told how to put right.
type undecodableUser struct{ err error }

func (e *undecodableUser) Error() string { return e.err.Error() }
func (e *undecodableUser) Unwrap() error { return e.err }

// permHop is the permissions extension that marks a connection from another
// relay node, presenting a guest's key. A hop announces x/crypto's default
// version, as any Go client does, so the certificate it authenticated with is
// what tells it apart from a plain ssh guest.
const permHop = "upterm-hop"

// bannerFor is the banner to send with err, the refusal of meta's connection,
// or "" for none. A guest earns one by a failed lookup of its session: the
// session isn't stored (its host may be reconnecting, and about to store it
// again) or the store couldn't say. On an embedded-mode relay it earns one too
// by a user that names no session at all. Refusing the guest itself, a key the
// session doesn't admit, say, sends none, and neither does a host's connection.
// A key refused to another relay node earns the hop banner, for that node to
// read. sessionID is the one meta's user names.
func bannerFor(meta ssh.ConnMetadata, sessionID string, err error) string {
	var hop *hopRefusal
	if errors.As(err, &hop) {
		return upterm.HopBannerKeyRefused
	}
	if string(meta.ClientVersion()) == upterm.HostSSHClientVersion {
		return ""
	}
	var undecodable *undecodableUser
	if errors.As(err, &undecodable) {
		// The user prints on the guest's own terminal, so anything unprintable
		// in it is escaped, as bannerSessionID escapes an odd ID. It is quoted
		// whatever its shape, being no session ID.
		return fmt.Sprintf("upterm: %q isn't a session on this relay; use the whole ssh command the host shared.\n", meta.User())
	}
	var lookup *lookupError
	if !errors.As(err, &lookup) {
		return ""
	}
	var missing *ErrSessionNotFound
	if errors.As(err, &missing) {
		return fmt.Sprintf(upterm.BannerNoHostFormat, bannerSessionID(sessionID))
	}
	return upterm.BannerLookupFailed
}

// bannerSessionID is how a banner names sessionID, which is whatever the
// guest's user carries, control characters included, and which the banner
// prints on the guest's own terminal: as is when it has a session ID's shape,
// and quoted, with anything unprintable escaped, otherwise.
func bannerSessionID(sessionID string) string {
	odd := func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
	}
	if len(sessionID) == 0 || len(sessionID) > 64 || strings.ContainsFunc(sessionID, odd) {
		return fmt.Sprintf("%q", sessionID)
	}
	return sessionID
}

var (
	// errHostOnInternalListener refuses a host on the internal listener. Only
	// other relay nodes are meant to reach it, and hosts register on the public
	// one, so this node's sshd takes none from there.
	errHostOnInternalListener = errors.New("hosts register on the public listener")

	// errRelayCertOnPublicListener refuses a relay certificate on the public
	// listener or the bridge. With an internal listener a hop arrives there and
	// nowhere else, so a relay certificate here is no hop, whoever signed it.
	// Authorizing its key instead, as the shared listener does, would admit a
	// hop sent to the wrong listener, on a session open to any key, as the
	// relay's key rather than the guest's.
	errRelayCertOnPublicListener = errors.New("relay certificate on a public listener")

	// errRelayCertFromUntrustedSigner refuses, on the internal listener, a relay
	// certificate that no hop authority signed. Such a certificate there claims
	// to be a hop, and a hop whose signer isn't trusted is refused, not
	// authorized as the certificate's key: on a session open to any key, that
	// would let it join as an ordinary guest.
	errRelayCertFromUntrustedSigner = errors.New("relay certificate from an untrusted signer")
)

// isRelayCertificate reports whether pk is a certificate carrying an
// AuthRequest, the kind a relay node mints for a hop. It is judged from the
// certificate alone, before and apart from who signed it.
func isRelayCertificate(pk ssh.PublicKey) bool {
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return false
	}
	_, ok = cert.Extensions[upterm.SSHCertExtension]
	return ok
}

// errUpstreamHostKeyMismatch is returned by the upstream HostKeyCallback below.
// A sentinel rather than an ad-hoc error so the failure can be recognized after
// x/crypto has wrapped it, and reported to the peer by identity, not by text.
var errUpstreamHostKeyMismatch = errors.New(upterm.UpstreamHostKeyMismatch)

type proxyAuth struct {
	NodeAddr string
	// listener is the one its sshProxy serves: a direct guest's AuthRequest
	// takes its origin from it, and a hop's keeps the one it carries.
	listener          listenerKind
	authorizedKeys    map[string]struct{} // SHA256 fingerprints; nil disables the gate
	SessionManager    *SessionManager
	ConnDialer        connDialer
	Signers           []ssh.Signer
	HopSigners        []ssh.Signer
	HopTrusted        []ssh.PublicKey
	NodeTrusted       []ssh.PublicKey
	RefuseHostKeyHops bool
	HostSigners       []ssh.Signer

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

// isHopAuthority reports whether a key may vouch for a node hop.
func (a proxyAuth) isHopAuthority(key ssh.PublicKey) bool {
	if signerAuthority(a.HopSigners, key) {
		return true
	}
	for _, trusted := range a.HopTrusted {
		if key != nil && bytes.Equal(trusted.Marshal(), key.Marshal()) {
			return true
		}
	}
	return !a.RefuseHostKeyHops && signerAuthority(a.Signers, key)
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

// routeCreds retains both kinds so a refreshed route can change locality.
type routeCreds struct{ relay, hop []ssh.AuthMethod }

// preparedRoute is one upstream attempt's plan, taken from one snapshot of the
// session: where to dial, which host key to expect there, and the route to
// compare against if it fails. Taking all three from one read is what keeps the
// dial target and the host key it must present from disagreeing.
type preparedRoute struct {
	creds  routeCreds
	id     *api.Identifier   // the dial target
	route  Route             // node and generation, for the refresh comparison
	config *ssh.ClientConfig // credentials, and the host-key policy for that target
	// banner is the last banner the target sent as the attempt authenticated.
	// A relay node states its verdict on a refused key there.
	banner string
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

// needsRelayCreds includes registrations at this node's sshd, and guests
// reaching a local host that pins this relay's signing key.
func (t *upstreamTarget) needsRelayCreds() bool {
	return t.id.Type == api.Identifier_HOST || t.local != nil
}

// admits reports whether key may join the session t leads to.
func (t *upstreamTarget) admits(key ssh.PublicKey) bool {
	return t.local == nil || t.local.IsClientKeyAllowed(key)
}

// authenticate decides who an offered key speaks for, without reading the
// session store: the user's format, the authorized_keys gate on hosts, which of
// the node's listeners may take a host or a relay certificate, and the identity
// a certificate this relay minted carries. The key it returns is the one a
// session's authorized keys are checked against. The flag reports that such a
// certificate carried it: the mark of another relay node, presenting a guest's
// key. A guest's own agent certificate is not one.
func (a proxyAuth) authenticate(conn ssh.ConnMetadata, pk ssh.PublicKey) (*AuthRequest, ssh.PublicKey, bool, error) {
	if string(conn.ClientVersion()) == upterm.HostSSHClientVersion {
		// First of all, so nothing is dialed for it.
		if a.listener == listenerInternal {
			return nil, nil, false, errHostOnInternalListener
		}
		if conn.User() == "" {
			return nil, nil, false, fmt.Errorf("empty session ID for host connection")
		}
	} else if _, _, err := a.SessionManager.GetEncodeDecoder().Decode(conn.User()); err != nil {
		err = fmt.Errorf("invalid SSH user format: %w", err)
		// Only an embedded-mode user carries more than the session ID, and so
		// can be cut short to the ID alone. A Consul-mode user is the ID
		// itself, and any but an empty one decodes.
		if a.SessionManager.GetRoutingMode() == routing.ModeEmbedded {
			err = &undecodableUser{err}
		}
		return nil, nil, false, err
	}
	checker := UserCertChecker{
		IsUserAuthority: a.isHopAuthority,
		UserKeyFallback: func(user string, key ssh.PublicKey) (ssh.PublicKey, error) {
			return key, nil
		},
	}

	// Gate registration based on authorized_keys before any cert/upstream work.
	if err := a.checkAuthorizedKeys(conn, pk); err != nil {
		return nil, nil, false, err
	}

	// Where an internal listener exists, a relay certificate is a hop on that
	// listener and nowhere else.
	relayCert := isRelayCertificate(pk)
	if relayCert && (a.listener == listenerPublic || a.listener == listenerBridge) {
		return nil, nil, false, errRelayCertOnPublicListener
	}

	auth, key, err := checker.Authenticate(conn.User(), pk)
	// On the internal listener a relay certificate is a hop or nothing.
	if relayCert && a.listener == listenerInternal && errors.Is(err, errCertUntrustedAuthority) {
		return nil, nil, false, errRelayCertFromUntrustedSigner
	}
	// Otherwise a certificate this relay did not mint is not a credential, it
	// is just a key the peer holds: an ssh-agent's own CA certificate arrives
	// this way. Authorizing cert.Key rather than refusing keeps who may join
	// unchanged, and the authorized-key check is what then decides. A
	// malformed AuthRequest from a signer we do trust is a different matter and
	// is not tolerated.
	if errors.Is(err, errCertNotSignedByHost) || errors.Is(err, errCertUntrustedAuthority) {
		err = nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("error checking user cert: %w", err)
	}

	// Use the public-key if a key can't be parsed from cert
	if key == nil {
		key = pk
	}

	// Only a certificate this relay's authority minted yields an AuthRequest,
	// and only a relay node holds one. It is the guest's own, as the node the
	// guest entered by recorded it, and goes on unchanged, its origin included:
	// that node is the only one that knew where the guest came in.
	hop := auth != nil
	if auth == nil {
		auth = &AuthRequest{
			ClientVersion: string(conn.ClientVersion()),
			RemoteAddr:    conn.RemoteAddr().String(),
			// Behind a PROXY-protocol front end this is the address the
			// guest dialled, which is what sshd puts in SSH_CONNECTION.
			LocalAddr:     conn.LocalAddr().String(),
			AuthorizedKey: ssh.MarshalAuthorizedKey(key),
		}
		// Only a guest's request records where it entered. A host's goes to
		// this node's own sshd, which admits the host by it, and stays as it
		// has always been.
		if string(conn.ClientVersion()) != upterm.HostSSHClientVersion {
			auth.Ingress, auth.IngressNode, auth.IngressConnection = originOf(a.listener, conn, a.NodeAddr)
		}
	}

	return auth, key, hop, nil
}

// authorize decides whether an offered key may proceed, and resolves where its
// upstream goes. Stock SSH calls this for unsigned public-key queries as well,
// and a successful query does not count against MaxAuthTries, so it must stay
// cheap: no certificate minting, no upstream connection, and at most one read
// of the session. The flag reports, as authenticate's does, that the key is
// another relay node's.
func (a proxyAuth) authorize(conn ssh.ConnMetadata, pk ssh.PublicKey) (*AuthRequest, *upstreamTarget, bool, error) {
	auth, key, hop, err := a.authenticate(conn, pk)
	if err != nil {
		return nil, nil, false, err
	}

	target, err := a.resolve(conn)
	if err != nil {
		return nil, nil, false, err
	}
	// TODO: simplify auth key validation by moving it to host validation only
	if !target.admits(key) {
		err = fmt.Errorf("public key not allowed")
		if hop {
			err = &hopRefusal{err}
		}
		return nil, nil, false, err
	}

	return auth, target, hop, nil
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

	// A failed read of the store comes back as a lookupError already, and a
	// user that doesn't decode isn't one.
	sessionID, nodeAddr, sess, err := a.SessionManager.lookupSSHUser(user)
	if err != nil {
		return nil, fmt.Errorf("error resolving SSH user %s: %w", user, err)
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
func (a proxyAuth) plan(conn ssh.ConnMetadata, target *upstreamTarget, creds routeCreds) *preparedRoute {
	hostKeyCb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if target.local == nil {
			// check host keys for sideway connections
			for _, s := range a.HostSigners {
				if utils.KeysEqual(key, s.PublicKey()) {
					return nil
				}
			}

			if target.id.Type != api.Identifier_HOST {
				for _, trusted := range a.NodeTrusted {
					if utils.KeysEqual(key, trusted) {
						return nil
					}
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

	pr := &preparedRoute{id: target.id, route: target.route, creds: creds}
	auth := creds.hop
	if target.needsRelayCreds() {
		auth = creds.relay
	}
	pr.config = &ssh.ClientConfig{User: conn.User(), HostKeyCallback: hostKeyCb, Auth: auth}
	pr.config.BannerCallback = func(message string) error {
		pr.banner = message
		return nil
	}
	return pr
}

// prepare mints upstream credentials for a key whose ownership the client has
// already proven, and plans the first attempt with them. It re-runs
// authorization so the decision and the attempt cannot disagree, and takes the
// attempt's dial target, host-key policy and route from the one session read
// that authorization made; that costs one extra session lookup, on success
// only. It does not open a connection. The permissions it returns are the
// client connection's, carrying permHop when the key is another relay node's.
func (a proxyAuth) prepare(conn ssh.ConnMetadata, pk ssh.PublicKey) (*preparedRoute, *ssh.Permissions, error) {
	auth, target, hop, err := a.authorize(conn, pk)
	if err != nil {
		return nil, nil, err
	}

	signers, err := a.newUserCertSigners(conn, auth)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cert signers: %w", err)
	}

	perms := &ssh.Permissions{}
	if hop {
		perms.Extensions = map[string]string{permHop: ""}
	}
	creds := routeCreds{relay: []ssh.AuthMethod{ssh.PublicKeys(signers...)}}
	creds.hop = creds.relay
	if len(a.HopSigners) > 0 {
		hop, err := signUserCerts(conn, auth, a.HopSigners[:1])
		if err != nil {
			return nil, nil, fmt.Errorf("error creating hop cert signer: %w", err)
		}
		creds.hop = []ssh.AuthMethod{ssh.PublicKeys(hop...)}
	}
	return a.plan(conn, target, creds), perms, nil
}

// prepareFrom plans an attempt from sess, a snapshot of pk's session, with
// creds, the credentials of an attempt prepare planned: the certificates in
// them were minted as the client authenticated, and outlast the upstream
// stage. It authorizes pk against sess as authorize does against its own read,
// and reads nothing itself, so a watch that replaces or removes the cache entry
// meanwhile changes nothing about the attempt.
func (a proxyAuth) prepareFrom(conn ssh.ConnMetadata, pk ssh.PublicKey, sess *Session, creds routeCreds) (*preparedRoute, error) {
	_, key, _, err := a.authenticate(conn, pk)
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
	next, err := a.prepareFrom(conn, pk, fresh, attempted.creds)
	if err != nil {
		logger.Info("refreshed the route; it no longer admits the key", "error", err)
		return nil, false
	}

	logger.Info("refreshed the route; retrying on it")
	return next, true
}

// newUserCertSigners mints, with each of the relay's signing keys, a
// certificate that presents auth upstream. Its KeyId is conn's own SSH session
// ID, a hop's as well: the sshd binds a host's session proof to it, the one
// value both ends of that connection share. A guest's ID at the node it
// entered by travels in auth instead, as ingress_connection.
func (a proxyAuth) newUserCertSigners(conn ssh.ConnMetadata, auth *AuthRequest) ([]ssh.Signer, error) {
	return signUserCerts(conn, auth, a.Signers)
}

func signUserCerts(conn ssh.ConnMetadata, auth *AuthRequest, signers []ssh.Signer) ([]ssh.Signer, error) {
	var certSigners []ssh.Signer
	for _, s := range signers {
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
