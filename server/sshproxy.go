package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
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
}

func (r *sshProxy) Shutdown() error {
	r.mux.Lock()
	defer r.mux.Unlock()

	if r.routing != nil {
		return r.routing.Shutdown()
	}

	return nil
}

func (r *sshProxy) Serve(ln net.Listener) error {
	authorizedKeys, err := loadAuthorizedKeys(r.AuthorizedKeysFiles)
	if err != nil {
		return err
	}

	r.mux.Lock()
	r.routing = &SSHRouting{
		HostSigners: r.HostSigners,
		AuthPiper: &authPiper{
			HostSigners:    r.HostSigners,
			Signers:        r.Signers,
			SessionManager: r.SessionManager,
			ConnDialer:     r.ConnDialer,
			NodeAddr:       r.NodeAddr,
			authorizedKeys: authorizedKeys,
			Logger:         r.Logger.With("component", "auth"),
		},
		Decoder:         r.SessionManager.GetEncodeDecoder(),
		MetricsProvider: r.MetricsProvider,
		Logger:          r.Logger,
	}
	r.mux.Unlock()

	return r.routing.Serve(ln)
}

type authPiper struct {
	NodeAddr       string
	authorizedKeys map[string]struct{} // SHA256 fingerprints; nil disables the gate
	SessionManager *SessionManager
	ConnDialer     connDialer
	Signers        []ssh.Signer
	HostSigners    []ssh.Signer

	Logger *slog.Logger
}

func (a authPiper) checkAuthorizedKeys(conn ssh.ConnMetadata, pk ssh.PublicKey) error {
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

func (a authPiper) PublicKeyCallback(conn ssh.ConnMetadata, pk ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	checker := UserCertChecker{
		UserKeyFallback: func(user string, key ssh.PublicKey) (ssh.PublicKey, error) {
			return key, nil
		},
	}

	// Gate registration based on authorized_keys before any cert/upstream work.
	if err := a.checkAuthorizedKeys(conn, pk); err != nil {
		return nil, err
	}

	auth, key, err := checker.Authenticate(conn.User(), pk)
	if err == errCertNotSignedByHost {
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("error checking user cert: %w", err)
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

	hostSess, err := a.hostSession(conn)
	if err != nil {
		return nil, err
	}
	// TODO: simplify auth key validation by moving it to host validation only
	if hostSess != nil && !hostSess.IsClientKeyAllowed(key) {
		return nil, fmt.Errorf("public key not allowed")
	}

	signers, err := a.newUserCertSigners(conn, auth)
	if err != nil {
		return nil, fmt.Errorf("error creating cert signers: %w", err)
	}

	c, err := a.dialUpstream(conn)
	if err != nil {
		return nil, fmt.Errorf("error dialing upstream: %w", err)
	}

	hostKeyCb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if hostSess == nil {
			// check host keys for sideway connections
			for _, s := range a.HostSigners {
				if utils.KeysEqual(key, s.PublicKey()) {
					return nil
				}
			}
		} else {
			for _, pk := range hostSess.HostPublicKeys {
				if utils.KeysEqual(key, pk) {
					return nil
				}
			}
		}

		return fmt.Errorf("ssh: host key mismatch")
	}

	return &ssh.Upstream{
		Conn:    c,
		Address: conn.RemoteAddr().String(),
		ClientConfig: ssh.ClientConfig{
			HostKeyCallback: hostKeyCb,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		},
	}, nil
}

func (a *authPiper) dialUpstream(conn ssh.ConnMetadata) (net.Conn, error) {
	var (
		user          = conn.User()
		clientVersion = string(conn.ClientVersion())
	)

	// Determine connection type and create identifier accordingly
	var id *api.Identifier
	if clientVersion == upterm.HostSSHClientVersion {
		// HOST connection: user is the session ID
		id = &api.Identifier{
			Id:   user,
			Type: api.Identifier_HOST,
		}
	} else {
		// CLIENT connection: decode the SSH user
		sessionID, nodeAddr, err := a.SessionManager.ResolveSSHUser(user)
		if err != nil {
			return nil, fmt.Errorf("error resolving SSH user %s: %w", user, err)
		}

		id = &api.Identifier{
			Id:       sessionID,
			NodeAddr: nodeAddr,
			Type:     api.Identifier_CLIENT,
		}
	}

	c, err := a.ConnDialer.Dial(id)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (a authPiper) newUserCertSigners(conn ssh.ConnMetadata, auth *AuthRequest) ([]ssh.Signer, error) {
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

// hostSession returns a session if the routing is required to be done on client side and the current
// is proxy node.
func (a *authPiper) hostSession(conn ssh.ConnMetadata) (*Session, error) {
	user := conn.User()
	clientVersion := string(conn.ClientVersion())

	// HOST connections don't validate authorized keys
	if clientVersion == upterm.HostSSHClientVersion {
		return nil, nil
	}

	// CLIENT connection: decode the SSH user to get session ID and node address
	sessionID, nodeAddr, err := a.SessionManager.ResolveSSHUser(user)
	if err != nil {
		return nil, fmt.Errorf("error decoding SSH user %s: %w", user, err)
	}

	// Don't validate authorized key if the node does not match the request that routing is needed
	if a.NodeAddr != nodeAddr {
		return nil, nil
	}

	return a.SessionManager.GetSession(sessionID)
}
