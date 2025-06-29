package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	HostSigners     []ssh.Signer
	Signers         []ssh.Signer
	NodeAddr        string
	ConnDialer      connDialer
	SessionManager  *SessionManager
	Logger          log.FieldLogger
	MetricsProvider provider.Provider

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
	r.mux.Lock()
	r.routing = &SSHRouting{
		HostSigners: r.HostSigners,
		AuthPiper: &authPiper{
			HostSigners:    r.HostSigners,
			Signers:        r.Signers,
			SessionManager: r.SessionManager,
			ConnDialer:     r.ConnDialer,
			NodeAddr:       r.NodeAddr,
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
	SessionManager *SessionManager
	ConnDialer     connDialer
	Signers        []ssh.Signer
	HostSigners    []ssh.Signer
}

func (a authPiper) PublicKeyCallback(conn ssh.ConnMetadata, pk ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	checker := UserCertChecker{
		UserKeyFallback: func(user string, key ssh.PublicKey) (ssh.PublicKey, error) {
			return key, nil
		},
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
