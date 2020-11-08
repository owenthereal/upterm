package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	HostSigners     []ssh.Signer
	NodeAddr        string
	ConnDialer      connDialer
	SessionRepo     *sessionRepo
	Logger          log.FieldLogger
	MetricsProvider provider.Provider

	authPiper *authPiper
	routing   *SSHRouting
	mux       sync.Mutex
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
	r.authPiper = &authPiper{
		HostSigners: r.HostSigners,
		SessionRepo: r.SessionRepo,
		NodeAddr:    r.NodeAddr,
	}
	r.routing = &SSHRouting{
		HostSigners:      r.HostSigners,
		Logger:           r.Logger,
		FindUpstreamFunc: r.findUpstream,
		MetricsProvider:  r.MetricsProvider,
	}
	r.mux.Unlock()

	return r.routing.Serve(ln)
}

func (r *sshProxy) findUpstream(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		user = conn.User()
	)

	id, err := api.DecodeIdentifier(user, string(conn.ClientVersion()))
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

	c, err := r.ConnDialer.Dial(*id)
	if err != nil {
		return nil, nil, err
	}

	pipe := r.authPiper.AuthPipe(user)

	return c, pipe, nil
}

type authPiper struct {
	NodeAddr    string
	SessionRepo *sessionRepo
	HostSigners []ssh.Signer
}

func (a authPiper) AuthPipe(user string) *ssh.AuthPipe {
	return &ssh.AuthPipe{
		User:                    user, // TODO: look up client user by public key
		NoneAuthCallback:        a.noneAuthCallback,
		PasswordCallback:        a.passwordCallback,
		PublicKeyCallback:       a.publicKeyCallback,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
	}
}

// publicKeyCallback turns client public key into server cert before passing it to host
// There is no way to pass the client public key directly to host
// because we don't have the Client private key to re-sign the request.
func (a authPiper) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	var (
		auth *AuthRequest
		err  error
	)

	cert, ok := key.(*ssh.Certificate)
	// If public key is a cert, try to parse auth request and public key from it
	if ok {
		auth, key, err = ParseAuthRequestFromCert(conn.User(), cert)
		if err != nil {
			return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error parsing cert: %w", err)
		}
	}

	// TODO: simplify auth key validation by moving it to host validation only
	if err := a.validateClientAuthorizedKey(conn, key); err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error validating client authorized key: %w", err)
	}

	if auth == nil {
		auth = &AuthRequest{
			ClientVersion: string(conn.ClientVersion()),
			RemoteAddr:    conn.RemoteAddr().String(),
			AuthorizedKey: ssh.MarshalAuthorizedKey(key),
		}
	}

	signers, err := a.newCertSigners(conn, *auth)
	if err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error creating cert signers: %w", err)
	}

	return ssh.AuthPipeTypeMap, ssh.PublicKeys(signers...), err
}

func (a authPiper) newCertSigners(conn ssh.ConnMetadata, auth AuthRequest) ([]ssh.Signer, error) {
	var certSigners []ssh.Signer
	for _, hs := range a.HostSigners {
		s := CertSigner{
			SessionID:   string(conn.SessionID()),
			User:        conn.User(),
			AuthRequest: auth,
		}

		cs, err := s.SignCert(hs)
		if err != nil {
			return nil, err
		}

		certSigners = append(certSigners, cs)
	}

	return certSigners, nil
}

func (a authPiper) passwordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (a authPiper) noneAuthCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (a authPiper) validateClientAuthorizedKey(conn ssh.ConnMetadata, key ssh.PublicKey) error {
	user := conn.User()
	id, err := api.DecodeIdentifier(user, string(conn.ClientVersion()))
	if err != nil {
		return fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

	// Don't vdalite authorized key if:
	// 1. This is not a client request
	// 2. The node does not match the request that routing is needed
	if id.Type != api.Identifier_CLIENT || a.NodeAddr != id.NodeAddr {
		return nil
	}

	sess, err := a.SessionRepo.Get(id.Id)
	if err != nil {
		return err
	}

	if !sess.IsClientKeyAllowed(key) {
		return fmt.Errorf("public key not allowed")
	}

	return nil
}
