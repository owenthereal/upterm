package server

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	proto "github.com/golang/protobuf/proto"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
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
	if err := a.validateClientAuthorizedKey(conn, key); err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error validating client authorized key in public callback: %w", err)
	}

	auth := &AuthRequest{
		ClientVersion: string(conn.ClientVersion()),
		RemoteAddr:    conn.RemoteAddr().String(),
		AuthorizedKey: ssh.MarshalAuthorizedKey(key),
	}
	b, err := proto.Marshal(auth)
	if err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error authenticating client in public key callback: %w", err)
	}

	var certSigners []ssh.Signer
	for _, hs := range a.HostSigners {
		// Ref: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
		at := time.Now()
		bt := at.Add(1 * time.Minute) // cert valid for 1 min
		cert := &ssh.Certificate{
			Nonce:           []byte(utils.GenerateNonce()),
			Key:             hs.PublicKey(),
			CertType:        ssh.HostCert,
			KeyId:           string(conn.SessionID()),
			ValidPrincipals: []string{conn.User()},
			ValidAfter:      uint64(at.Unix()),
			ValidBefore:     uint64(bt.Unix()),
			SignatureKey:    hs.PublicKey(), // TODO: use different key
			Permissions: ssh.Permissions{
				Extensions: map[string]string{upterm.SSHCertExtension: string(b)},
			},
		}
		// TODO: use differnt key
		if err := cert.SignCert(rand.Reader, hs); err != nil {
			return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error signing host cert: %w", err)
		}

		cs, err := ssh.NewCertSigner(cert, hs)
		if err != nil {
			return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error generating host signer: %w", err)
		}

		certSigners = append(certSigners, cs)
	}

	return ssh.AuthPipeTypeMap, ssh.PublicKeys(certSigners...), err
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
