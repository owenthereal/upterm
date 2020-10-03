package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	proto "github.com/golang/protobuf/proto"
	"github.com/owenthereal/upterm/host/api"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	HostSigners     []ssh.Signer
	ConnDialer      connDialer
	authPiper       authPiper
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
}

func (a authPiper) AuthPipe(user string) *ssh.AuthPipe {
	return &ssh.AuthPipe{
		User:                    user, // TODO: look up client user by public key
		NoneAuthCallback:        a.noneCallback,
		PasswordCallback:        a.passThroughPasswordCallback, // password needs to be passed through for sideway routing. Otherwise, it can be discarded
		PublicKeyCallback:       a.convertToPasswordPublicKeyCallback,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
	}
}

func (a authPiper) passThroughPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	var auth AuthRequest
	if err := proto.Unmarshal(password, &auth); err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error authenticating client in password callback: %w", err)
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(auth.AuthorizedKey)
	if err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error parsing authorized key: %w", err)
	}

	if err := a.validateClientAuthorizedKey(conn, pk); err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error validating client authorized key in password callback: %w", err)
	}

	return ssh.AuthPipeTypePassThrough, nil, nil
}

func (a authPiper) convertToPasswordPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	if err := a.validateClientAuthorizedKey(conn, key); err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error validating client authorized key in public callback: %w", err)
	}

	// Can't auth with the public key against session upstream in the Host
	// because we don't have the Client private key to re-sign the request.
	// Public key auth is converted to password key auth with public key as
	// the password so that session upstream in the host can at least validate it.
	// The password is in the format of authorized key of the public key.
	auth := &AuthRequest{
		ClientVersion: string(conn.ClientVersion()),
		RemoteAddr:    conn.RemoteAddr().String(),
		AuthorizedKey: ssh.MarshalAuthorizedKey(key),
	}
	b, err := proto.Marshal(auth)
	if err != nil {
		return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("error authenticating client in public key callback: %w", err)
	}

	return ssh.AuthPipeTypeMap, ssh.Password(string(b)), nil
}

func (a authPiper) noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (a authPiper) validateClientAuthorizedKey(conn ssh.ConnMetadata, key ssh.PublicKey) error {
	user := conn.User()
	id, err := api.DecodeIdentifier(user, string(conn.ClientVersion()))
	if err != nil {
		return fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

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
