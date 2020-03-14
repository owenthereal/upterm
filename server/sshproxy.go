package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/host/api"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type SSHProxy struct {
	HostSigners     []ssh.Signer
	ConnDialer      *connDialer
	Logger          log.FieldLogger
	MetricsProvider provider.Provider

	routing *SSHRouting
	mux     sync.Mutex
}

func (r *SSHProxy) Shutdown() error {
	r.mux.Lock()
	defer r.mux.Unlock()

	if r.routing != nil {
		return r.routing.Shutdown()
	}

	return nil
}

func (r *SSHProxy) Serve(ln net.Listener) error {
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

func (r *SSHProxy) findUpstream(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		user = conn.User()
	)

	id, err := api.DecodeIdentifier(user, string(conn.ClientVersion()))
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

	c, err := r.ConnDialer.Dial(id)
	if err != nil {
		return nil, nil, err
	}

	pipe := &ssh.AuthPipe{
		User:                    user, // TODO: look up client user by public key
		NoneAuthCallback:        r.noneCallback,
		PasswordCallback:        r.passThroughPasswordCallback, // password needs to be passed through for sideway routing. Otherwise, it can be discarded
		PublicKeyCallback:       r.convertToPasswordPublicKeyCallback,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
	}
	return c, pipe, nil
}

func (r *SSHProxy) passThroughPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypePassThrough, nil, nil
}

func (r *SSHProxy) convertToPasswordPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	// Can't auth with the public key against session upstream in the Host
	// because we don't have the Client private key to re-sign the request.
	// Public key auth is converted to password key auth with public key as
	// the password so that session upstream in the hostcan at least validate it.
	// The password is in the format of authorized key of the public key.
	authorizedKey := ssh.MarshalAuthorizedKey(key)
	return ssh.AuthPipeTypeMap, ssh.Password(string(authorizedKey)), nil
}

func (r *SSHProxy) noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}
