package server

import (
	"fmt"
	"net"
	"sync"

	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Proxy struct {
	HostSigners         []ssh.Signer
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	UpstreamNode        bool
	Logger              log.FieldLogger

	routing *Routing
	mux     sync.Mutex
}

func (r *Proxy) Shutdown() error {
	r.mux.Lock()
	defer r.mux.Unlock()

	if r.routing != nil {
		return r.routing.Shutdown()
	}

	return nil
}

func (r *Proxy) Serve(ln net.Listener) error {
	r.mux.Lock()
	r.routing = &Routing{
		HostSigners:      r.HostSigners,
		Logger:           r.Logger,
		FindUpstreamFunc: r.findUpstream,
	}
	r.mux.Unlock()

	return r.routing.Serve(ln)
}

func (r *Proxy) findUpstream(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		c    net.Conn
		err  error
		user = conn.User()
	)

	id, err := api.DecodeIdentifier(user)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

	if id.Type == api.Identifier_HOST {
		// Drop early if the request is not from a known client
		if !r.UpstreamNode && !r.isKnownClient(conn) {
			return nil, nil, fmt.Errorf("unknown client: client=%s user=%s", conn.ClientVersion(), id.Id)
		}

		r.Logger.WithField("user", id.Id).Info("dialing sshd")
		c, err = r.SSHDDialListener.Dial()
	} else {
		r.Logger.WithField("session", id.Id).Info("dialing session")
		c, err = r.SessionDialListener.Dial(id.Id)
	}
	if err != nil {
		return nil, nil, err
	}

	var pipe *ssh.AuthPipe
	if r.UpstreamNode {
		pipe = &ssh.AuthPipe{
			User:                    user, // TODO: look up client user by public key
			NoneAuthCallback:        r.noneCallback,
			PasswordCallback:        r.passThroughPasswordCallback,
			PublicKeyCallback:       r.discardPublicKeyCallback,
			UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
		}
	} else {
		pipe = &ssh.AuthPipe{
			User:                    user, // TODO: look up client user by public key
			NoneAuthCallback:        r.noneCallback,
			PasswordCallback:        r.discardPasswordCallback,
			PublicKeyCallback:       r.convertToPasswordPublicKeyCallback,
			UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
		}

	}
	return c, pipe, nil
}

func (r *Proxy) isKnownClient(conn ssh.ConnMetadata) bool {
	return string(conn.ClientVersion()) == upterm.HostSSHClientVersion
}

func (r *Proxy) discardPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
}

func (r *Proxy) passThroughPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypePassThrough, nil, nil
}

func (r *Proxy) convertToPasswordPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	// Can't auth with the public key against session upstream in the Host
	// because we don't have the Client private key to re-sign the request.
	// Public key auth is converted to password key auth with public key as
	// the password so that session upstream in the hostcan at least validate it.
	// The password is in the format of authorized key of the public key.
	authorizedKey := ssh.MarshalAuthorizedKey(key)
	return ssh.AuthPipeTypeMap, ssh.Password(string(authorizedKey)), nil
}

func (r *Proxy) noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (r *Proxy) discardPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
}
