package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/host/api"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	tcpDialTimeout = 1 * time.Second
)

type SSHProxy struct {
	HostSigners         []ssh.Signer
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	NodeAddr            string
	UpstreamNode        bool

	Logger          log.FieldLogger
	MetricsProvider provider.Provider

	routing *Routing
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
	r.routing = &Routing{
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
		c    net.Conn
		err  error
		user = conn.User()
	)

	id, err := api.DecodeIdentifier(user, string(conn.ClientVersion()))
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding identifier from user %s: %w", user, err)
	}

	if id.Type == api.Identifier_HOST {
		r.Logger.WithField("user", id.Id).Info("dialing sshd")
		c, err = r.SSHDDialListener.Dial()
	} else {
		host, port, ee := net.SplitHostPort(id.NodeAddr)
		if ee != nil {
			return nil, nil, fmt.Errorf("host address %s is malformed: %w", user, ee)
		}
		addr := net.JoinHostPort(host, port)

		if r.NodeAddr == addr {
			r.Logger.WithFields(log.Fields{"session": id.Id, "addr": addr}).Info("dialing session")
			c, err = r.SessionDialListener.Dial(id.Id)
		} else {
			// route to neighbour nodes
			r.Logger.WithFields(log.Fields{"session": id.Id, "addr": addr}).Info("routing session")
			c, err = net.DialTimeout("tcp", addr, tcpDialTimeout)
		}
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
			PasswordCallback:        r.passThroughPasswordCallback, // password needs to be passed through for sideway routing. Otherwise, it can be discarded
			PublicKeyCallback:       r.convertToPasswordPublicKeyCallback,
			UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
		}

	}
	return c, pipe, nil
}

func (r *SSHProxy) discardPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
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
