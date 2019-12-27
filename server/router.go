package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jingweno/upterm/upterm"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var ErrServerClosed = errors.New("http: Server closed")

type FindUpstreamFunc func(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error)

type Router struct {
	HostSigners      []ssh.Signer
	FindUpstreamFunc FindUpstreamFunc
	Logger           log.FieldLogger

	listener net.Listener
	mu       sync.Mutex
	doneChan chan struct{}
}

func (p *Router) getDoneChan() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.getDoneChanLocked()
}

func (p *Router) getDoneChanLocked() chan struct{} {
	if p.doneChan == nil {
		p.doneChan = make(chan struct{})

	}

	return p.doneChan
}

func (p *Router) closeDoneChanLocked() {
	ch := p.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by s.mu.
		close(ch)
	}
}

func (p *Router) closeListenersLocked() error {
	return p.listener.Close()
}

func (p *Router) Shutdown() error {
	p.mu.Lock()
	lnerr := p.closeListenersLocked()
	p.closeDoneChanLocked()
	p.mu.Unlock()

	return lnerr
}

func (p *Router) Serve(ln net.Listener) error {
	p.listener = ln

	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				p.Logger.Infof("http: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			p.Logger.WithError(err).Info("failed to accept connection")
			return err
		}

		tempDelay = 0

		logger := p.Logger.WithField("addr", conn.RemoteAddr())
		logger.Info("connection accepted")

		piper := &ssh.PiperConfig{
			FindUpstream:  p.FindUpstreamFunc,
			ServerVersion: upterm.ServerSSHServerVersion,
		}
		for _, signer := range p.HostSigners {
			piper.AddHostKey(signer)
		}

		go func(c net.Conn, logger log.FieldLogger) {
			defer c.Close()

			pipec := make(chan *ssh.PiperConn, 0)
			errorc := make(chan error, 0)

			go func() {
				p, err := ssh.NewSSHPiperConn(c, piper)

				if err != nil {
					errorc <- err
					return
				}

				pipec <- p
			}()

			var pc *ssh.PiperConn
			select {
			case pc = <-pipec:
			case err := <-errorc:
				logger.WithError(err).Info("connection establishing failed")
				return
			case <-time.After(30 * time.Second):
				logger.WithError(err).Info("pipe establishing timeout")
				return
			}

			defer pc.Close()

			if err := pc.Wait(); err != nil && !isIgnoredErr(err) {
				logger.WithError(err).Info("error waiting for pipe")
			}

			logger.Info("connection closed")
		}(conn, logger)
	}
}

type GlobalRouter struct {
	HostSigners  []ssh.Signer
	UpstreamHost string
	Logger       log.FieldLogger
	router       *Router
}

func (r *GlobalRouter) Shutdown() error {
	if r.router != nil {
		return r.router.Shutdown()
	}

	return nil
}

func (r *GlobalRouter) Serve(ln net.Listener) error {
	r.router = &Router{
		HostSigners:      r.HostSigners,
		Logger:           r.Logger,
		FindUpstreamFunc: r.findUpstreamFunc,
	}

	return r.router.Serve(ln)
}

func (r *GlobalRouter) findUpstreamFunc(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		c    net.Conn
		err  error
		user = conn.User()
	)

	split := strings.SplitN(user, ":", 2)
	// e.g., username:127.0.0.1:2222
	if len(split) == 2 {
		host, port, err := net.SplitHostPort(split[1])
		if err != nil {
			return nil, nil, fmt.Errorf("host address %s is malformed: %w", user, err)
		}

		c, err = net.Dial("tcp", net.JoinHostPort(host, port))
	} else {
		c, err = net.Dial("tcp", r.UpstreamHost) // if no host addr is specified, route to upstream LB
	}
	if err != nil {
		return nil, nil, err
	}

	pipe := &ssh.AuthPipe{
		User:                    user, // TODO: look up user by public key
		NoneAuthCallback:        r.noneCallback,
		PasswordCallback:        r.passwordCallback,
		PublicKeyCallback:       r.publicKeyCallback,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
	}

	return c, pipe, nil
}

func (r *GlobalRouter) noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (r *GlobalRouter) passwordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
}

func (r *GlobalRouter) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	// Can't auth with the public key against upstream because we don't have
	// the Client private key to re-sign the request. Public key auth is converted
	// to password key auth with public key as the password so that upstream can at
	// least validate it.
	// The password is in the format of authorized key of the public key.
	authorizedKey := ssh.MarshalAuthorizedKey(key)
	return ssh.AuthPipeTypeMap, ssh.Password(string(authorizedKey)), nil
}

type LocalRouter struct {
	HostSigners         []ssh.Signer
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	UpstreamNode        bool
	Logger              log.FieldLogger

	router *Router
}

func (r *LocalRouter) Shutdown() error {
	if r.router != nil {
		return r.router.Shutdown()
	}

	return nil
}

func (r *LocalRouter) Serve(ln net.Listener) error {
	r.router = &Router{
		HostSigners:      r.HostSigners,
		Logger:           r.Logger,
		FindUpstreamFunc: r.findUpstream,
	}

	return r.router.Serve(ln)
}

func (r *LocalRouter) findUpstream(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		c    net.Conn
		err  error
		user = conn.User()
	)
	if r.shouldRouteToSSHD(conn) {
		r.Logger.WithField("user", user).Info("dialing sshd")
		c, err = r.SSHDDialListener.Dial()
	} else {
		r.Logger.WithField("session", user).Info("dialing session")
		c, err = r.SessionDialListener.Dial(r.parseSessionIDFromUser(user))
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

func (r *LocalRouter) discardPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
}

func (r *LocalRouter) passThroughPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypePassThrough, nil, nil
}

func (r *LocalRouter) convertToPasswordPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	// Can't auth with the public key against session upstream in the Host
	// because we don't have the Client private key to re-sign the request.
	// Public key auth is converted to password key auth with public key as
	// the password so that session upstream in the hostcan at least validate it.
	// The password is in the format of authorized key of the public key.
	authorizedKey := ssh.MarshalAuthorizedKey(key)
	return ssh.AuthPipeTypeMap, ssh.Password(string(authorizedKey)), nil
}

func (r *LocalRouter) noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func (r *LocalRouter) discardPasswordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeDiscard, nil, nil
}

func (r *LocalRouter) shouldRouteToSSHD(conn ssh.ConnMetadata) bool {
	return utils.IsHostUser(conn.User()) || upterm.HostSSHClientVersion == string(conn.ClientVersion())
}

// user is in the format of username:host-addr@host
func (r *LocalRouter) parseSessionIDFromUser(user string) string {
	return strings.SplitN(user, ":", 2)[0]
}

func isIgnoredErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}

	return false
}
