package server

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var ErrServerClosed = errors.New("http: Server closed")

type Proxy struct {
	HostSigners         []ssh.Signer
	UpstreamSigner      ssh.Signer
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger

	listener       net.Listener
	upstreamSigner ssh.Signer
	mu             sync.Mutex
	doneChan       chan struct{}
}

func (p *Proxy) getDoneChan() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.getDoneChanLocked()
}

func (p *Proxy) getDoneChanLocked() chan struct{} {
	if p.doneChan == nil {
		p.doneChan = make(chan struct{})

	}

	return p.doneChan
}

func (p *Proxy) closeDoneChanLocked() {
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

func (p *Proxy) closeListenersLocked() error {
	return p.listener.Close()
}

func (p *Proxy) Shutdown() error {
	p.mu.Lock()
	lnerr := p.closeListenersLocked()
	p.closeDoneChanLocked()
	p.mu.Unlock()

	return lnerr
}

func (p *Proxy) Serve(ln net.Listener) error {
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
			FindUpstream:  p.findUpstream,
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

func isIgnoredErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}

	return false
}

func (p *Proxy) findUpstream(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	var (
		c    net.Conn
		err  error
		user = conn.User()
	)
	if shouldRouteToSSHD(conn) {
		p.Logger.WithField("user", user).Info("dialing sshd")
		c, err = p.SSHDDialListener.Dial()
	} else {
		p.Logger.WithField("session", user).Info("dialing session")
		c, err = p.SessionDialListener.Dial(parseSessionIDFromUser(user))
	}
	if err != nil {
		return nil, nil, err
	}

	return c, &ssh.AuthPipe{
		User:                    user, // TODO: look up client user by public key
		NoneAuthCallback:        noneCallback,
		PasswordCallback:        passwordCallback,
		PublicKeyCallback:       p.publicKeyCallback,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: validate host's public key
	}, nil
}

func (p *Proxy) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	if shouldRouteToSSHD(conn) {
		p.Logger.WithField("user", conn.User()).Info("sshd publickey callback")
		return ssh.AuthPipeTypeMap, ssh.PublicKeys(p.UpstreamSigner), nil
	} else {
		p.Logger.WithField("session", conn.User()).Info("session publickey callback")
		// Can't auth with the public key against session upstream in the Host
		// because we don't have the Client private key to re-sign the request.
		// Public key auth is converted to password key auth with public key as
		// the password so that session upstream in the hostcan at least validate it.
		// The password is in the format of authorized key of the public key.
		authorizedKey := ssh.MarshalAuthorizedKey(key)
		return ssh.AuthPipeTypeMap, ssh.Password(string(authorizedKey)), nil
	}
}

func noneCallback(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func passwordCallback(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	return ssh.AuthPipeTypeNone, nil, nil
}

func shouldRouteToSSHD(conn ssh.ConnMetadata) bool {
	return upterm.HostSSHClientVersion == string(conn.ClientVersion())
}

// user is in the format of username:host-addr@host
func parseSessionIDFromUser(user string) string {
	return strings.SplitN(user, ":", 2)[0]
}
