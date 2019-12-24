package server

import (
	"io"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedStreamlocalChannelType     = "forwarded-streamlocal@openssh.com"
	streamlocalForwardChannelType       = "streamlocal-forward@openssh.com"
	cancelStreamlocalForwardChannelType = "cancel-streamlocal-forward@openssh.com"
)

type streamlocalChannelForwardMsg struct {
	SocketPath string
}

type forwardedStreamlocalPayload struct {
	SocketPath string
	Reserved0  string
}

func newStreamlocalForwardHandler(sessionDialListener SessionDialListener, logger log.FieldLogger) *streamlocalForwardHandler {
	return &streamlocalForwardHandler{
		sessionDialListener: sessionDialListener,
		forwards:            make(map[string]net.Listener),
		logger:              logger,
	}

}

type streamlocalForwardHandler struct {
	sessionDialListener SessionDialListener
	forwards            map[string]net.Listener
	logger              log.FieldLogger
	sync.Mutex
}

func (h *streamlocalForwardHandler) Handler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case streamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Info("error parsing streamlocal payload")
			return false, []byte(err.Error())
		}

		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.SocketPath, 0) {
			return false, []byte("port forwarding is disabled")
		}

		sessionID := reqPayload.SocketPath
		logger := h.logger.WithFields(log.Fields{"session-id": sessionID})
		ln, err := h.sessionDialListener.Listen(sessionID)
		if err != nil {
			logger.WithError(err).Info("error listening socketing")
			return false, []byte(err.Error())
		}

		h.Lock()
		h.forwards[sessionID] = ln
		h.Unlock()

		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[sessionID]
			h.Unlock()
			if ok {
				ln.Close()
			}
		}()

		go func(logger *log.Entry, socketPath string) {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				payload := gossh.Marshal(&forwardedStreamlocalPayload{
					SocketPath: sessionID,
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedStreamlocalChannelType, payload)
					if err != nil {
						logger.WithError(err).Info("error opening channel")
						c.Close()
						return
					}
					go gossh.DiscardRequests(reqs)
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(ch, c)
					}()
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(c, ch)
					}()
				}()
			}
			h.Lock()
			delete(h.forwards, sessionID)
			h.Unlock()
		}(logger, sessionID)

		return true, nil

	case cancelStreamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Info("error parsing steamlocal payload")
			return false, []byte(err.Error())
		}

		h.Lock()
		ln, ok := h.forwards[reqPayload.SocketPath]
		h.Unlock()
		if ok {
			ln.Close()
		}

		return true, nil

	default:
		return false, nil
	}
}
