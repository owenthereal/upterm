package server

import (
	"io"
	"net"
	"sync"

	"github.com/charmbracelet/ssh"
	"github.com/oklog/run"
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

func newStreamlocalForwardHandler(
	sessionStore SessionStore,
	sessionDialListener SessionDialListener,
	logger log.FieldLogger,
) *streamlocalForwardHandler {
	return &streamlocalForwardHandler{
		sessionStore:        sessionStore,
		sessionDialListener: sessionDialListener,
		forwards:            make(map[string]net.Listener),
		logger:              logger,
	}
}

type streamlocalForwardHandler struct {
	sessionStore        SessionStore
	sessionDialListener SessionDialListener
	forwards            map[string]net.Listener
	logger              log.FieldLogger
	sync.Mutex
}

func (h *streamlocalForwardHandler) listen(ctx ssh.Context, ln net.Listener, sessionID string, logger log.FieldLogger) error {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(sessionID string, logger log.FieldLogger) {
			payload := gossh.Marshal(&forwardedStreamlocalPayload{
				SocketPath: sessionID,
			})
			ch, reqs, err := conn.OpenChannel(forwardedStreamlocalChannelType, payload)
			if err != nil {
				logger.WithError(err).Error("error opening channel")
				_ = c.Close()
				return
			}

			closeAll := func() {
				_ = ch.Close()
				_ = c.Close()
			}

			var g run.Group
			{
				g.Add(func() error {
					gossh.DiscardRequests(reqs)
					return nil
				}, func(err error) {
					closeAll()
				})
			}
			{
				g.Add(func() error {
					_, err := io.Copy(ch, c)
					return err
				}, func(err error) {
					closeAll()
				})
			}
			{
				g.Add(func() error {
					_, err := io.Copy(c, ch)
					return err
				}, func(err error) {
					closeAll()
				})
			}

			if err := g.Run(); err != nil {
				logger.WithError(err).Error("error listening connection")
			}
		}(sessionID, logger)
	}
}

func (h *streamlocalForwardHandler) Handler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	switch req.Type {
	case streamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Error("error parsing streamlocal payload")
			return false, []byte(err.Error())
		}

		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.SocketPath, 0) {
			return false, []byte("port forwarding is disabled")
		}

		sessionID := reqPayload.SocketPath
		logger := h.logger.WithFields(log.Fields{"session-id": sessionID})

		// validate session exists
		if _, err := h.sessionStore.Get(sessionID); err != nil {
			return false, []byte(err.Error())
		}

		ln, err := h.sessionDialListener.Listen(sessionID)
		if err != nil {
			logger.WithError(err).Error("error listening socketing")
			return false, []byte(err.Error())
		}

		h.trackListener(sessionID, ln)

		var g run.Group
		{
			g.Add(func() error {
				<-ctx.Done()
				return ctx.Err()
			}, func(err error) {
				h.closeListener(sessionID)
			})
		}
		{
			g.Add(func() error {
				return h.listen(ctx, ln, sessionID, logger)
			}, func(err error) {
				h.closeListener(sessionID)
			})
		}

		go func(sessionID string) {
			if err := g.Run(); err != nil {
				h.logger.WithError(err).WithField("session-id", sessionID).Debug("error handling ssh session")
			}
		}(sessionID)

		return true, nil
	case cancelStreamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Error("error parsing steamlocal payload")
			return false, []byte(err.Error())
		}

		sessionID := reqPayload.SocketPath
		h.closeListener(sessionID)

		return true, nil

	default:
		return false, nil
	}
}

func (h *streamlocalForwardHandler) trackListener(sessionID string, ln net.Listener) {
	h.Lock()
	defer h.Unlock()
	h.forwards[sessionID] = ln
}

func (h *streamlocalForwardHandler) closeListener(sessionID string) {
	h.Lock()
	defer h.Unlock()

	ln, ok := h.forwards[sessionID]
	if ok {
		_ = ln.Close()
	}

	delete(h.forwards, sessionID)

	_ = h.sessionStore.Delete(sessionID)
}
