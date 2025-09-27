package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/charmbracelet/ssh"
	"github.com/oklog/run"
	"log/slog"
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

// isExpectedShutdownError returns true if the error is expected during normal session shutdown
func isExpectedShutdownError(err error) bool {
	if err == nil {
		return false
	}

	// Context cancellation is normal during shutdown
	if errors.Is(err, context.Canceled) {
		return true
	}

	// EOF and connection closed errors are normal during shutdown
	if errors.Is(err, io.EOF) {
		return true
	}

	errStr := err.Error()
	// Common shutdown-related error messages
	shutdownMessages := []string{
		"closed",
		"connection reset",
		"broken pipe",
		"use of closed network connection",
	}

	for _, msg := range shutdownMessages {
		if strings.Contains(errStr, msg) {
			return true
		}
	}

	return false
}

func newStreamlocalForwardHandler(
	sessionManager *SessionManager,
	sessionDialListener SessionDialListener,
	logger *slog.Logger,
) *streamlocalForwardHandler {
	return &streamlocalForwardHandler{
		sessionManager:      sessionManager,
		sessionDialListener: sessionDialListener,
		forwards:            make(map[string]net.Listener),
		logger:              logger,
	}
}

type streamlocalForwardHandler struct {
	sessionManager      *SessionManager
	sessionDialListener SessionDialListener
	forwards            map[string]net.Listener
	logger              *slog.Logger
	sync.Mutex
}

func (h *streamlocalForwardHandler) listen(ctx ssh.Context, ln net.Listener, sessionID string, logger *slog.Logger) error {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}

		go h.handleConnection(ctx, conn, c, sessionID, logger)
	}
}

func (h *streamlocalForwardHandler) handleConnection(ctx ssh.Context, conn *gossh.ServerConn, localConn net.Conn, sessionID string, logger *slog.Logger) {
	defer func() {
		if err := localConn.Close(); err != nil {
			logger.Debug("error closing local connection", "error", err)
		}
	}()

	payload := gossh.Marshal(&forwardedStreamlocalPayload{
		SocketPath: sessionID,
	})

	ch, reqs, err := conn.OpenChannel(forwardedStreamlocalChannelType, payload)
	if err != nil {
		logger.Error("error opening channel", "error", err)
		return
	}
	defer func() {
		if err := ch.Close(); err != nil {
			logger.Debug("error closing SSH channel", "error", err)
		}
	}()

	var g run.Group

	// Context cancellation handler
	{
		g.Add(func() error {
			<-ctx.Done()
			return ctx.Err()
		}, func(err error) {
			// Context cancelled, close all connections
		})
	}

	// SSH request handler
	{
		g.Add(func() error {
			gossh.DiscardRequests(reqs)
			return nil
		}, func(err error) {
			// Requests handler stopped
		})
	}

	// Copy from local to SSH channel
	{
		g.Add(func() error {
			_, err := io.Copy(ch, localConn)
			return err
		}, func(err error) {
			// Copy stopped
		})
	}

	// Copy from SSH channel to local
	{
		g.Add(func() error {
			_, err := io.Copy(localConn, ch)
			return err
		}, func(err error) {
			// Copy stopped
		})
	}

	if err := g.Run(); err != nil && err != context.Canceled {
		logger.Error("error handling connection", "error", err)
	}
}

func (h *streamlocalForwardHandler) Handler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	switch req.Type {
	case streamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.Error("error parsing streamlocal payload", "error", err)
			return false, []byte(err.Error())
		}

		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.SocketPath, 0) {
			return false, []byte("port forwarding is disabled")
		}

		sessionID := reqPayload.SocketPath
		logger := h.logger.With("session-id", sessionID)

		// validate session exists
		if _, err := h.sessionManager.GetSession(sessionID); err != nil {
			return false, []byte(err.Error())
		}

		ln, err := h.sessionDialListener.Listen(sessionID)
		if err != nil {
			logger.Error("error listening socket", "error", err)
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
				// Log expected shutdown errors at debug level, critical errors at error level
				if isExpectedShutdownError(err) {
					h.logger.Debug("ssh session ended", "session-id", sessionID)
				} else {
					h.logger.Error("error handling ssh session", "error", err, "session-id", sessionID)
				}
			}
		}(sessionID)

		return true, nil
	case cancelStreamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.Error("error parsing streamlocal payload", "error", err)
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

	logger := h.logger.With("session-id", sessionID)

	ln, ok := h.forwards[sessionID]
	if !ok {
		// Already closed
		return
	}

	if err := ln.Close(); err != nil {
		logger.Error("error closing listener", "error", err)
	} else {
		logger.Debug("closed listener")
	}

	delete(h.forwards, sessionID)

	if err := h.sessionManager.DeleteSession(sessionID); err != nil {
		logger.Error("error deleting session", "error", err)
	}
}
