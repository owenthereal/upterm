package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"charm.land/ssh"
	"github.com/oklog/run"
	gossh "golang.org/x/crypto/ssh"
	"log/slog"
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
	sessions *localSessions,
	logger *slog.Logger,
) *streamlocalForwardHandler {
	return &streamlocalForwardHandler{
		sessionManager:      sessionManager,
		sessionDialListener: sessionDialListener,
		sessions:            sessions,
		forwards:            make(map[string]forward),
		logger:              logger,
	}
}

type streamlocalForwardHandler struct {
	sessionManager      *SessionManager
	sessionDialListener SessionDialListener
	sessions            *localSessions
	forwards            map[string]forward // by session ID
	logger              *slog.Logger
	sync.Mutex
}

// forward is a registration's session socket listener. The socket is named by
// the session ID, which a newer registration of the same ID binds after a
// takeover, so the listener is kept with the registration that bound it.
type forward struct {
	reg *Registration
	ln  net.Listener
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

	// Whichever side finishes first, close both. Without this, a guest
	// disconnecting leaves the channel to the host open until the host next
	// writes output, so the host cannot tell that the guest has left.
	closeBoth := func(error) {
		_ = localConn.Close()
		_ = ch.Close()
	}

	var g run.Group

	// Context cancellation handler
	{
		g.Add(func() error {
			<-ctx.Done()
			return ctx.Err()
		}, closeBoth)
	}

	// SSH request handler
	{
		g.Add(func() error {
			gossh.DiscardRequests(reqs)
			return nil
		}, closeBoth)
	}

	// Copy from local to SSH channel
	{
		g.Add(func() error {
			_, err := io.Copy(ch, localConn)
			return err
		}, closeBoth)
	}

	// Copy from SSH channel to local
	{
		g.Add(func() error {
			_, err := io.Copy(localConn, ch)
			return err
		}, closeBoth)
	}

	if err := g.Run(); err != nil && err != context.Canceled && !isExpectedShutdownError(err) {
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

		// Only the connection that registered a session may open its tunnel,
		// and only while that registration is still the one this node serves.
		// The store is shared across nodes, so existence alone proves nothing
		// about who is asking; an ended registration whose store release
		// failed must not be reopened uncounted; and a replaced one must not
		// take the socket from its successor.
		reg := ownedRegistration(ctx, sessionID)
		if reg == nil {
			logger.Warn("rejected forward for session not created on this connection")
			return false, []byte("session not created on this connection")
		}
		if !h.sessions.active(reg) {
			logger.Warn("rejected forward for ended session")
			return false, []byte("session has ended")
		}
		if _, err := h.sessionManager.GetSession(sessionID); err != nil {
			return false, []byte(err.Error())
		}

		ln, err := h.bind(reg)
		if errors.Is(err, errForwardEnded) {
			logger.Warn("rejected forward for ended session")
			return false, []byte("session has ended")
		}
		if err != nil {
			logger.Error("error listening socket", "error", err)
			return false, []byte(err.Error())
		}

		var g run.Group
		{
			g.Add(func() error {
				<-ctx.Done()
				return ctx.Err()
			}, func(err error) {
				h.closeListener(reg)
			})
		}
		{
			g.Add(func() error {
				return h.listen(ctx, ln, sessionID, logger)
			}, func(err error) {
				h.closeListener(reg)
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
		reg := ownedRegistration(ctx, sessionID)
		if reg == nil {
			h.logger.Warn("rejected cancel for session not created on this connection", "session-id", sessionID)
			return false, []byte("session not created on this connection")
		}
		h.closeListener(reg)

		return true, nil

	default:
		return false, nil
	}
}

// errForwardEnded refuses a forward whose registration ended, or was replaced,
// before it could bind.
var errForwardEnded = errors.New("session has ended")

// bind listens on reg's session socket and records the listener as reg's,
// provided reg is still the registration this node serves. The check, the bind
// and the record all happen under the handler lock, which a takeover's
// closeListener takes too: a forward that began before the takeover either
// binds before the old listener is closed, and is closed with it, or finds its
// registration replaced. It can't bind after that close and take the socket's
// name from the successor.
//
// A listener still held by a registration this node no longer serves is
// closed first, under the same lock. Takeovers can overlap: when a later one
// overtakes a takeover that hasn't yet closed the listener it replaced, that
// listener would otherwise keep the socket's name from the registration this
// node now serves. A listener of the registration this node serves is never
// closed here, so a second forward from it still fails.
func (h *streamlocalForwardHandler) bind(reg *Registration) (net.Listener, error) {
	h.Lock()
	if !h.sessions.active(reg) {
		h.Unlock()
		return nil, errForwardEnded
	}
	var evicted *Registration
	if fwd, ok := h.forwards[reg.ID()]; ok && !h.sessions.active(fwd.reg) {
		if err := fwd.ln.Close(); err != nil {
			h.logger.Error("error closing a replaced registration's listener", "error", err, "session-id", reg.ID())
		}
		delete(h.forwards, reg.ID())
		evicted = fwd.reg
	}
	ln, err := h.sessionDialListener.Listen(reg.ID())
	if err == nil {
		h.forwards[reg.ID()] = forward{reg: reg, ln: ln}
	}
	h.Unlock()

	// Outside the lock: ending releases the store entry, and a Consul call can
	// be slow. The release is conditional, so it leaves reg's entry alone.
	if evicted != nil {
		h.sessions.end(evicted)
	}
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func (h *streamlocalForwardHandler) trackListener(reg *Registration, ln net.Listener) {
	h.Lock()
	defer h.Unlock()
	h.forwards[reg.ID()] = forward{reg: reg, ln: ln}
}

// closeListener closes reg's listener and ends reg. A listener for reg's ID
// that another registration bound is left alone, so a replaced registration's
// late cleanup can't close its successor's socket.
func (h *streamlocalForwardHandler) closeListener(reg *Registration) {
	logger := h.logger.With("session-id", reg.ID())

	h.Lock()
	fwd, ok := h.forwards[reg.ID()]
	if !ok || !fwd.reg.Same(reg) {
		// Already closed, or not reg's
		h.Unlock()
		return
	}
	if err := fwd.ln.Close(); err != nil {
		logger.Error("error closing listener", "error", err)
	} else {
		logger.Debug("closed listener")
	}
	delete(h.forwards, reg.ID())
	h.Unlock()

	// Outside the lock: ending releases the store entry, and a Consul call
	// can be slow.
	h.sessions.end(reg)
}
