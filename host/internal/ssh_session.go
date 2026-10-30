package internal

import (
	"context"
	"sync"
	"time"

	gssh "charm.land/ssh"
	"golang.org/x/crypto/ssh"
)

// rawSessionHandler keeps the SSH library's PTY request and window handling,
// but sends output directly to the channel. Upterm already owns a real PTY;
// the library's emulated PTY writer would turn LF into CRLF a second time,
// breaking cursor positioning in programs such as GNU Screen (#288, #278).
func rawSessionHandler(srv *gssh.Server, conn *ssh.ServerConn, newChan ssh.NewChannel, ctx gssh.Context) {
	channel := &sessionChannel{NewChannel: newChan}
	// DefaultSessionHandler runs the channel's request loop and returns when
	// it ends, which x/crypto makes happen only when the far side's CLOSE
	// arrives or the connection goes: the moment the channel is closed from
	// the far side, for a session with a pty or without one.
	closed := make(chan struct{})
	defer close(closed)
	// These are the fields DefaultSessionHandler reads in charm.land/ssh v0.4.3;
	// recheck them when upgrading the dependency. Build this configuration per
	// channel so the captured output cannot leak to another session on the same
	// connection, and do not copy the running server's mutexes.
	// One wrapper belongs to this channel, including during admission. Charm
	// invokes its callback synchronously before launching any handler.
	raw := &rawSession{closed: closed}
	subsystems := make(map[string]gssh.SubsystemHandler, len(srv.SubsystemHandlers))
	for name, handle := range srv.SubsystemHandlers {
		if handle != nil {
			subsystems[name] = func(_ gssh.Session) { handle(raw) }
		}
	}
	sessionServer := &gssh.Server{
		Handler:     func(_ gssh.Session) { srv.Handler(raw) },
		PtyCallback: srv.PtyCallback,
		PtyHandler:  srv.PtyHandler,
		SessionRequestCallback: func(sess gssh.Session, requestType string) bool {
			raw.Session = sess
			raw.channel = channel.channel
			raw.requestType = requestType
			raw.requestReceivedAt = time.Now()
			raw.startWindowChanges()
			return srv.SessionRequestCallback == nil || srv.SessionRequestCallback(raw, requestType)
		},
		SubsystemHandlers: subsystems,
	}
	gssh.DefaultSessionHandler(sessionServer, conn, channel, ctx)
}

// Capture the underlying channel when DefaultSessionHandler accepts it.
type sessionChannel struct {
	ssh.NewChannel
	channel ssh.Channel
}

func (c *sessionChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	channel, requests, err := c.NewChannel.Accept()
	c.channel = channel
	return channel, requests, err
}

type rawSession struct {
	gssh.Session
	channel           ssh.Channel
	requestType       string
	requestReceivedAt time.Time
	// admission is the tracker chosen before acknowledgement, rather than a
	// selection repeated later from the handler's configuration.
	admission   *guestHandlers
	windowsOnce sync.Once
	windowsMu   sync.Mutex
	pty         gssh.Pty
	isPty       bool
	windows     chan gssh.Window
	// closed closes once the channel has been closed from the far side: the
	// close the session's Exit sent has been answered, or the connection has
	// gone.
	closed <-chan struct{}
}

func (s *rawSession) Write(p []byte) (int, error) {
	return s.channel.Write(p)
}

// startWindowChanges runs before admission can start a permission wait. It is
// the only consumer of Charm's window channel; handlers consume the bounded
// mailbox instead, so a slow handler never blocks the SSH request loop/CLOSE.
func (s *rawSession) startWindowChanges() {
	// Called in Charm's request loop, before the handler starts, so this copy
	// cannot race with that loop updating Charm's mutable Pty.Window.
	pty, changes, ok := s.Session.Pty()
	if changes == nil {
		return
	}
	s.windowsOnce.Do(func() {
		s.pty, s.isPty = pty, ok
		s.windows = make(chan gssh.Window, 1)
		go func() {
			defer close(s.windows)
			for window := range changes {
				s.windowsMu.Lock()
				s.pty.Window = window
				s.windowsMu.Unlock()
				select {
				case s.windows <- window:
				default:
					select {
					case <-s.windows:
					default:
					}
					s.windows <- window
				}
			}
		}()
	})
}

func (s *rawSession) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	s.windowsMu.Lock()
	defer s.windowsMu.Unlock()
	return s.pty, s.windows, s.isPty
}

func sessionRequestType(sess gssh.Session) string {
	if raw, ok := sess.(*rawSession); ok {
		return raw.requestType
	}
	return ""
}

func sessionRequestReceivedAt(sess gssh.Session) time.Time {
	if raw, ok := sess.(*rawSession); ok {
		return raw.requestReceivedAt
	}
	return time.Time{}
}

// sessionOperationContext joins host/caller cancellation, transport loss and
// channel CLOSE. Reading EOF on stdin is deliberately unrelated. Callers must
// release the watcher when the operation ends, even on a still-open channel.
func sessionOperationContext(parent context.Context, sess gssh.Session) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stopTransport := context.AfterFunc(sess.Context(), cancel)
	// Observe an already ended session before returning to a caller that may
	// be about to perform its first side effect.
	if sess.Context().Err() != nil {
		cancel()
	}
	select {
	case <-channelClosed(sess):
		cancel()
	default:
	}
	go func() {
		select {
		case <-channelClosed(sess):
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { stopTransport(); cancel() }
}
