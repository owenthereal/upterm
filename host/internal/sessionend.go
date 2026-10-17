package internal

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"syscall"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// ShutdownSignal is a shutdown cause that carries the signal the daemon
// received. host's hostSignalError is one.
type ShutdownSignal interface{ ShutdownSignal() syscall.Signal }

// shutdownKind is why a session is being shut down, if it is.
type shutdownKind int

const (
	shutdownNone shutdownKind = iota
	shutdownJoinTimeout
	shutdownStopped
	shutdownSignaled
	shutdownCanceled
)

// overrides reports whether this is a shutdown whose status, 1, every client
// is sent in place of what its command returned while it was torn down: a
// stop, a signal or a cancellation. A join timeout is not one; it keeps its 0.
func (k shutdownKind) overrides() bool {
	return k == shutdownStopped || k == shutdownSignaled || k == shutdownCanceled
}

// end is the session-end request a local client is sent for this shutdown,
// given the signal for one that was signalled; with no shutdown, the session
// ended as its command did.
func (k shutdownKind) end(sig syscall.Signal) upterm.SessionEnd {
	switch k {
	case shutdownJoinTimeout:
		return upterm.SessionEnd{Cause: upterm.CauseJoinTimeout}
	case shutdownStopped:
		return upterm.SessionEnd{Cause: upterm.CauseStopped}
	case shutdownSignaled:
		return upterm.SessionEnd{Cause: upterm.CauseSignaled, Signal: endSignal(sig)}
	case shutdownCanceled:
		return upterm.SessionEnd{Cause: upterm.CauseCanceled}
	}
	return upterm.SessionEnd{Cause: upterm.CauseExited}
}

// endSignal is sig as a session-end request names it: as SSH spells it,
// without "SIG" ("TERM"), or, for a signal with no name -- a real-time one on
// Linux -- its number ("40"), so that a terminal can still say which signal
// it was, as the session's record does.
func endSignal(sig syscall.Signal) string {
	if name := sshSignalName(sig); name != "" {
		return name
	}
	return strconv.Itoa(int(sig))
}

// shutdownCause classifies the session's shutdown cause: the one published
// into o, or, with none published but stopCtx done -- a plain cancellation --
// context.Cause(stopCtx). It asks what the cause wraps rather than what it is:
// host's winner for a stop is the signal actor's join of its context's error
// and cause, and for a signal its own error type. A cause that is none of the
// named ones is a cancellation.
func shutdownCause(o *endOrder, stopCtx context.Context) (shutdownKind, syscall.Signal) {
	cause := o.published()
	if cause == nil && stopCtx != nil && stopCtx.Err() != nil {
		cause = context.Cause(stopCtx)
	}
	if cause == nil {
		return shutdownNone, 0
	}
	var sig ShutdownSignal
	switch {
	case errors.Is(cause, ErrJoinTimeout):
		return shutdownJoinTimeout, 0
	case errors.Is(cause, ErrSessionStopped):
		return shutdownStopped, 0
	case errors.As(cause, &sig):
		return shutdownSignaled, sig.ShutdownSignal()
	}
	return shutdownCanceled, 0
}

// endOrder holds, per session, the published shutdown cause, and orders it
// against each command's end. One mutex covers both, so that "ended before
// the shutdown" means the end was recorded before the cause was: neither the
// branch a wait actor's select takes, which can find both ready, nor the
// teardown's first hangup, which a command can beat by exiting on its own
// after the stop, can say that.
type endOrder struct {
	mu    sync.Mutex
	cause error // the winning cause once published; nil before
	// session is the session's context. With no cause published, its
	// cancellation is the shutdown: a plain cancellation, which is what
	// stopping a server nobody published a cause to amounts to.
	session context.Context

	// onCommandEnded, if set, is called each time a command's end has been
	// recorded. Nil in production; a test uses it to know the waiter has.
	onCommandEnded func()
}

// watch tells o the session's context. ServeWithContext calls it before
// anything runs.
func (o *endOrder) watch(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.session = ctx
}

// publish records cause as the session's shutdown cause. The first one
// published stands, and a nil one publishes nothing.
func (o *endOrder) publish(cause error) {
	if cause == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cause == nil {
		o.cause = cause
	}
}

// published returns the published cause, or nil. A nil order -- a test's
// handler -- has none.
func (o *endOrder) published() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cause
}

// commandEnded is called by a command's waiter the moment Wait returns,
// before it closes what says the command has gone; it reports whether a
// shutdown had been published by then, or, with none published, the
// session's context cancelled.
func (o *endOrder) commandEnded() (afterShutdown bool) {
	if o == nil {
		return false
	}
	o.mu.Lock()
	afterShutdown = o.cause != nil || (o.session != nil && o.session.Err() != nil)
	o.mu.Unlock()
	if o.onCommandEnded != nil {
		o.onCommandEnded()
	}
	return afterShutdown
}

// PublishShutdown records cause as the session's shutdown cause. host calls
// it, synchronously, with the winning cause just before it cancels the
// server with that same cause: a handler that ends between the two still
// sees it, and a command that ends between them ended after it.
func (s *Server) PublishShutdown(cause error) {
	s.order.publish(cause)
}

// hostEndBound is how long a session that is ending waits for the clients on
// its host door to be sent its end: the wait for each one's reply to the
// session-end request, the status's flush, and a margin.
const hostEndBound = upterm.SessionEndReplyBound + guestFlushTimeout + time.Second

// sendSessionEnd tells a local client why the session ended, ahead of its
// exit status: a global request it answers before the status is sent, so that
// it has the cause whatever the status, 0 included. The reply is waited for
// within upterm.SessionEndReplyBound and no longer -- a client that is
// suspended still gets its status after that, and one from before the request
// refuses it at once -- and a reply that comes later is abandoned, not waited
// for. A nil conn, a test's fake session's, is sent nothing.
func sendSessionEnd(conn *ssh.ServerConn, end upterm.SessionEnd) {
	if conn == nil {
		return
	}
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		_, _, _ = conn.SendRequest(upterm.SessionEndRequestType, true, ssh.Marshal(&end))
	}()
	timer := time.NewTimer(upterm.SessionEndReplyBound)
	defer timer.Stop()
	select {
	case <-replied:
	case <-timer.C:
	}
}

// endedOnItsOwn reports whether r is the outcome of a command that ended on
// its own -- exited, or was killed by a signal -- before any shutdown.
func (r CommandResult) endedOnItsOwn() bool {
	return (r.Exited || r.SignalNumber != nil) && !r.EndedAfterShutdown
}

// commandEnd is the session-end request for a session that ended because its
// command did.
func commandEnd(r CommandResult) upterm.SessionEnd {
	switch {
	case r.Exited:
		return upterm.SessionEnd{Cause: upterm.CauseExited}
	case r.SignalNumber != nil:
		return upterm.SessionEnd{Cause: upterm.CauseSignaled, Signal: endSignal(syscall.Signal(*r.SignalNumber))}
	}
	// No outcome of its own to tell -- it never started, or its end was
	// never confirmed -- so it is the reason upterm didn't record.
	return upterm.SessionEnd{Cause: upterm.CauseCanceled}
}

// endingCause is how the session's end looks to a handler ending now: its
// shutdown cause (see shutdownCause), and the shared command's outcome once
// it has one. A shared command that ended on its own before any shutdown is
// what the session ended for. A cause published after it, and whatever then
// tore down a forced command, changed nothing -- the session was ending
// already -- so the cause is then none.
func (h *sessionHandler) endingCause() (kind shutdownKind, sig syscall.Signal, res CommandResult, commandDone bool) {
	kind, sig = shutdownCause(h.order, h.stopCtx)
	if h.cmdDone != nil {
		select {
		case <-h.cmdDone:
			commandDone = true
		default:
		}
	}
	if commandDone && h.commandResult != nil {
		res = h.commandResult()
		if res.endedOnItsOwn() {
			kind, sig = shutdownNone, 0
		}
	}
	return kind, sig, res, commandDone
}

// exitWith sends the client its status, and a client on the host door, first,
// why the session ended. Guests are never told: the request is for the
// session's own terminals.
func (h *sessionHandler) exitWith(sess gssh.Session, end upterm.SessionEnd, code int) {
	if h.kind == kindHost {
		sendSessionEnd(serverConn(sess), end)
	}
	_ = sess.Exit(code)
}

// exitLate ends the session of a client that arrived as the session was
// already ending: 1 if it was stopped, signalled or cancelled, as every other
// client is sent then, and a local client is told why first. Otherwise 0, as
// such a client always has been, rather than the status of a command it never
// saw, and no cause: an exit would say the 0 was the command's, which it
// isn't, and a join timeout's is told by a notice in the stream that this
// client never gets, so the plain status says all there is to say.
func (h *sessionHandler) exitLate(sess gssh.Session) {
	kind, sig, _, _ := h.endingCause()
	if !kind.overrides() {
		_ = sess.Exit(0)
		return
	}
	h.exitWith(sess, kind.end(sig), 1)
}
