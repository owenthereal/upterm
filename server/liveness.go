package server

import (
	"context"
	"log/slog"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// hostLiveness paces the pings that find a host connection which has gone
// silent: one every interval, and the connection is closed when a ping goes
// unanswered for bound. A host that vanishes without closing its connection
// is otherwise noticed only by TCP: minutes at best, and never while a proxy
// or a stuck peer holds the connection open. Its registration keeps guests
// from reaching the session in the meantime.
type hostLiveness struct {
	interval, bound time.Duration
}

var defaultHostLiveness = hostLiveness{15 * time.Second, 15 * time.Second}

// orDefault returns l with any field left zero taken from the default. A zero
// interval would otherwise ping in a tight loop.
func (l hostLiveness) orDefault() hostLiveness {
	if l.interval <= 0 {
		l.interval = defaultHostLiveness.interval
	}
	if l.bound <= 0 {
		l.bound = defaultHostLiveness.bound
	}
	return l
}

// pingHost sends conn's peer a keepalive every l.interval, and closes conn
// when one goes unanswered for l.bound, so that the connection's owner cleans
// up after a host that is gone. It returns when conn is closed or ctx ends.
//
// Any reply counts as an answer: a client that doesn't know the request
// refuses it, and a refusal is still a peer that is there.
func pingHost(ctx context.Context, conn gossh.Conn, l hostLiveness, logger *slog.Logger) {
	for {
		if !sleep(ctx, l.interval) {
			return
		}
		// SendRequest blocks until a reply or the end of the connection, so it
		// can't be given a deadline. Closing conn, which is what an unanswered
		// ping leads to, is what lets it return; the channel is buffered so it
		// can hand back its result with no one left to take it.
		done := make(chan error, 1)
		go func() {
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		timeout := time.NewTimer(l.bound)
		select {
		case err := <-done:
			timeout.Stop()
			if err != nil { // the connection is gone
				return
			}
		case <-timeout.C:
			logger.Warn("closing a host connection that stopped answering", "bound", l.bound)
			_ = conn.Close()
			return
		case <-ctx.Done():
			timeout.Stop()
			return
		}
	}
}
