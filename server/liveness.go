package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
	gossh "golang.org/x/crypto/ssh"
)

// pingHost closes conn once its peer has gone silent, so that the connection's
// owner cleans up after a host that is gone. A host that vanishes without
// closing its connection is otherwise noticed only by TCP: minutes at best, and
// never while a proxy or a stuck peer holds the connection open. Its
// registration keeps guests from reaching the session in the meantime. It
// returns when conn is closed or ctx ends.
//
// A host is judged by whether bytes keep arriving, not by whether a ping was
// answered in time. x/crypto answers a request only after the output queued
// ahead of it, so on a slow uplink a live host's reply can trail by longer than
// any bound that is also short enough to notice a dead one, while its output
// arrives the whole time. The ping is only a nudge for a host that has gone
// quiet, and any reply counts: a client that doesn't know the request refuses
// it, and a refusal is still a peer that is there.
//
// lastRead must advance with the host's own bytes: the proxy's host-facing
// connection when there is a proxy. conn is not that connection then, and the
// proxy writes to it on its own account, so its reads would keep a silent host
// alive. A lastRead that doesn't advance with the host's reads at all would
// read a live host as silent, and close it.
func pingHost(ctx context.Context, conn gossh.Conn, lastRead func() time.Time, t liveness.Timing, logger *slog.Logger) {
	liveness.Watch(ctx, t, lastRead,
		func() error {
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			return err
		},
		func(err error) {
			// Only silence is worth a log line: a failed probe is a connection
			// that has already gone, and closing it is only to be sure.
			if errors.Is(err, liveness.ErrSilent) {
				logger.Warn("closing a host connection that went silent", "error", err)
			}
			_ = conn.Close()
		})
}

// hostActivity records, for each host this node's SSH proxy is serving, the
// proxy's own connection from that host, so that the node's sshd can tell
// whether the host is still sending.
//
// The sshd can't tell from its own connection. That one runs from the proxy to
// the sshd, and the proxy writes to it on its own account: it rejects every
// guest channel open beyond maxSSHConcurrentChannelOpens itself, and x/crypto
// answers a channel close without asking anyone. A silent host whose guests
// keep retrying would keep that connection busy forever, and its dead
// registration with it. The proxy's connection from the host carries only what
// the host sent.
//
// A host's two connections share one name: the proxy mints the SSH session ID of
// the host's connection into the certificate it presents to the sshd, and the
// sshd keeps it as the connection's downstream session ID.
//
// A nil *hostActivity is valid and records nothing, for a proxy or an sshd that
// runs without the other.
type hostActivity struct {
	mu    sync.Mutex
	conns map[string]*liveness.Conn
}

func newHostActivity() *hostActivity {
	return &hostActivity{conns: make(map[string]*liveness.Conn)}
}

// track records c as the host-facing connection of the host whose downstream SSH
// session ID is sessionID, until the returned func is called.
func (h *hostActivity) track(sessionID []byte, c *liveness.Conn) (untrack func()) {
	if h == nil {
		return func() {}
	}
	key := string(sessionID)
	h.mu.Lock()
	h.conns[key] = c
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		// Only its own entry: an ID names one connection, but removing another's
		// would blind the sshd to a host that is still there.
		if h.conns[key] == c {
			delete(h.conns, key)
		}
	}
}

// lookup returns the host-facing connection of the host whose downstream SSH
// session ID is sessionID, or nil if none is recorded.
func (h *hostActivity) lookup(sessionID []byte) *liveness.Conn {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[string(sessionID)]
}
