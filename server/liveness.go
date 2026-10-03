package server

import (
	"context"
	"errors"
	"log/slog"
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
// lastRead must advance with the reads of the connection under the SSH
// transport. One that doesn't would read a live host as silent, and close it.
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
