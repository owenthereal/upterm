package command

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/utils"
)

// statusLookupTimeout bounds ~?'s lookup, the record and the daemon together:
// the lines are wanted now, and a daemon that doesn't answer within it is
// reported as not answering rather than waited for.
const statusLookupTimeout = time.Second

// statusGuestRows is how many guest rows ~? lists before it counts the rest
// and points at upterm session info for them.
const statusGuestRows = 3

// statusSource is what ~? reports on: the session's name, the launch this
// terminal is attached to and the admin socket it answers at; and the keys
// this terminal offers, its escape character and whether ~^Z suspends it.
type statusSource struct {
	Name, LaunchID, AdminSocket string
	Escape                      byte
	Suspend                     bool
}

// statusView is what statusLines gathered; renderStatus turns it into ~?'s
// lines.
type statusView struct {
	Name string
	// Unavailable: the record or the daemon didn't answer for this launch
	// within the bound, so nothing is said about the session at all.
	Unavailable  bool
	Guests       []string // client rows, already redacted
	RelayUp      bool
	CanReconnect bool // the relay is down and being redialled
	LostAt       time.Time
	NextAt       time.Time
	Reason       string
	Join         string // how guests join; empty when it isn't worth showing
}

// statusLines is ~?'s text: the session's status from its record (the relay)
// and its daemon (the guests, and how to join), then the keys. The whole
// lookup is bounded by statusLookupTimeout; past it, or when either source
// doesn't answer for the launch this terminal is attached to, the session's
// status is unavailable and only the keys follow. Nothing is guessed: a
// daemon that doesn't answer is not zero guests, and a record that can't be
// read is not a healthy relay.
//
// Why it is unavailable goes to logger, at debug level and bounded, with the
// session's name: the lines say only that it is. A nil logger logs nothing.
func statusLines(ctx context.Context, src statusSource, logger *slog.Logger) []string {
	ctx, cancel := context.WithTimeout(ctx, statusLookupTimeout)
	defer cancel()
	// On a goroutine of its own, so the bound holds whatever a step does with
	// ctx: a record on a filesystem that has stopped answering honours none.
	// The reason is logged there, before the view is handed over, so a lookup
	// the bound gave up on still says why once it ends.
	found := make(chan statusView, 1)
	go func() {
		v, why := lookupStatus(ctx, src)
		if why != nil {
			logStatusUnavailable(logger, src.Name, why)
		}
		found <- v
	}()
	v := statusView{Name: src.Name, Unavailable: true}
	select {
	case v = <-found:
	case <-ctx.Done():
		logStatusUnavailable(logger, src.Name, fmt.Errorf("no answer within %s", statusLookupTimeout))
	}
	return renderStatus(v, src.Escape, src.Suspend)
}

// logStatusUnavailable logs why ~? found the session's status unavailable.
func logStatusUnavailable(logger *slog.Logger, name string, why error) {
	logging.LogWithin(logger, slog.LevelDebug, logging.LogBound, "session status unavailable", "session", name, "reason", why)
}

// lookupStatus reads src's session from its record and its daemon, each
// checked against the launch this terminal is attached to: the name can pass
// to another launch while it is, and that one is not this terminal's session.
// The view is unavailable whenever the error, which says why, is not nil.
func lookupStatus(ctx context.Context, src statusSource) (statusView, error) {
	unavailable := statusView{Name: src.Name, Unavailable: true}
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), src.Name)
	switch {
	case err != nil:
		return unavailable, fmt.Errorf("reading the session's record: %w", err)
	case rec == nil:
		return unavailable, errors.New("no record of the session")
	case !held:
		return unavailable, errors.New("the session has ended")
	case src.LaunchID == "" || rec.LaunchID != src.LaunchID:
		return unavailable, errors.New("the record is another launch's")
	}
	sess, err := adminSession(ctx, src.AdminSocket)
	if err != nil {
		return unavailable, fmt.Errorf("asking the daemon: %w", err)
	}
	if !sameLaunch(rec, sess) {
		return unavailable, errors.New("the daemon answered for another launch")
	}

	v := statusView{Name: src.Name}
	switch rec.Status {
	case sessiondir.StatusReady:
		v.RelayUp = true
	case sessiondir.StatusReconnecting:
		v.CanReconnect = true
		v.LostAt, v.NextAt, v.Reason = rec.TunnelLostAt, rec.NextAttemptAt, rec.TunnelReason
	case sessiondir.StatusDisconnected:
		// Down for good: a relay that can't reconnect.
	default:
		// Starting or ending: neither says what the relay is doing for
		// guests, and a status this upterm doesn't know isn't guessed at.
		return unavailable, fmt.Errorf("the record's status is %q", rec.Status)
	}
	for _, c := range sess.GetConnectedClients() {
		// The session's own terminals are not guests, as countGuests has it.
		if c.GetKind() != api.Client_HOST {
			v.Guests = append(v.Guests, clientDesc(c))
		}
	}
	// The connect string only while it is one guests can act on, now or once
	// the relay is back: a disconnected session's cannot connect.
	if joinable(rec.Status) {
		if detail, err := buildSessionDetail(sess); err == nil {
			v.Join = detail.JoinCommand
			if v.Join == "" {
				// A relay join can't take: the ssh line reaches it.
				v.Join = detail.SSHCommand
			}
		}
	}
	return v, nil
}

// adminSession asks the daemon at socket for its session, over a connection
// closed afterwards: the terminal asking lives on, and asks again.
func adminSession(ctx context.Context, socket string) (*api.GetSessionResponse, error) {
	if socket == "" {
		return nil, errors.New("no admin socket")
	}
	conn, err := host.AdminConn(socket)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return api.NewAdminServiceClient(conn).GetSession(ctx, &api.GetSessionRequest{})
}

// renderStatus is v as ~?'s lines, each without its line ending, the keys
// last. escape and suspend are this terminal's.
func renderStatus(v statusView, escape byte, suspend bool) []string {
	keys := keysLine(escape, suspend)
	if v.Unavailable {
		return []string{"upterm: session status unavailable", keys}
	}

	head := fmt.Sprintf("upterm: session %s: %s; ", v.Name, guestCount(len(v.Guests)))
	var lines []string
	switch {
	case v.RelayUp:
		lines = append(lines, head+"the relay is connected")
	case v.CanReconnect:
		line := head + "the relay is disconnected"
		if !v.LostAt.IsZero() {
			line += " since " + tui.ClockTime(v.LostAt)
		}
		if v.Reason != "" {
			line += " (" + v.Reason + ")"
		}
		// The next try is when upterm tries, not when guests are back. One
		// that is not ahead of the clock is under way, or was due while the
		// machine slept: saying when it was would promise nothing.
		next := "upterm: guests can't join while the relay is disconnected"
		if wait := time.Until(v.NextAt); !v.NextAt.IsZero() && wait > 0 {
			next += fmt.Sprintf("; next try in %d s", int(math.Ceil(wait.Seconds())))
		}
		lines = append(lines, line, next)
	default:
		lines = append(lines, head+"the relay connection is lost, and this relay can't reconnect; restart the session to share it again")
	}

	for i, g := range v.Guests {
		if i == statusGuestRows {
			lines = append(lines, fmt.Sprintf("upterm:   and %d more: upterm session info %s", len(v.Guests)-statusGuestRows, v.Name))
			break
		}
		lines = append(lines, "upterm:   "+g)
	}
	if v.Join != "" {
		lines = append(lines, "upterm: guests join with: "+v.Join)
	}
	return append(lines, keys)
}

// guestCount is n guests, in words.
func guestCount(n int) string {
	if n == 1 {
		return "1 guest"
	}
	return fmt.Sprintf("%d guests", n)
}

// keysLine lists the keys that work in this terminal, with its own escape
// character, and ~^Z only where this terminal can be suspended: not on
// Windows, and not without job control.
func keysLine(escape byte, suspend bool) string {
	e := string(escape)
	keys := []string{e + ". detach"}
	if suspend {
		keys = append(keys, e+"^Z suspend")
	}
	keys = append(keys, e+e+" send "+e, e+"? this list")
	return "upterm: keys: " + strings.Join(keys, "  ")
}
