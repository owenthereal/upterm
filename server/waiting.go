package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/owenthereal/upterm/internal/termtext"
	gossh "golang.org/x/crypto/ssh"
)

// maxWaiting bounds a waiting screen: it expires at most this long after the
// verdict that opened it.
const maxWaiting = 10 * time.Minute

// waitingGrace is how long past its screen's expiry a waiting guest is given
// to be shown the expired text, before its transport is closed however the
// screen is blocked.
const waitingGrace = 2 * time.Second

// WaitingScreen is a display-only screen for a claimed user, frozen once
// Admit returns it: a binding of the authority's own, to an offer and an
// attempt, of the user the guest typed and the key it proved. Leaving it
// cancels only Await, never the authority's attempt. Await can't authorize a
// target: once it succeeds, the screen shows ApprovedMessage, exits 0 and
// closes, and the guest must connect again. Await is called at most once,
// after the shell starts, and must return when its context ends; the relay
// joins that wait before it releases the connection.
type WaitingScreen struct {
	// OfferID and AttemptID bind the screen to the authority's offer and
	// attempt; each is a UUID.
	OfferID, AttemptID string
	// Address must be the user the guest typed, byte for byte.
	Address string
	// KeyFingerprint must be the fingerprint of the key the guest proved.
	KeyFingerprint string
	// ExpiredMessage is shown once Expires has passed, and ApprovedMessage
	// once Await succeeds. Both are required.
	ExpiredMessage  []byte
	ApprovedMessage []byte
	// Expires is when the screen ends, at most 10 minutes after the verdict;
	// a later one ends it then.
	Expires time.Time
	Await   func(ctx context.Context) (Target, error)
}

// WaitingEnded ends a waiting screen, showing the guest Text as a
// VerdictMessage admission shows its message.
type WaitingEnded struct{ Text []byte }

func (e *WaitingEnded) Error() string { return "the guest's wait ended" }

// validWaiting reports whether w is a screen for the guest that typed user
// and proved the key of fingerprint, at now: bound to an offer and an
// attempt, to that user and key, with both texts and something to wait on,
// and not yet expired.
func validWaiting(w *WaitingScreen, user, fingerprint string, now time.Time) bool {
	return w != nil && w.Await != nil && validUUID(w.OfferID) && validUUID(w.AttemptID) && w.Address == user && w.KeyFingerprint == fingerprint &&
		len(w.ExpiredMessage) > 0 && len(w.ApprovedMessage) > 0 && now.Before(w.Expires)
}

// frozenWaiting is w as the relay keeps it from now: texts of its own, and an
// expiry no later than maxWaiting after now.
func frozenWaiting(w *WaitingScreen, now time.Time) *WaitingScreen {
	frozen := *w
	frozen.ExpiredMessage = bytes.Clone(w.ExpiredMessage)
	frozen.ApprovedMessage = bytes.Clone(w.ApprovedMessage)
	frozen.Expires = minTime(frozen.Expires, now.Add(maxWaiting))
	return &frozen
}

// ptyRequestMsg is a pty-req's payload, RFC 4254 section 6.2.
type ptyRequestMsg struct {
	Term    string
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
	Modes   string
}

// windowChangeMsg is a window-change's payload, RFC 4254 section 6.7.
type windowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

// waitingSession is the one display-only session of a waiting guest.
type waitingSession struct {
	channel  gossh.Channel
	requests <-chan *gossh.Request
}

// awaitResult is what Await returned.
type awaitResult struct {
	err error
}

// serveWaiting shows the admission's message on one shell, discards all
// input and refuses every other channel and request. Every outcome closes the
// screen.
func (p *SSHRouting) serveWaiting(g *guestConn, peer sshPeer, stage time.Duration) error {
	logger := p.logger().With("connection-id", g.guest.ConnectionID)
	waiting := g.admission.Waiting
	// Ending the wait or its stage bound closes the connection.
	ctx, stopWaiting := context.WithCancel(g.ctx)
	_ = context.AfterFunc(ctx, func() { _ = peer.conn.Close() })
	limit := time.AfterFunc(stage, stopWaiting)
	// cutoff closes the guest's transport a grace after the screen expires,
	// whether or not its shell has started, and however the screen is
	// blocked: answering a guest that stopped reading can block it. Until a
	// decision comes in time, the screen ends at the first of the two.
	cutoff := time.AfterFunc(time.Until(waiting.Expires)+waitingGrace, g.forceClose)
	var (
		workers sync.WaitGroup
		session *waitingSession
		// ended is closed once the screen is over, however it ends.
		ended = make(chan struct{})
	)
	defer func() {
		limit.Stop()
		cutoff.Stop()
		stopWaiting()
		close(ended)
		_ = peer.conn.Close()
		workers.Wait()
	}()
	workers.Go(func() {
		for request := range peer.requests {
			replyRequest(request, false)
		}
	})
	sessions := make(chan *waitingSession, 1)
	workers.Go(func() {
		defer close(sessions)
		opened := false
		for channel := range peer.channels {
			if opened || channel.ChannelType() != "session" {
				_ = channel.Reject(gossh.Prohibited, "not permitted")
				continue
			}
			opened = true
			ch, requests, err := channel.Accept()
			if err != nil {
				continue
			}
			// The session's requests reach the screen through forwarded
			// while it lasts. Once it is over, what the guest still sends is
			// discarded, unanswered, until the mux closes the requests: a mux
			// left blocked delivering one never sees its transport close, and
			// the screen's workers would never end.
			forwarded := make(chan *gossh.Request)
			workers.Go(func() {
				defer close(forwarded)
				for request := range requests {
					select {
					case forwarded <- request:
					case <-ended:
						for range requests {
						}
						return
					}
				}
			})
			s := &waitingSession{channel: ch, requests: forwarded}
			// Taken in from the start, so that nothing the guest sends can
			// wait in the connection for later.
			workers.Go(func() { _, _ = io.Copy(io.Discard, ch) })
			workers.Go(func() { _, _ = io.Copy(io.Discard, ch.Stderr()) })
			sessions <- s
		}
	})

	select {
	case <-ctx.Done():
		return nil
	case session = <-sessions:
		if session == nil {
			return nil
		}
	}
	var (
		// terminal is the latest the guest asked for, nil for none.
		terminal *ptyRequestMsg
		decided  chan awaitResult
		expires  <-chan time.Time
	)
	var expiry *time.Timer
	defer func() {
		if expiry != nil {
			expiry.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-expires:
			limit.Reset(stage)
			exitShowing(session.channel, session.requests, session.channel, waiting.ExpiredMessage, terminal != nil)
			return nil
		case decision := <-decided:
			if ctx.Err() != nil {
				return nil
			}
			limit.Reset(stage)
			if !time.Now().Before(waiting.Expires) {
				exitShowing(session.channel, session.requests, session.channel, waiting.ExpiredMessage, terminal != nil)
				return nil
			}
			// Decided in time, the screen ends within the stage.
			cutoff.Stop()
			if decision.err != nil {
				logger.Info("a guest's wait ended", "error", decision.err)
				var ended *WaitingEnded
				var message []byte
				if errors.As(decision.err, &ended) {
					message = ended.Text
				}
				exitShowing(session.channel, session.requests, session.channel, message, terminal != nil)
				return nil
			}
			exitShowingStatus(session.channel, session.requests, session.channel, waiting.ApprovedMessage, terminal != nil, 0)
			return nil
		case request, ok := <-session.requests:
			if !ok {
				return nil
			}
			switch request.Type {
			case "pty-req":
				var m ptyRequestMsg
				if decided != nil || gossh.Unmarshal(request.Payload, &m) != nil {
					replyRequest(request, false)
					continue
				}
				terminal = &m
				replyRequest(request, true)
			case "window-change":
				resize(terminal, request)
			case "shell":
				if decided != nil {
					replyRequest(request, false)
					continue
				}
				replyRequest(request, true)
				if !time.Now().Before(waiting.Expires) {
					exitShowing(session.channel, session.requests, session.channel, waiting.ExpiredMessage, terminal != nil)
					return nil
				}
				_, _ = session.channel.Write(termtext.Sanitize(g.admission.Message, terminal != nil))
				// From now the screen's expiry is the bound.
				limit.Stop()
				expiry = time.NewTimer(time.Until(waiting.Expires))
				expires = expiry.C
				decided = make(chan awaitResult, 1)
				awaitCtx, cancel := context.WithDeadline(ctx, waiting.Expires)
				workers.Go(func() {
					defer cancel()
					_, err := waiting.Await(awaitCtx)
					decided <- awaitResult{err}
				})
			default:
				replyRequest(request, false)
			}
		}
	}
}

// resize applies a waiting session's window-change request to terminal, the
// latest it asked for, and answers it: refused when there is no terminal to
// resize or the request doesn't parse.
func resize(terminal *ptyRequestMsg, request *gossh.Request) {
	var m windowChangeMsg
	if terminal == nil || gossh.Unmarshal(request.Payload, &m) != nil {
		replyRequest(request, false)
		return
	}
	terminal.Columns, terminal.Rows, terminal.Width, terminal.Height = m.Columns, m.Rows, m.Width, m.Height
	replyRequest(request, true)
}
