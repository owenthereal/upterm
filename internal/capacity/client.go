package capacity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"golang.org/x/crypto/ssh"
)

func makeSigner() (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
func guestHandshake(ctx context.Context, raw net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stop() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, reqs), nil
}
func openGuest(ctx context.Context, g *guard, t Target, u *url.URL, s *api.GetSessionResponse, identity ssh.Signer, proxy *tunnelProxy) (*ssh.Client, net.Conn, error) {
	if err := g.session(ctx, s); err != nil {
		return nil, nil, err
	}
	var raw net.Conn
	var err error
	if u.Scheme == "ssh" {
		raw, err = g.connectPermit(ctx, t, u.Host, proxy.takePermit())
	} else {
		copy := *u
		copy.User = url.UserPassword(s.SessionId, base64.URLEncoding.EncodeToString([]byte(s.NodeAddr)))
		raw, err = ws.NewWSConnContext(ctx, &copy, true, proxy.url)
	}
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{User: s.SshUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(identity)}, ClientVersion: upterm.ClientSSHClientVersion, HostKeyCallback: pinnedKey(t)}
	client, err := guestHandshake(ctx, raw, u.Host, cfg)
	return client, raw, err
}

type guest struct {
	queueElapsed     time.Duration
	barriers         map[int]*frameBarrier
	transportLive    bool
	disruption       int
	disruptedAt      time.Time
	lastActiveSeq    int
	lastActiveAt     time.Time
	activeGeneration int
	activeOffered    bool

	canary       bool
	probeSeq     [4]int
	pending      map[string]time.Time
	challenges   map[string]time.Time
	lifetimeStop func() bool
	acks         int64
	ops          sync.Mutex
	inputOps     sync.Mutex
	id           int
	host         *hostRun
	target       Target
	endpoint     *url.URL
	identity     ssh.Signer
	proxy        *tunnelProxy
	client       *ssh.Client
	raw          net.Conn
	channels     []*ssh.Session
	writers      []io.WriteCloser
	done         []chan struct{}
	seq          int
	generation   int
	expected     bool
	mu           sync.Mutex
}

func (q *guest) close() {
	q.ops.Lock()
	defer q.ops.Unlock()
	if q.lifetimeStop != nil {
		q.lifetimeStop()
		q.lifetimeStop = nil
	}
	if q.client != nil {
		_ = q.client.Close()
	}
	if q.raw != nil {
		_ = q.raw.Close()
	}
	q.inputOps.Lock()
	defer q.inputOps.Unlock()
	for _, d := range q.done {
		<-d
	}
	q.done = nil
	q.mu.Lock()
	q.channels = nil
	q.writers = nil
	q.transportLive = false
	q.mu.Unlock()
}
func (q *guest) connect(ctx context.Context, r *runState) error {
	q.ops.Lock()
	defer q.ops.Unlock()
	q.mu.Lock()
	q.challenges = map[string]time.Time{}
	// A baseline belongs to one transport. Reconstructed old B frames must
	// not activate the new reader before its own live Q/B exchange.
	q.barriers = nil
	q.mu.Unlock()
	s, err := q.host.session(ctx)
	if err != nil {
		return err
	}
	if err = r.guard.session(ctx, s); err != nil {
		return err
	}
	timeout := r.guestReadyTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	q.queueElapsed = 0
	queuedAt := time.Now()
	queuectx := ctx
	cancelQueue := func() {}
	q.mu.Lock()
	restoring := q.expected && q.generation > 0
	q.mu.Unlock()
	if restoring && !q.canary {
		queuectx, cancelQueue = context.WithTimeout(ctx, retryQueueLimit)
	}
	permit, err := r.guard.permit(queuectx)
	q.queueElapsed = time.Since(queuedAt)
	cancelQueue()
	if err != nil {
		if ctx.Err() == nil {
			r.rec.event("admission_queue", map[string]any{"role": "guest", "guest": q.id, "retry": true, "queue_ms": float64(q.queueElapsed) / float64(time.Millisecond), "generator_limited": true})
			err = errors.New("generator_admission_backlog")
			r.fail(err)
		}
		return err
	}
	defer permit.release()
	q.proxy.mu.Lock()
	q.proxy.permit = permit
	q.proxy.mu.Unlock()
	r.rec.event("admission_queue", map[string]any{"role": "guest", "guest": q.id, "queue_ms": float64(q.queueElapsed) / float64(time.Millisecond), "generation": q.generation})
	serviceBegan := time.Now()
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, raw, err := openGuest(attempt, r.guard, q.target, q.endpoint, s, q.identity, q.proxy)
	q.mu.Lock()
	q.client = client
	q.raw = raw
	q.transportLive = err == nil
	q.mu.Unlock()
	if err != nil {
		return err
	}
	q.lifetimeStop = context.AfterFunc(ctx, func() { _ = client.Close() })
	stop := context.AfterFunc(attempt, func() { _ = client.Close() })
	defer stop()
	channels := r.cfg.ChannelsPerGuest
	if q.canary {
		channels = 1
	}
	for ch := 0; ch < channels; ch++ {
		session, err := q.client.NewSession()
		if err != nil {
			return err
		}
		q.channels = append(q.channels, session)
		if err = session.RequestPty("dumb", 100, 2048, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			return err
		}
		in, err := session.StdinPipe()
		if err != nil {
			return err
		}
		out, err := session.StdoutPipe()
		if err != nil {
			return err
		}
		session.Stderr = io.Discard
		if err = session.Shell(); err != nil {
			return err
		}
		q.writers = append(q.writers, in)
		stream := q.id*4 + ch
		probeSeq := q.probeSeq[ch]
		q.probeSeq[ch]++
		if ch == 0 {
			probeSeq = q.seq
			q.seq++
		}
		ready := make(chan struct{}, 1)
		helperReady := make(chan struct{}, 1)
		done := make(chan struct{})
		q.done = append(q.done, done)
		go func() {
			defer close(done)
			tracker := sequenceTracker{}
			epochs := map[string]int{}
			live := false
			baseline := time.Time{}
			hostKey := fmt.Sprintf("H:%d", q.host.id)
			err := scanFrames(out, func(o observation) error {
				if o.kind == "B" {
					r.actual(128)
					q.mu.Lock()
					barrier := q.barriers[stream]
					matches := o.id == stream && barrier != nil && o.sent.Equal(barrier.sent)
					q.mu.Unlock()
					if !matches {
						return nil
					}
					if !live {
						tracker[hostKey] = o.seq - 1
						baseline = barrier.sent
						live = true
					} else if last := tracker[hostKey]; last != o.seq-1 {
						return fmt.Errorf("host output suffix missing: host=%d received_through=%d emitted=%d", q.host.id, last, o.seq)
					}
					if barrier.final {
						if err := r.verifyFinalInputs(tracker, q.host.id, baseline); err != nil {
							return err
						}
					}
					barrier.once.Do(func() { close(barrier.done) })
					return nil
				}
				if !live {
					return nil
				}
				if err := r.observe(tracker, epochs, o); err != nil {
					return err
				}
				r.actual(int64(frameLength(o.kind)))
				r.rec.mu.Lock()
				r.rec.summary.ReceivedFrames++
				acknowledged := false
				if o.kind == "I" && o.id == stream {
					sent, ok := q.acknowledge(o)
					acknowledged = ok
					if ok {
						ms := float64(time.Since(sent)) / float64(time.Millisecond)
						if q.canary {
							r.rec.summary.CanaryRTTCount++
							r.rec.summary.CanaryRTTMillis = append(r.rec.summary.CanaryRTTMillis, ms)
						} else {
							r.rec.summary.RTTCount++
							if len(r.rec.summary.RTTMillis) < 100000 {
								r.rec.summary.RTTMillis = append(r.rec.summary.RTTMillis, ms)
							} else if i := mathrand.IntN(r.rec.summary.RTTCount); i < 100000 {
								r.rec.summary.RTTMillis[i] = ms
							}
						}
					}
				}
				r.rec.mu.Unlock()
				if acknowledged && o.seq == probeSeq {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
				return nil
			}, func(ack observation) {
				r.actual(128)
				if ack.id != stream || ack.seq != probeSeq {
					return
				}
				q.mu.Lock()
				key := fmt.Sprintf("%d:%d:%d", ack.id, ack.seq, ack.sent.UnixNano())
				sent, exists := q.challenges[key]
				valid := exists && sent.Equal(ack.sent)
				if valid {
					delete(q.challenges, key)
				}
				q.mu.Unlock()
				if !valid {
					return
				}
				select {
				case helperReady <- struct{}{}:
				default:
				}
			})
			q.mu.Lock()
			expected := q.expected
			q.mu.Unlock()
			if err != nil && !expected && ctx.Err() == nil {
				r.fail(fmt.Errorf("guest %d channel %d: %w", q.id, ch, err))
			}
		}()
		if err = q.helperChallenge(attempt, r, in, stream, probeSeq, ch, helperReady); err != nil {
			return err
		}
		if err = q.barrier(attempt, r, in, stream, "Q"); err != nil {
			return err
		}
		if err = r.send(q, in, stream, probeSeq); err != nil {
			return err
		}
		select {
		case <-ready:
		case <-attempt.Done():
			return fmt.Errorf("terminal readiness: %w", attempt.Err())
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !stop() {
		return errors.New("guest readiness cancelled")
	}
	r.rec.event("guest_ready", map[string]any{"guest": q.id, "host": q.host.id, "transport": q.endpoint.Scheme, "node": s.NodeAddr, "session_id": s.SessionId, "channels": len(q.channels), "generation": q.generation, "canary": q.canary, "ready_ms": float64(time.Since(serviceBegan)) / float64(time.Millisecond), "queue_ms": float64(q.queueElapsed) / float64(time.Millisecond)})
	return nil
}
func frameLength(kind string) int {
	if kind == "H" {
		return 1024
	}
	return 128
}
func (q *guest) active(r *runState) error {
	q.mu.Lock()
	expected := q.expected
	q.mu.Unlock()
	if expected {
		r.paused()
		return nil
	}
	q.inputOps.Lock()
	defer q.inputOps.Unlock()
	q.mu.Lock()
	if q.expected {
		q.mu.Unlock()
		r.paused()
		return nil
	}
	if len(q.writers) == 0 {
		q.mu.Unlock()
		return errors.New("guest has no terminal")
	}
	w, seq := q.writers[0], q.seq
	q.seq++
	q.mu.Unlock()
	sent := time.Now()
	err := r.send(q, w, q.id*4, seq)
	if err != nil {
		q.mu.Lock()
		expected := q.expected
		q.mu.Unlock()
		if expected {
			r.paused()
			return nil
		}
		return err
	}
	q.mu.Lock()
	q.lastActiveSeq = seq
	q.lastActiveAt = sent
	q.activeGeneration = q.generation
	q.activeOffered = true
	q.mu.Unlock()
	r.rec.mu.Lock()
	r.rec.summary.ActiveFrames++
	r.rec.mu.Unlock()
	return nil
}
func (r *runState) paused()         { r.rec.mu.Lock(); r.rec.summary.PausedActiveFrames++; r.rec.mu.Unlock() }
func (q *guest) setExpected(b bool) { q.mu.Lock(); q.expected = b; q.mu.Unlock() }
func transport(t Target, percent, index, total int, public bool) (*url.URL, error) {
	raw := t.SSHURL
	if public {
		raw = t.PublicSSHURL
	}
	if index < total*percent/100 {
		raw = t.WSURL
		if public {
			raw = t.PublicWSURL
		}
	}
	return endpoint(raw, "ssh", "ws", "wss")
}

// Replay and duplicates are observations, never a second completed request.
func (q *guest) acknowledge(o observation) (time.Time, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := fmt.Sprintf("%d:%d", o.id, o.seq)
	sent, ok := q.pending[key]
	if !ok || !sent.Equal(o.sent) {
		return time.Time{}, false
	}
	delete(q.pending, key)
	q.acks++
	return sent, true
}

func (q *guest) helperChallenge(ctx context.Context, r *runState, w io.Writer, stream, seq, ch int, ready <-chan struct{}) error {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("helper readiness: %w", err)
		}
		if attempt > 1 {
			r.rec.mu.Lock()
			r.rec.summary.ReadinessChallengeRetries++
			r.rec.mu.Unlock()
			r.rec.event("readiness_challenge_retry", map[string]any{"guest": q.id, "host": q.host.id, "channel": ch, "attempt": attempt, "canary": q.canary})
		}
		if err := r.sendKind(q, w, stream, seq, "R"); err != nil {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ready:
			timer.Stop()
			return nil
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("helper readiness: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
