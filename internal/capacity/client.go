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
		raw, err = g.connect(ctx, t, u.Host)
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
	canary       bool
	probeSeq     [4]int
	pending      map[string]time.Time
	lifetimeStop func() bool
	acks         int64
	ops          sync.Mutex
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
	for _, d := range q.done {
		<-d
	}
	q.done = nil
	q.channels = nil
	q.writers = nil
}
func (q *guest) connect(ctx context.Context, r *runState) error {
	q.ops.Lock()
	defer q.ops.Unlock()
	s, err := q.host.session(ctx)
	if err != nil {
		return err
	}
	if err = r.guard.session(ctx, s); err != nil {
		return err
	}
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q.client, q.raw, err = openGuest(attempt, r.guard, q.target, q.endpoint, s, q.identity, q.proxy)
	if err != nil {
		return err
	}
	client := q.client
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
			err := scanFrames(out, func(o observation) error {
				if !live {
					if o.kind != "I" || o.id != stream || o.seq != probeSeq {
						return nil
					}
					live = true
				}
				if err := r.observe(tracker, epochs, o); err != nil {
					return err
				}
				r.actual(int64(frameLength(o.kind)))
				r.rec.mu.Lock()
				r.rec.summary.ReceivedFrames++
				if o.kind == "I" && o.id == stream {
					q.mu.Lock()
					q.acks++
					delete(q.pending, fmt.Sprintf("%d:%d", o.id, o.seq))
					q.mu.Unlock()
					ms := float64(time.Since(o.sent)) / float64(time.Millisecond)
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
				r.rec.mu.Unlock()
				if o.kind == "I" && o.id == stream {
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
		if err = r.sendKind(q, in, stream, probeSeq, "R"); err != nil {
			return err
		}
		select {
		case <-helperReady:
		case <-attempt.Done():
			return fmt.Errorf("helper readiness: %w", attempt.Err())
		case <-ctx.Done():
			return ctx.Err()
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
	r.rec.event("guest_ready", map[string]any{"guest": q.id, "host": q.host.id, "transport": q.endpoint.Scheme, "node": s.NodeAddr, "session_id": s.SessionId, "channels": len(q.channels), "generation": q.generation, "canary": q.canary})
	return nil
}
func frameLength(kind string) int {
	if kind == "H" {
		return 1024
	}
	return 128
}
func (q *guest) active(r *runState) error {
	q.ops.Lock()
	defer q.ops.Unlock()
	q.mu.Lock()
	expected := q.expected
	q.mu.Unlock()
	if expected {
		r.rec.mu.Lock()
		r.rec.summary.PausedActiveFrames++
		r.rec.mu.Unlock()
		return nil
	}
	if len(q.writers) == 0 {
		return errors.New("guest has no terminal")
	}
	err := r.send(q, q.writers[0], q.id*4, q.seq)
	q.seq++
	if err == nil {
		r.rec.mu.Lock()
		r.rec.summary.ActiveFrames++
		r.rec.mu.Unlock()
	}
	return err
}
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
