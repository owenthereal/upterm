package capacity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"golang.org/x/crypto/ssh"
)

type guard struct {
	cfg    Config
	lookup func(context.Context, string) ([]net.IPAddr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	mu     sync.Mutex
	next   time.Time
	gate   chan struct{}
	active int
	peak   int
}

func newGuard(c Config) *guard {
	return &guard{gate: make(chan struct{}, 1), cfg: c, lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
}
func (g *guard) resolved(ctx context.Context, t Target, addr string) (string, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil || production(h) {
		return "", errors.New("unauthorized destination")
	}
	var ips []net.IPAddr
	if ip := net.ParseIP(h); ip != nil {
		ips = []net.IPAddr{{IP: ip}}
	} else {
		ips, err = g.lookup(ctx, h)
		if err != nil {
			return "", err
		}
	}
	if len(ips) == 0 {
		return "", errors.New("empty DNS response")
	}
	for _, ip := range ips {
		if !contains(t.AllowedIPs, ip.IP.String()) {
			return "", errors.New("DNS address outside manifest")
		}
	}
	return net.JoinHostPort(ips[0].IP.String(), p), nil
}

// A permit holds the one dial gate until an actual external dial starts.
// Waiting for it is generator pacing, outside initial service deadlines.
type dialPermit struct {
	g      *guard
	once   sync.Once
	queued time.Duration
}

func (p *dialPermit) release() {
	if p != nil {
		p.once.Do(func() { <-p.g.gate })
	}
}
func (g *guard) permit(ctx context.Context) (*dialPermit, error) {
	began := time.Now()
	select {
	case g.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p := &dialPermit{g: g}
	g.mu.Lock()
	when := g.next
	g.mu.Unlock()
	if err := pause(ctx, time.Until(when)); err != nil {
		p.release()
		return nil, err
	}
	p.queued = time.Since(began)
	return p, nil
}
func (g *guard) connect(ctx context.Context, t Target, addr string) (net.Conn, error) {
	return g.connectPermit(ctx, t, addr, nil)
}
func (g *guard) connectPermit(ctx context.Context, t Target, addr string, permit *dialPermit) (net.Conn, error) {
	defer func() { permit.release() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	allowed := false
	for _, raw := range []string{t.SSHURL, t.WSURL, t.PublicSSHURL, t.PublicWSURL, t.TelemetryURL} {
		u, err := endpoint(raw, "ssh", "ws", "wss", "http")
		if err == nil && u.Host == addr {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("destination absent from manifest endpoints")
	}
	pinned, err := g.resolved(ctx, t, addr)
	if err != nil {
		return nil, err
	}
	if permit == nil {
		permit, err = g.permit(ctx)
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !time.Now().Before(g.cfg.Manifest.ExpiresAt) {
		return nil, errors.New("manifest expired")
	}
	g.mu.Lock()
	if g.active >= 1000 {
		g.mu.Unlock()
		return nil, errors.New("external connection safety stop")
	}
	g.active++
	if g.active > g.peak {
		g.peak = g.active
	}
	g.mu.Unlock()
	// Update pacing at the actual dial, so delayed/cancelled reservations
	// cannot bunch later external handshakes together.
	g.mu.Lock()
	g.next = time.Now().Add(time.Second / time.Duration(g.cfg.AdmissionsPerSecond))
	g.mu.Unlock()
	permit.release()
	dialctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := g.dial(dialctx, "tcp", pinned)
	if err != nil {
		g.mu.Lock()
		g.active--
		g.mu.Unlock()
		return nil, err
	}
	return &countedConn{Conn: conn, release: func() { g.mu.Lock(); g.active--; g.mu.Unlock() }}, nil
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (g *guard) session(ctx context.Context, s *api.GetSessionResponse) error {
	if s == nil || s.SessionId == "" {
		return errors.New("missing session")
	}
	for _, t := range g.cfg.Manifest.Targets {
		if contains(t.NodeAddresses, s.NodeAddr) {
			if _, err := g.resolved(ctx, t, s.NodeAddr); err != nil {
				return err
			}
			if strings.Contains(s.SshUser, ":") {
				id, node, err := (&routing.EmbeddedEncodeDecoder{}).Decode(s.SshUser)
				if err != nil || id != s.SessionId || node != s.NodeAddr {
					return errors.New("SSH route disagrees with allowed session node")
				}
			} else if s.SshUser != s.SessionId {
				return errors.New("SSH route disagrees with session ID")
			}
			return nil
		}
	}
	return errors.New("session node outside manifest")
}

func (g *guard) guestKey(ctx context.Context, entry Target, transport string, s *api.GetSessionResponse) (ssh.HostKeyCallback, error) {
	if err := g.session(ctx, s); err != nil {
		return nil, err
	}
	// SSH terminates at the entry. Embedded-mode WebSocket routing also goes
	// through the entry's SSH proxy. Consul-mode WebSocket routing instead
	// pipes SSH to the session's node, or hands off to the entry's SSH proxy
	// if that TCP dial fails. Each certificate must match its own authority
	// and principal; a raw key cannot establish the entry fallback identity.
	// Its plain SSH user distinguishes it from the validated embedded route.
	if transport != "ssh" && s.SshUser == s.SessionId {
		for _, origin := range g.cfg.Manifest.Targets {
			if origin.MachineID != entry.MachineID && contains(origin.NodeAddresses, s.NodeAddr) {
				check := pinnedKey(origin)
				fallback := pinnedKey(entry)
				node := s.NodeAddr
				return func(addr string, remote net.Addr, key ssh.PublicKey) error {
					err := check(node, remote, key)
					if _, cert := key.(*ssh.Certificate); err == nil || !cert {
						return err
					}
					return fallback(addr, remote, key)
				}, nil
			}
		}
	}
	return pinnedKey(entry), nil
}

func pinnedKey(t Target) ssh.HostKeyCallback {
	var pins []ssh.PublicKey
	for _, s := range t.HostKeys {
		k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(s))
		pins = append(pins, k)
	}
	matches := func(k ssh.PublicKey) bool {
		for _, p := range pins {
			if p != nil && bytes.Equal(p.Marshal(), k.Marshal()) {
				return true
			}
		}
		return false
	}
	return func(addr string, _ net.Addr, k ssh.PublicKey) error {
		if cert, ok := k.(*ssh.Certificate); ok {
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				return err
			}
			if cert.CertType != ssh.HostCert || !matches(cert.SignatureKey) {
				return errors.New("untrusted relay certificate")
			}
			return (&ssh.CertChecker{}).CheckCert(h, cert)
		}
		if !matches(k) {
			return errors.New("relay key differs from manifest")
		}
		return nil
	}
}

// A private CONNECT door keeps Host's own reconnect machinery behind the same
// DNS pinning and admission limiter as guests. It also owns the actual sockets
// severed during host churn; no host or session is replaced.
type tunnelProxy struct {
	g              *guard
	t              Target
	ctx            context.Context
	server         *http.Server
	listener       net.Listener
	url            *url.URL
	mu             sync.Mutex
	conns          map[net.Conn]bool
	closing        bool
	workers        sync.WaitGroup
	done           chan struct{}
	permit         *dialPermit
	dialStarted    chan time.Time
	readyTimer     *time.Timer
	serviceTimeout time.Duration
	queueLimit     time.Duration
	queueTime      time.Duration
	failure        func(error)
	queueEvent     func(time.Duration, bool)
}

func newTunnelProxy(ctx context.Context, g *guard, t Target) (*tunnelProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &tunnelProxy{g: g, t: t, ctx: ctx, listener: ln, conns: map[net.Conn]bool{}, done: make(chan struct{}), dialStarted: make(chan time.Time, 1), queueLimit: 5 * time.Second}
	p.url = &url.URL{Scheme: "http", Host: ln.Addr().String()}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second}
	go func() { defer close(p.done); _ = p.server.Serve(ln) }()
	return p, nil
}
func (p *tunnelProxy) track(c net.Conn, external bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		_ = c.Close()
		return false
	}
	p.conns[c] = external
	return true
}
func (p *tunnelProxy) untrack(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}
func (p *tunnelProxy) cut() (int, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	var actual time.Time
	// Sever the external socket first. Closing the loopback side first could
	// race its copier and turn the external close into an uncounted no-op.
	for c, external := range p.conns {
		if !external {
			continue
		}
		if err := c.Close(); err == nil {
			n++
			actual = time.Now()
		}
		delete(p.conns, c)
	}
	for c := range p.conns {
		_ = c.Close()
		delete(p.conns, c)
	}
	return n, actual
}
func (p *tunnelProxy) ready() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readyTimer != nil {
		p.readyTimer.Stop()
		p.readyTimer = nil
	}
	if p.serviceTimeout > 0 {
		p.serviceTimeout = 30 * time.Second
	}
}
func (p *tunnelProxy) queued() time.Duration { p.mu.Lock(); defer p.mu.Unlock(); return p.queueTime }
func (p *tunnelProxy) close() {
	p.mu.Lock()
	p.closing = true
	if p.readyTimer != nil {
		p.readyTimer.Stop()
	}
	p.permit.release()
	p.permit = nil
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	_ = p.server.Close()
	<-p.done
	p.workers.Wait()
}
func (p *tunnelProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.workers.Add(1)
	p.mu.Unlock()
	defer p.workers.Done()
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	permit := p.permit
	p.permit = nil
	p.mu.Unlock()
	if permit == nil {
		// Released retry/WS dial clocks include CONNECT. Keep that queue bounded,
		// classify saturation as generator-limited, and give retry service its
		// normal 30 seconds after this at-most-five-second pacing allowance.
		queuedAt := time.Now()
		queuectx, cancel := context.WithTimeout(p.ctx, p.queueLimit)
		var err error
		permit, err = p.g.permit(queuectx)
		cancel()
		if p.queueEvent != nil {
			p.queueEvent(time.Since(queuedAt), err != nil)
		}
		if err != nil {
			if p.ctx.Err() == nil && p.failure != nil {
				p.failure(errors.New("generator_admission_backlog"))
			}
			http.Error(w, "generator admission backlog", http.StatusServiceUnavailable)
			return
		}
	}
	defer permit.release()
	p.mu.Lock()
	p.queueTime += permit.queued
	p.mu.Unlock()
	began := time.Now()
	select {
	case p.dialStarted <- began:
	default:
	}
	upstream, err := p.g.connectPermit(p.ctx, p.t, r.Host, permit)
	if err != nil {
		http.Error(w, "destination refused", http.StatusForbidden)
		return
	}
	p.mu.Lock()
	if p.serviceTimeout > 0 {
		p.readyTimer = time.AfterFunc(p.serviceTimeout-time.Since(began), func() { _ = upstream.Close() })
	}
	serviceTimer := p.readyTimer
	p.mu.Unlock()
	if serviceTimer != nil {
		defer serviceTimer.Stop()
	}
	if !p.track(upstream, true) {
		return
	}
	defer p.untrack(upstream)
	downstream, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	if !p.track(downstream, false) {
		return
	}
	defer p.untrack(downstream)
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(upstream, rw)
		// Either peer can disappear while the other remains silent. Release
		// both sockets to unblock the opposite copier before joining it.
		_ = upstream.Close()
		_ = downstream.Close()
	}()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	_ = upstream.Close()
	<-copied
}

func (p *tunnelProxy) takePermit() *dialPermit {
	p.mu.Lock()
	defer p.mu.Unlock()
	permit := p.permit
	p.permit = nil
	return permit
}
