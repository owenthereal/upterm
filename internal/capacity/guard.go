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
	active int
	peak   int
}

func newGuard(c Config) *guard {
	return &guard{cfg: c, lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
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
func (g *guard) admit(ctx context.Context) error {
	g.mu.Lock()
	when := g.next
	if when.Before(time.Now()) {
		when = time.Now()
	}
	g.next = when.Add(time.Second / time.Duration(g.cfg.AdmissionsPerSecond))
	g.mu.Unlock()
	timer := time.NewTimer(time.Until(when))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (g *guard) connect(ctx context.Context, t Target, addr string) (net.Conn, error) {
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
	if err = g.admit(ctx); err != nil {
		return nil, err
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
	conn, err := g.dial(ctx, "tcp", pinned)
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
	g        *guard
	t        Target
	ctx      context.Context
	server   *http.Server
	listener net.Listener
	url      *url.URL
	mu       sync.Mutex
	conns    map[net.Conn]bool
	closing  bool
	workers  sync.WaitGroup
	done     chan struct{}
}

func newTunnelProxy(ctx context.Context, g *guard, t Target) (*tunnelProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &tunnelProxy{g: g, t: t, ctx: ctx, listener: ln, conns: map[net.Conn]bool{}, done: make(chan struct{})}
	p.url = &url.URL{Scheme: "http", Host: ln.Addr().String()}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second}
	go func() { defer close(p.done); _ = p.server.Serve(ln) }()
	return p, nil
}
func (p *tunnelProxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		_ = c.Close()
		return false
	}
	p.conns[c] = true
	return true
}
func (p *tunnelProxy) untrack(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}
func (p *tunnelProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		_ = c.Close()
	}
}
func (p *tunnelProxy) close() {
	p.mu.Lock()
	p.closing = true
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
		http.Error(w, "CONNECT required", 405)
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	upstream, err := p.g.connect(ctx, p.t, r.Host)
	if err != nil {
		http.Error(w, "destination refused", 403)
		return
	}
	if !p.track(upstream) {
		return
	}
	defer p.untrack(upstream)
	downstream, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	if !p.track(downstream) {
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
	go func() { defer close(copied); _, _ = io.Copy(upstream, rw) }()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	_ = upstream.Close()
	<-copied
}
