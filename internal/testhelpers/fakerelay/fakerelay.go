// Package fakerelay is an SSH server standing in for uptermd, for tests that
// need a relay to answer as the real one doesn't: with a random ID to a proven
// registration, as a relay without proofs does, with a scripted refusal, or by
// refusing a key at authentication. It serves ssh:// only.
//
// It is a package of its own because it imports server, and server's tests
// import internal/testhelpers.
package fakerelay

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	streamlocalForward       = "streamlocal-forward@openssh.com"
	cancelStreamlocalForward = "cancel-streamlocal-forward@openssh.com"
)

// Relay is a running fake relay.
type Relay struct {
	// Addr is the host:port to dial over ssh://.
	Addr string

	ln     net.Listener
	config *ssh.ServerConfig
	answer func(*server.CreateSessionRequest) (bool, []byte)

	mu       sync.Mutex
	admit    func(ssh.PublicKey) bool
	offered  []ssh.PublicKey
	conns    map[net.Conn]struct{}
	closed   bool
	handlers map[string]func([]byte) (bool, []byte)
	latest   *ssh.ServerConn
	onAccept func()

	forwards    atomic.Int64
	connections atomic.Int64

	wg sync.WaitGroup
}

// Start runs a relay presenting hostKey as a plain key, which answers every
// upterm.ServerCreateSessionRequestType with answer and grants every
// streamlocal forward. It admits any key until Admit says otherwise, and
// stops when the test ends.
func Start(t testing.TB, hostKey ssh.Signer, answer func(*server.CreateSessionRequest) (ok bool, body []byte)) *Relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakerelay: listen: %v", err)
	}
	r := &Relay{Addr: ln.Addr().String(), ln: ln, answer: answer, conns: make(map[net.Conn]struct{})}
	r.config = &ssh.ServerConfig{PublicKeyCallback: r.publicKey}
	r.config.AddHostKey(hostKey)
	t.Cleanup(r.close)
	r.wg.Add(1)
	go r.accept()
	return r
}

// RandomID answers as a relay without proofs does: it ignores the proof and
// registers the session under a random ID, saying nothing about reconnecting.
func RandomID(*server.CreateSessionRequest) (bool, []byte) {
	b, err := proto.Marshal(&server.CreateSessionResponse{SessionID: utils.GenerateSessionID()})
	if err != nil {
		return false, []byte(err.Error())
	}
	return true, b
}

// Admit decides which keys authenticate from now on; nil admits any key.
// Refused keys are still recorded as offered.
func (r *Relay) Admit(fn func(ssh.PublicKey) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.admit = fn
}

// Offered is every public key a client offered, across connections, in the
// order they were offered.
func (r *Relay) Offered() []ssh.PublicKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ssh.PublicKey(nil), r.offered...)
}

// OnAccept has fn run for each connection the relay accepts from now on, as
// it is accepted: before the relay has read any of it, and before the
// handshake can go on.
func (r *Relay) OnAccept(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onAccept = fn
}

// Handle answers every request named name with fn from now on, in place of
// the refusal a request the relay does not know gets.
func (r *Relay) Handle(name string, fn func(payload []byte) (ok bool, body []byte)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handlers == nil {
		r.handlers = make(map[string]func([]byte) (bool, []byte))
	}
	r.handlers[name] = fn
}

// Push sends a request named name to the client of the newest connection that
// completed its handshake, and returns the client's reply.
func (r *Relay) Push(name string, payload []byte) (bool, []byte, error) {
	r.mu.Lock()
	conn := r.latest
	r.mu.Unlock()
	if conn == nil {
		return false, nil, errors.New("fakerelay: no connection to push to")
	}
	return conn.SendRequest(name, true, payload)
}

// Forwards is how many streamlocal-forward requests the relay has granted.
func (r *Relay) Forwards() int { return int(r.forwards.Load()) }

// Connections is how many TCP connections the relay has accepted, whether or
// not they went on to authenticate.
func (r *Relay) Connections() int { return int(r.connections.Load()) }

func (r *Relay) publicKey(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offered = append(r.offered, key)
	if r.admit != nil && !r.admit(key) {
		return nil, errRefused
	}
	return &ssh.Permissions{}, nil
}

var errRefused = errors.New("fakerelay: key refused")

func (r *Relay) accept() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.connections.Add(1)
		r.mu.Lock()
		onAccept := r.onAccept
		r.mu.Unlock()
		if onAccept != nil {
			onAccept()
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			_ = conn.Close()
			return
		}
		r.conns[conn] = struct{}{}
		r.wg.Add(1)
		r.mu.Unlock()
		go r.serve(conn)
	}
}

func (r *Relay) serve(conn net.Conn) {
	defer r.wg.Done()
	defer func() {
		_ = conn.Close()
		r.mu.Lock()
		delete(r.conns, conn)
		r.mu.Unlock()
	}()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, r.config)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	r.mu.Lock()
	r.latest = sconn
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "fakerelay opens no channels")
		}
	}()

	for req := range reqs {
		switch req.Type {
		case upterm.ServerCreateSessionRequestType:
			var csr server.CreateSessionRequest
			if err := proto.Unmarshal(req.Payload, &csr); err != nil {
				_ = req.Reply(false, []byte(err.Error()))
				continue
			}
			ok, body := r.answer(&csr)
			_ = req.Reply(ok, body)
		case streamlocalForward:
			// Counted before the reply, so a client that has its listener
			// sees the count that goes with it.
			r.forwards.Add(1)
			_ = req.Reply(true, nil)
		case cancelStreamlocalForward:
			_ = req.Reply(true, nil)
		default:
			r.mu.Lock()
			handle := r.handlers[req.Type]
			r.mu.Unlock()
			if handle == nil {
				_ = req.Reply(false, nil)
				continue
			}
			ok, body := handle(req.Payload)
			_ = req.Reply(ok, body)
		}
	}
}

func (r *Relay) close() {
	_ = r.ln.Close()
	r.mu.Lock()
	r.closed = true
	conns := r.conns
	r.conns = make(map[net.Conn]struct{})
	r.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
	r.wg.Wait()
}
