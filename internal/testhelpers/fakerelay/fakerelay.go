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

	mu      sync.Mutex
	admit   func(ssh.PublicKey) bool
	offered []ssh.PublicKey
	conns   map[net.Conn]struct{}
	closed  bool

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
			_ = req.Reply(false, nil)
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
