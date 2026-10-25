package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// sshSessionWork owns store-producing callbacks and their descendants, and
// the actual HandleConn calls accepted by one sshd. It does not join SSH copy
// workers or liveness probes, which make no store calls.
type sshSessionWork struct {
	mu              sync.Mutex
	stopping        bool
	count           int
	sealed, drained chan struct{}
	keeperContext   context.Context
	cancelKeepers   context.CancelFunc
	peers           map[net.Conn]*sshWorkRef
	stopOnce        sync.Once
	stopErr         error
	stopDone        chan struct{}
}

type sshWorkRef struct {
	owner  *sshSessionWork
	active bool // guarded by owner.mu
}

func newSSHSessionWork() *sshSessionWork {
	ctx, cancel := context.WithCancel(context.Background())
	return &sshSessionWork{sealed: make(chan struct{}), drained: make(chan struct{}),
		keeperContext: ctx, cancelKeepers: cancel, peers: make(map[net.Conn]*sshWorkRef), stopDone: make(chan struct{})}
}

func (w *sshSessionWork) enter() (*sshWorkRef, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping {
		return nil, false
	}
	w.count++
	return &sshWorkRef{owner: w, active: true}, true
}

func (r *sshWorkRef) child() *sshWorkRef {
	w := r.owner
	w.mu.Lock()
	defer w.mu.Unlock()
	if !r.active {
		panic("SSH child handed off by a completed producer")
	}
	w.count++
	return &sshWorkRef{owner: w, active: true}
}

func (r *sshWorkRef) done() {
	w := r.owner
	w.mu.Lock()
	defer w.mu.Unlock()
	if !r.active {
		panic("SSH producer completed twice")
	}
	r.active = false
	w.count--
	if w.stopping && w.count == 0 {
		close(w.drained)
	}
}

func (w *sshSessionWork) seal() <-chan struct{} {
	w.mu.Lock()
	if !w.stopping {
		w.stopping = true
		close(w.sealed)
		if w.count == 0 {
			close(w.drained)
		}
	}
	w.mu.Unlock()
	w.cancelKeepers()
	return w.drained
}

func (w *sshSessionWork) wait(ctx context.Context) error {
	select {
	case <-w.drained:
		return nil
	default:
	}
	select {
	case <-w.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// registerPeer and seal serialize: an Accept returning after the cutoff must
// close its connection without starting HandleConn.
func (w *sshSessionWork) registerPeer(conn net.Conn) (*sshWorkRef, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping {
		return nil, false
	}
	w.count++
	ref := &sshWorkRef{owner: w, active: true}
	w.peers[conn] = ref
	return ref, true
}

func (w *sshSessionWork) handleConn(srv *ssh.Server, conn net.Conn, ref *sshWorkRef) {
	defer ref.done()
	defer func() {
		w.mu.Lock()
		delete(w.peers, conn)
		w.mu.Unlock()
	}()
	srv.HandleConn(conn)
}

// stop shares one cutoff, deadline and outcome between Shutdown and the Serve
// error path. A timed-out owner remains incomplete even if it returns later.
func (w *sshSessionWork) stop(ln *closeOnceListener) error {
	// Once elects the stop caller only. Waiting under its mutex would leave
	// concurrent Serve/Shutdown callers blocked on a lock throughout drain.
	leader := false
	w.stopOnce.Do(func() { leader = true })
	if leader {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutDownDeadline)
		defer cancel()
		w.seal()
		var closeErr error
		if ln != nil {
			closeErr = ln.Close()
		}
		w.mu.Lock()
		peers := make([]net.Conn, 0, len(w.peers))
		for conn := range w.peers {
			peers = append(peers, conn)
		}
		w.mu.Unlock()
		for _, conn := range peers {
			_ = conn.Close()
		}
		w.stopErr = errors.Join(closeErr, w.wait(ctx))
		close(w.stopDone)
	}
	<-w.stopDone // Publishes the same completed outcome to every stop caller.
	return w.stopErr
}

// serveSSH keeps the accept scope separate from stop, so its own reference is
// retired before Serve's error path waits for all admitted work.
func (w *sshSessionWork) serveSSH(work *sshWorkRef, srv *ssh.Server, ln net.Listener) error {
	defer work.done()
	if len(srv.HostSigners) == 0 {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		signer, err := gossh.NewSignerFromKey(key)
		if err != nil {
			return err
		}
		srv.HostSigners = []ssh.Signer{signer}
	}
	if srv.SubsystemHandlers == nil {
		srv.SubsystemHandlers = make(map[string]ssh.SubsystemHandler)
		for name, handler := range ssh.DefaultSubsystemHandlers {
			srv.SubsystemHandlers[name] = handler
		}
	}
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-w.sealed:
				return ssh.ErrServerClosed
			default:
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() { //nolint:staticcheck // Match the pinned SSH accept retry policy.
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay = min(2*delay, time.Second)
				}
				timer := time.NewTimer(delay)
				select {
				case <-w.sealed:
					timer.Stop()
					return ssh.ErrServerClosed
				case <-timer.C:
				}
				continue
			}
			return err
		}
		ref, ok := w.registerPeer(conn)
		if !ok {
			_ = conn.Close()
			return ssh.ErrServerClosed
		}
		go w.handleConn(srv, conn, ref)
	}
}
