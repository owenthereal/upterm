package memlistener

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/test/bufconn"
)

var (
	errMissingAddress = errors.New("missing address")
)

const (
	defaultBufferSize = 256 * 1024
)

type addr struct{}

func (addr) Network() string { return "mem" }
func (addr) String() string  { return "mem" }

type errListenerAlreadyExist struct {
	addr string
}

func (e errListenerAlreadyExist) Error() string {
	return fmt.Sprintf("listener with address %s already exist", e.addr)
}

type errListenerNotFound struct {
	addr string
}

func (e errListenerNotFound) Error() string {
	return fmt.Sprintf("listener with address %s not found", e.addr)
}

func New() *MemoryListener {
	return &MemoryListener{}
}

type MemoryListener struct {
	listeners sync.Map
}

func (l *MemoryListener) Listen(network, address string) (net.Listener, error) {
	return l.ListenMem(network, address, defaultBufferSize)
}

func (l *MemoryListener) ListenMem(network, address string, sz int) (net.Listener, error) {
	switch network {
	case "mem", "memory":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: net.UnknownNetworkError(network)}
	}

	if address == "" {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: errMissingAddress}
	}

	ln := &memlistener{
		Listener:  bufconn.Listen(sz),
		addr:      address,
		closeFunc: l.removeListener,
	}
	actual, loaded := l.listeners.LoadOrStore(address, ln)
	if loaded {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: errListenerAlreadyExist{address}}
	}

	return actual.(net.Listener), nil
}

func (l *MemoryListener) Dial(network, address string) (net.Conn, error) {
	switch network {
	case "mem", "memory":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: net.UnknownNetworkError(network)}
	}

	if address == "" {
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: errMissingAddress}
	}

	val, exist := l.listeners.Load(address)
	if !exist {
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: errListenerNotFound{address}}
	}

	ln := val.(*memlistener)

	return ln.Dial()
}

func (l *MemoryListener) removeListener(address string) {
	l.listeners.Delete(address)
}

type memlistener struct {
	*bufconn.Listener
	addr      string
	closeFunc func(addr string)
}

func (m *memlistener) Close() error {
	defer m.closeFunc(m.addr)
	return m.Listener.Close()
}
