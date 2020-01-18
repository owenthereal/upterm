package memlistener

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/test/bufconn"
)

var (
	listeners    = make(map[string]*memlistener)
	listenersMux sync.Mutex

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

func Listen(network, address string) (net.Listener, error) {
	return ListenMem(network, address, defaultBufferSize)
}

func ListenMem(network, address string, sz int) (net.Listener, error) {
	switch network {
	case "mem", "memory":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: net.UnknownNetworkError(network)}
	}

	if address == "" {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: errMissingAddress}
	}

	listenersMux.Lock()
	defer listenersMux.Unlock()

	ln := listeners[address]
	if ln != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr{}, Err: errListenerAlreadyExist{address}}
	}

	ln = &memlistener{
		Listener:  bufconn.Listen(sz),
		addr:      address,
		closeFunc: removeListener,
	}
	listeners[address] = ln

	return ln, nil
}

func Dial(network, address string) (net.Conn, error) {
	switch network {
	case "mem", "memory":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: net.UnknownNetworkError(network)}
	}

	if address == "" {
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: errMissingAddress}
	}

	listenersMux.Lock()
	ln, exist := listeners[address]
	listenersMux.Unlock()
	if !exist {
		return nil, &net.OpError{Op: "dial", Net: network, Source: addr{}, Addr: addr{}, Err: errListenerNotFound{address}}
	}

	return ln.Dial()
}

func removeListener(address string) {
	listenersMux.Lock()
	defer listenersMux.Unlock()

	delete(listeners, address)
}

type memlistener struct {
	*bufconn.Listener
	addr      string
	closeFunc func(addr string)
}

func (m *memlistener) Close() error {
	m.closeFunc(m.addr)
	return m.Listener.Close()
}
