package memlistener

import (
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/test/bufconn"
)

var (
	listeners    = make(map[string]*memlistener)
	listenersMux sync.Mutex
)

const (
	defaultBufferSize = 256 * 1024
)

func Listen(network, address string) (net.Listener, error) {
	return ListenMem(network, address, defaultBufferSize)
}

func ListenMem(network, address string, sz int) (net.Listener, error) {
	listenersMux.Lock()
	defer listenersMux.Unlock()

	ln, exist := listeners[address]
	if exist {
		return nil, fmt.Errorf("listener %s already exists", address)
	}

	ln = &memlistener{
		Listener:  bufconn.Listen(sz),
		addr:      address,
		closeFunc: removeListener,
	}
	listeners[address] = ln

	return ln, nil
}

func DialMem(address string) (net.Conn, error) {
	listenersMux.Lock()
	defer listenersMux.Unlock()

	ln, exist := listeners[address]
	if !exist {
		return nil, fmt.Errorf("listener %s not found", address)
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
