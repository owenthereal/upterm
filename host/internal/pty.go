package internal

import (
	"os"
	"sync"

	"github.com/creack/pty"
)

func WrapPty(f *os.File) *Pty {
	return &Pty{File: f}
}

// Pty is a wrapper of the pty *os.File that provides a read/write mutex.
// This is to prevent data race that might happen for reszing, reading and closing.
// See ftests failure:
// * https://travis-ci.org/jingweno/upterm/jobs/632489866
// * https://travis-ci.org/jingweno/upterm/jobs/632458125
type Pty struct {
	*os.File
	sync.RWMutex
}

func (p *Pty) Setsize(ws *pty.Winsize) error {
	p.RLock()
	defer p.RUnlock()

	return pty.Setsize(p.File, ws)
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	pty.RLock()
	defer pty.RUnlock()

	return pty.File.Read(p)
}

func (pty *Pty) Close() error {
	pty.Lock()
	defer pty.Unlock()

	return pty.File.Close()
}
