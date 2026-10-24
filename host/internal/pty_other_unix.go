//go:build !windows && !linux

package internal

import "os"

func preparePTYMaster(f *os.File) (*os.File, error) { return f, nil }

func readPTY(p *pty, b []byte) (int, error) {
	p.RLock()
	defer p.RUnlock()
	return p.File.Read(b)
}

func closePTY(p *pty) error {
	p.Lock()
	defer p.Unlock()
	return p.File.Close()
}
