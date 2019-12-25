package server

import (
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	"github.com/jingweno/upterm/utils"
)

var Networks NetworkProviders

func init() {
	Networks = []NetworkProvider{&UnixProvider{}}
}

type NetworkProviders []NetworkProvider

func (n NetworkProviders) Get(name string) NetworkProvider {
	for _, p := range n {
		if p.Name() == name {
			return p
		}
	}

	return nil
}

type NetworkProvider interface {
	SetOpts(opts NetworkOptions) error
	Session() SessionDialListener
	SSHD() SSHDDialListener
	Name() string
	Opts() string
}

type NetworkOptions map[string]string

type SessionDialListener interface {
	Listen(sesisonID string) (net.Listener, error)
	Dial(sessionID string) (net.Conn, error)
}

type SSHDDialListener interface {
	Listen() (net.Listener, error)
	Dial() (net.Conn, error)
}

type UnixProvider struct {
	sessionSocketDir string
	sshdSocketPath   string
}

func (p *UnixProvider) Opts() string {
	return fmt.Sprintf("session-socket-dir=%s,sshd-socket-path=%s", p.sessionSocketDir, p.sshdSocketPath)
}

func (p *UnixProvider) SetOpts(opts NetworkOptions) error {
	var ok bool
	p.sessionSocketDir, ok = opts["session-socket-dir"]
	if !ok {
		dir, err := ioutil.TempDir("", "uptermd")
		if err != nil {
			return fmt.Errorf("missing \"session-socket-dir\" option for network provider %s", p.Name())
		}

		p.sessionSocketDir = dir
	}
	p.sshdSocketPath, ok = opts["sshd-socket-path"]
	if !ok {
		dir, err := ioutil.TempDir("", "uptermd")
		if err != nil {
			return fmt.Errorf("missing \"sshd-socket-path\" option for network provider %s", p.Name())
		}

		p.sshdSocketPath = filepath.Join(dir, "sshd.sock")
	}

	return nil
}

func (p *UnixProvider) Session() SessionDialListener {
	return &unixSessionDialListener{SocketDir: p.sessionSocketDir}
}

func (p *UnixProvider) SSHD() SSHDDialListener {
	return &unixSSHDDialListener{SocketPath: p.sshdSocketPath}
}

func (p *UnixProvider) Name() string {
	return "unix"
}

type unixSSHDDialListener struct {
	SocketPath string
}

func (d *unixSSHDDialListener) Listen() (net.Listener, error) {
	return net.Listen("unix", d.SocketPath)
}

func (d *unixSSHDDialListener) Dial() (net.Conn, error) {
	return net.Dial("unix", d.SocketPath)
}

type unixSessionDialListener struct {
	SocketDir string
}

func (d *unixSessionDialListener) Listen(sessionID string) (net.Listener, error) {
	return net.Listen("unix", d.socketPath(sessionID))
}

func (d *unixSessionDialListener) Dial(sessionID string) (net.Conn, error) {
	return net.Dial("unix", d.socketPath(sessionID))
}

func (d *unixSessionDialListener) socketPath(sessionID string) string {
	return filepath.Join(d.SocketDir, utils.SocketFile(sessionID))
}
