// This test-only executable intentionally uses stock x/crypto v0.58.0. Do not
// upgrade it with the application's dependency: it represents older SSH peers
// that count every rejected unsigned offer against MaxAuthTries.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// config precedes SSH on stdin; authentication observations go to Events.
type config struct {
	MaxAuthTries int
	RefuseAll    bool
	Allow        []byte
	Version      string
	Banner       string
	Exit         *int
	HostKey      []byte
	Events       string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	input := bufio.NewReader(os.Stdin)
	line, err := input.ReadBytes('\n')
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(line, &cfg); err != nil {
		return err
	}
	events, err := os.OpenFile(cfg.Events, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = events.Close() }()
	return serve(pipeConn{input}, cfg, events)
}

func serve(conn net.Conn, cfg config, events io.Writer) error {
	key, err := ssh.ParsePrivateKey(cfg.HostKey)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(events)
	var recordErr error
	record := func(kind string, key ssh.PublicKey) error {
		if recordErr == nil {
			recordErr = encoder.Encode(struct {
				Kind string
				Data []byte
			}{kind, key.Marshal()})
		}
		return recordErr
	}
	server := &ssh.ServerConfig{
		MaxAuthTries:  cfg.MaxAuthTries,
		ServerVersion: cfg.Version,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if err := record("offer", key); err != nil {
				return nil, err
			}
			if cfg.RefuseAll || (cfg.Allow != nil && !bytes.Equal(key.Marshal(), cfg.Allow)) {
				err := errors.New("fixture relay: key refused")
				if cfg.Banner != "" {
					return nil, &ssh.BannerError{Err: err, Message: cfg.Banner}
				}
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
		VerifiedPublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			return perms, record("authenticated", key)
		},
	}
	server.AddHostKey(key)
	sconn, channels, requests, err := ssh.NewServerConn(conn, server)
	if err != nil {
		// Authentication refusals and departing clients are the test input;
		// an observation failure must instead make the helper fail visibly.
		return recordErr
	}
	defer func() { _ = sconn.Close() }()
	go func() {
		for req := range requests {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	for nc := range channels {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go session(ch, reqs, cfg.Exit)
	}
	return nil
}

func session(ch ssh.Channel, requests <-chan *ssh.Request, exit *int) {
	go func() { _, _ = io.Copy(io.Discard, ch) }()
	for req := range requests {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			if exit != nil {
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(*exit)}))
				_ = ch.Close()
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// pipeConn presents the process's standard pipes as the server transport.
// Writes complete on stdout before the library continues, including its last
// disconnect. Only the config line is consumed before the SSH byte stream.
type pipeConn struct{ *bufio.Reader }

func (pipeConn) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (pipeConn) Close() error                { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }
func (pipeConn) LocalAddr() net.Addr         { return pipeAddr{} }
func (pipeConn) RemoteAddr() net.Addr        { return pipeAddr{} }
func (c pipeConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (pipeConn) SetReadDeadline(t time.Time) error  { return os.Stdin.SetReadDeadline(t) }
func (pipeConn) SetWriteDeadline(t time.Time) error { return os.Stdout.SetWriteDeadline(t) }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
