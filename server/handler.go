package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/jingweno/ssh"
	"github.com/jingweno/upterm"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedStreamlocalChannelType    = "forwarded-streamlocal@openssh.com"
	streamlocalForwardChannelType      = "streamlocal-forward@openssh.com"
	cancelStreamlocalForwardChanneType = "cancel-streamlocal-forward@openssh.com"
)

type streamlocalChannelForwardMsg struct {
	SocketPath string
}

type forwardedStreamlocalPayload struct {
	SocketPath string
	Reserved0  string
}

func newStreamlocalForwardHandler(socketDir string, logger log.FieldLogger) *streamlocalForwardHandler {
	return &streamlocalForwardHandler{
		socketDir: socketDir,
		forwards:  make(map[string]net.Listener),
		logger:    logger,
	}
}

type streamlocalForwardHandler struct {
	socketDir string
	forwards  map[string]net.Listener
	logger    log.FieldLogger
	sync.Mutex
}

func (h *streamlocalForwardHandler) Handler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case streamlocalForwardChannelType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Info("error parsing streamlocal payload")
			return false, []byte(err.Error())
		}

		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.SocketPath, 0) {
			return false, []byte("port forwarding is disabled")
		}

		requestedSocet := reqPayload.SocketPath
		socket := filepath.Join(h.socketDir, requestedSocet)
		logger := h.logger.WithFields(log.Fields{"requested-socket": requestedSocet, "socket": socket})

		if err := os.RemoveAll(socket); err != nil {
			msg := fmt.Sprintf("socket %s is in use", socket)
			logger.WithError(err).Info(msg)
			return false, []byte(msg)
		}

		ln, err := net.Listen("unix", socket)
		if err != nil {
			logger.WithError(err).Info("error listening socketing")
			return false, []byte(err.Error())
		}

		h.Lock()
		h.forwards[requestedSocet] = ln
		h.Unlock()

		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[requestedSocet]
			h.Unlock()
			if ok {
				ln.Close()
			}
		}()

		go func(logger *log.Entry, socketPath string) {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				payload := gossh.Marshal(&forwardedStreamlocalPayload{
					SocketPath: requestedSocet,
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedStreamlocalChannelType, payload)
					if err != nil {
						logger.WithError(err).Info("error opening channel")
						c.Close()
						return
					}
					go gossh.DiscardRequests(reqs)
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(ch, c)
					}()
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(c, ch)
					}()
				}()
			}
			h.Lock()
			delete(h.forwards, requestedSocet)
			h.Unlock()
		}(logger, requestedSocet)

		return true, nil

	case cancelStreamlocalForwardChanneType:
		var reqPayload streamlocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Info("error parsing steamlocal payload")
			return false, []byte(err.Error())
		}

		h.Lock()
		ln, ok := h.forwards[reqPayload.SocketPath]
		h.Unlock()
		if ok {
			ln.Close()
		}

		return true, nil

	default:
		return false, nil
	}
}

func newSSHProxyHandler(socketDir string, logger log.FieldLogger) *sshProxyHandler {
	return &sshProxyHandler{
		socketDir: socketDir,
		logger:    logger,
	}
}

type sshProxyHandler struct {
	socketDir string
	logger    log.FieldLogger
}

func (h *sshProxyHandler) Handler(s ssh.Session) {
	if err := h.handle(s); err != nil {
		h.logger.WithError(err).Info("error handling ssh session")
		if ee, ok := err.(*gossh.ExitError); ok {
			s.Exit(ee.ExitStatus())
		} else {
			s.Exit(1)
		}
	} else {
		s.Exit(0)
	}
}

func (h *sshProxyHandler) handle(s ssh.Session) error {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		return fmt.Errorf("no pty is requested")
	}

	user := s.User()
	socketPath := filepath.Join(h.socketDir, upterm.SocketFile(user))

	if _, err := os.Stat(socketPath); err != nil {
		return fmt.Errorf("socket does not exist: %w", err)
	}

	config := &gossh.ClientConfig{
		User: user,
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			return nil
		},
	}

	conn, err := gossh.Dial("unix", socketPath, config)
	if err != nil {
		return fmt.Errorf("error dialing %s: %w", h.socketDir, err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("error creating session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, gossh.TerminalModes{}); err != nil {
		return fmt.Errorf("error requesting pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("error getting stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error getting stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("error getting stderr pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("error requesting shell: %w", err)
	}

	ctx := context.Background()
	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					if err := session.WindowChange(win.Height, win.Width); err != nil {
						return err
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			return nil
		}, func(err error) {
			cancel()
		})
	}
	{
		sch := make(chan ssh.Signal)
		s.Signals(sch)
		g.Add(func() error {
			for s := range sch {
				if err := session.Signal(gossh.Signal(s)); err != nil {
					return err
				}
			}
			return nil
		}, func(err error) {
			close(sch)
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			_, err := io.Copy(s, upterm.NewContextReader(ctx, stderr))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			_, err := io.Copy(s, upterm.NewContextReader(ctx, stdout))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			_, err := io.Copy(stdin, upterm.NewContextReader(ctx, s))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return session.Wait()
		}, func(err error) {
			session.Close()
		})
	}

	return g.Run()
}
