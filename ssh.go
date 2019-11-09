package upterm

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedStreamLocalChannelType = "forwarded-streamlocal@openssh.com"
)

type streamLocalChannelForwardMsg struct {
	SocketPath string
}

type forwardedStreamLocalPayload struct {
	SocketPath string
	Reserved0  string
}

func NewForwardedUnixHandler(socketDir string, logger *log.Entry) *ForwardedUnixHandler {
	return &ForwardedUnixHandler{
		socketDir: socketDir,
		forwards:  make(map[string]net.Listener),
		logger:    logger,
	}
}

type ForwardedUnixHandler struct {
	socketDir string
	forwards  map[string]net.Listener
	logger    *log.Entry
	sync.Mutex
}

func (h *ForwardedUnixHandler) HandleSSHRequest(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case "streamlocal-forward@openssh.com":
		var reqPayload streamLocalChannelForwardMsg
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.logger.WithError(err).Info("error parsing streamlocal payload")
			return false, []byte(err.Error())
		}

		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.SocketPath, 0) {
			return false, []byte("port forwarding is disabled")
		}

		socketPath := reqPayload.SocketPath
		localSocketPath := filepath.Join(h.socketDir, socketPath)
		logger := h.logger.WithFields(log.Fields{"socket": socketPath, "path": localSocketPath})

		if err := os.RemoveAll(localSocketPath); err != nil {
			msg := fmt.Sprintf("socket %s is in use", socketPath)
			logger.WithError(err).Info(msg)
			return false, []byte(msg)
		}

		ln, err := net.Listen("unix", localSocketPath)
		if err != nil {
			logger.WithError(err).Info("error listening socketing")
			return false, []byte(err.Error())
		}

		h.Lock()
		h.forwards[socketPath] = ln
		h.Unlock()

		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[socketPath]
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
				payload := gossh.Marshal(&forwardedStreamLocalPayload{
					SocketPath: socketPath,
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedStreamLocalChannelType, payload)
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
			delete(h.forwards, socketPath)
			h.Unlock()
		}(logger, socketPath)

		return true, nil

	case "cancel-streamlocal-forward@openssh.com":
		var reqPayload streamLocalChannelForwardMsg
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

type SSHProxyHandler struct {
	socketDir string
	logger    *log.Entry
}

func NewSSHProxyHandler(socketDir string, logger *log.Entry) *SSHProxyHandler {
	return &SSHProxyHandler{
		socketDir: socketDir,
		logger:    logger,
	}
}

func (h *SSHProxyHandler) Handle(s ssh.Session) {
	if err := h.handle(s); err != nil {
		h.logger.WithError(err).Info("error handling ssh session")
		s.Exit(1)
	}
}

func (h *SSHProxyHandler) handle(s ssh.Session) error {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		return fmt.Errorf("no pty is requested")
	}

	user := s.User()
	logger := h.logger.WithField("user", user)
	socketPath := filepath.Join(h.socketDir, SocketFile(user))

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

	go func() {
		for win := range winCh {
			if err := session.WindowChange(win.Height, win.Width); err != nil {
				logger.WithError(err).Info("error requesting window change")
			}
		}
	}()

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

	go io.Copy(s, stdout)
	go io.Copy(s, stderr)
	io.Copy(stdin, s)

	return nil
}
