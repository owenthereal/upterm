package internal

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	ptylib "github.com/creack/pty"
	gssh "github.com/gliderlabs/ssh"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Command           []string
	CommandEnv        []string
	ForceCommand      []string
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	EventEmitter      *emitter.Emitter
	KeepAliveDuration time.Duration
	Stdin             *os.File
	Stdout            *os.File
	Logger            log.FieldLogger
	ReadOnly          bool
	VSCode            bool
	VSCodeWeb         bool
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter()

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		s.EventEmitter,
		writers,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		teh := terminalEventHandler{
			eventEmitter: s.EventEmitter,
			logger:       s.Logger,
		}
		g.Add(func() error {
			return teh.Handle(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		g.Add(func() error {
			<-stopChan // wait for SIGINT
			return nil
		}, func(err error) {
			close(stopChan)
		})
	}
	{
		if s.VSCode {
		} else {
			g.Add(func() error {
				return cmd.Run()
			}, func(err error) {
				cmdCancel()
			})
		}
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sh := sessionHandler{
			forceCommand:      s.ForceCommand,
			ptmx:              ptmx,
			eventEmmiter:      s.EventEmitter,
			writers:           writers,
			keepAliveDuration: s.KeepAliveDuration,
			ctx:               ctx,
			logger:            s.Logger,
			readonly:          s.ReadOnly,
			vscode:            s.VSCode,
		}
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			EventEmmiter:   s.EventEmitter,
			Logger:         s.Logger,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		server := gssh.Server{
			HostSigners: ss,
			Handler:     sh.HandleSession,
			Version:     upterm.HostSSHServerVersion,

			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.WithError(err).Error("connection failed")
			},
		}
		if len(s.AuthorizedKeys) != 0 {
			server.PublicKeyHandler = ph.HandlePublicKey
		}
		if s.VSCode {
			server.ChannelHandlers = map[string]gssh.ChannelHandler{
				"session":      gssh.DefaultSessionHandler,
				"direct-tcpip": gssh.DirectTCPIPHandler,
			}
			server.LocalPortForwardingCallback = gssh.LocalPortForwardingCallback(func(ctx gssh.Context, dhost string, dport uint32) bool {
				s.Logger.Info("Accepting local port forwarding request", dhost, dport)
				return true
			})
			server.SubsystemHandlers = map[string]gssh.SubsystemHandler{
				"sftp": sh.SftpHandler,
			}
		}

		g.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			// kill ssh sessionHandler
			cancel()
			// shut down ssh server
			_ = server.Shutdown(ctx)
		})
	}

	return g.Run()
}

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	EventEmmiter   *emitter.Emitter
	Logger         log.FieldLogger
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		h.Logger.WithError(err).Error("error parsing auth request from cert")
		return false
	}

	// TODO: sshproxy already rejects unauthorized keys
	// Does host still need to check them?
	if len(h.AuthorizedKeys) == 0 {
		emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
		return true
	}

	for _, k := range h.AuthorizedKeys {
		if gssh.KeysEqual(k, pk) {
			emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
			return true
		}
	}

	h.Logger.Info("unauthorized public key")
	return false
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              *pty
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            log.FieldLogger
	readonly          bool
	vscode            bool
}

func (h *sessionHandler) SftpHandler(sess gssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		h.logger.Infof("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		h.logger.Info("sftp client exited session.")
	} else if err != nil {
		h.logger.Info("sftp server completed with error:", err)
	}
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if h.vscode {
		if isPty {
			h.logger.Info("[upterm] new pty session start\n")
			fmt.Fprintf(os.Stdout, "[upterm] new pty session start\n")
			cmd := exec.Command("/bin/bash")
			setWinsize := func(f *os.File, width, height int) {
				_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
					uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(height), uint16(width), 0, 0})))
				if err != 0 {
					h.logger.Errorf("failed to set window size: %v", err)
				}
			}
			f, err := ptylib.Start(cmd)
			if err != nil {
				panic(err)
			}
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() {
				if _, err = io.Copy(f, sess); err != nil {
					h.logger.Errorf("[upterm] unknow error from io copy: %s\n", err)
					fmt.Fprintf(os.Stdout, "[upterm] unknow err, %s, please contact the developer\n", err)
				}
			}()
			if _, err = io.Copy(sess, f); err != nil {
				h.logger.Error("[upterm] unknow error from io copy: %s\n", err)
				fmt.Fprintf(os.Stdout, "[upterm] unknow err, %s, please contact the developer\n", err)
			}
			if err := cmd.Wait(); err != nil {
				h.logger.Error("failed to exit bash (%s)", err)
			}
			return
		}
		var cmd *exec.Cmd
		cmds := sess.Command()

		// vscode can't
		// defer sess.Close()

		if len(cmds) == 0 {
			cmds = []string{"bash"}
			cmd = exec.Command(cmds[0], cmds[1:]...)
		} else {
			if cmds[0] == "/usr/bin/zsh" || cmds[0] == "/bin/zsh" || cmds[0] == "/bin/bash" || cmds[0] == "/bin/sh" {
				cmd = exec.Command(cmds[0], cmds[1:]...)
			} else {
				cmds = []string{"-c", strings.Join(cmds, " ")}
				cmd = exec.Command("bash", cmds...)
			}
		}
		cmd.Stdout = sess
		cmd.Stderr = sess
		cmd.Stdin = sess
		err := cmd.Start()
		if err != nil {
			h.logger.Errorf("could not start command (%s)", err)
			return
		}
		fmt.Fprintf(os.Stdout, "[upterm] new vscode session start\n")

		state, err := cmd.Process.Wait()
		if err != nil {
			h.logger.Error("failed to wait cmd (%s)", err)
		}
		if state.String() != "exit status 0" && strings.Contains(strings.Join(cmds, " "), "ls") {
			if err := sess.Exit(1); err != nil {
				h.logger.Error("failed to exit cmd (%s)", err)
			}
		}
		h.logger.Infof("session closed")
		return
	}

	if !isPty {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
	}

	var (
		g    run.Group
		err  error
		ptmx = h.ptmx
	)

	// simulate openssh keepalive
	{
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			ticker := time.NewTicker(h.keepAliveDuration)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if _, err := sess.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil); err != nil {
						h.logger.WithError(err).Debug("error pinging client to keepalive")
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if len(h.forceCommand) > 0 {
		var cmd *exec.Cmd

		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()

		cmd, ptmx, err = startAttachCmd(ctx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Error("error starting force command")
			_ = sess.Exit(1)
			return
		}

		{
			// reattach output
			g.Add(func() error {
				_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
				return ptyError(err)
			}, func(err error) {
				cancel()
				ptmx.Close()
			})
		}
		{
			g.Add(func() error {
				return cmd.Wait()
			}, func(err error) {
				cancel()
				ptmx.Close()
			})
		}
	} else {
		// output
		if err := h.writers.Append(sess); err != nil {
			_ = sess.Exit(1)
			return
		}

		defer h.writers.Remove(sess)
	}

	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		tee := terminalEventEmitter{h.eventEmmiter}
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tee.TerminalWindowChanged(sessionID, ptmx, win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tee.TerminalDetached(sessionID, ptmx)
			cancel()
		})
	}

	// if a readonly session has been requested, don't connect stdin
	if h.readonly {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(sess, "\r\n=== Attached to read-only session ===\r\n\r\n")
	} else {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
			return err
		}, func(err error) {
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			_ = sess.Exit(exitError.ExitCode())
		} else {
			_ = sess.Exit(1)
		}
	} else {
		_ = sess.Exit(0)
	}
}

func emitClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID string, auth *server.AuthRequest, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

func emitClientLeftEvent(eventEmmiter *emitter.Emitter, sessionID string) {
	eventEmmiter.Emit(upterm.EventClientLeft, sessionID)
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *pty, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := startPty(cmd)

	return cmd, pty, err
}
