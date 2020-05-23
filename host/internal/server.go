package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/upterm"

	uio "github.com/jingweno/upterm/io"
	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/rs/xid"
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
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter()

	emCtx, emCancel := context.WithCancel(ctx)
	defer emCancel()
	em := newEventManager(emCtx, s.Logger.WithField("com", "event-manager"))

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		em,
		writers,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	{
		g.Add(func() error {
			em.HandleEvent()
			return nil
		}, func(err error) {
			emCancel()
		})
	}
	{
		g.Add(func() error {
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sh := sessionHandler{
			forceCommand:      s.ForceCommand,
			ptmx:              ptmx,
			em:                em,
			eventEmmiter:      s.EventEmitter,
			writers:           writers,
			keepAliveDuration: s.KeepAliveDuration,
			ctx:               ctx,
			logger:            s.Logger,
			readonly:          s.ReadOnly,
		}
		ph := passwordHandler{
			authorizedKeys: s.AuthorizedKeys,
			eventEmmiter:   s.EventEmitter,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		server := gssh.Server{
			HostSigners:     ss,
			Handler:         sh.HandleSession,
			PasswordHandler: ph.HandlePassword,
			Version:         upterm.HostSSHServerVersion,
			PublicKeyHandler: func(ctx gssh.Context, key gssh.PublicKey) bool {
				// This function is never executed when the protocol is ssh.
				// It acts as an indicator to crypto/ssh that public key auth
				// is enabled. This allows the ssh router to convert the public
				// key auth to password auth with public key as the password in
				// authorized key format.
				//
				// However, this function needs to return true to allow publickey
				// auth when the protocol is websocket.
				return true
			},
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

type passwordHandler struct {
	authorizedKeys []ssh.PublicKey
	eventEmmiter   *emitter.Emitter
}

func (h *passwordHandler) HandlePassword(ctx gssh.Context, password string) bool {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(password))
	if err != nil {
		return false
	}

	if len(h.authorizedKeys) == 0 {
		h.emitClientJoinEvent(ctx, pk)
		return true
	}

	for _, k := range h.authorizedKeys {
		if gssh.KeysEqual(k, pk) {
			h.emitClientJoinEvent(ctx, pk)
			return true
		}
	}

	return false
}

func (h *passwordHandler) emitClientJoinEvent(ctx gssh.Context, pk ssh.PublicKey) {
	c := api.Client{
		Id:                   ctx.SessionID(),
		Addr:                 ctx.RemoteAddr().String(),
		PublicKeyFingerprint: fingerprintSHA256(pk),
	}
	h.eventEmmiter.Emit(upterm.EventClientJoin, c)
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              *pty
	em                *eventManager
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            log.FieldLogger
	readonly          bool
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID)
	defer h.eventEmmiter.Emit(upterm.EventClientLeave, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
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

		cmdCtx, cmdCancel := context.WithCancel(h.ctx)
		defer cmdCancel()

		cmd, ptmx, err = startAttachCmd(cmdCtx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Error("error starting force command")
			_ = sess.Exit(1)
			return
		}

		{
			// reattach output
			ctx, cancel := context.WithCancel(h.ctx)
			g.Add(func() error {
				_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
				return ptyError(err)
			}, func(err error) {
				cancel()
			})
		}
		{
			g.Add(func() error {
				return cmd.Wait()
			}, func(err error) {
				cmdCancel()
				ptmx.Close()
			})
		}
	} else {
		// output
		_ = h.writers.Append(sess)
		defer h.writers.Remove(sess)
	}
	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		tm := h.em.TerminalEvent(xid.New().String(), ptmx)
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tm.TerminalWindowChanged(win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tm.TerminalDetached()
			cancel()
		})
	}

	// if a readonly session has been requested, don't connect stdin
	if !h.readonly {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
			return err
		}, func(err error) {
			cancel()
		})
	} else {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(sess, "\r\n=== Attached to read-only session ===\r\n\r\n")
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

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *pty, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := startPty(cmd)

	return cmd, pty, err
}

func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return fmt.Sprintf("SHA256:%s", strings.TrimRight(b64hash, "="))
}
