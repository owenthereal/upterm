package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/creack/pty"
	gssh "github.com/gliderlabs/ssh"
	"github.com/jingweno/upterm/host/internal/command"

	"github.com/jingweno/upterm/host/internal/event"
	uio "github.com/jingweno/upterm/io"
	"github.com/oklog/run"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Command        []string
	CommandEnv     []string
	JoinCommand    []string
	Signers        []ssh.Signer
	AuthorizedKeys []ssh.PublicKey
	Stdin          *os.File
	Stdout         *os.File
	Logger         log.FieldLogger
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter()

	emCtx, emCancel := context.WithCancel(ctx)
	em := event.NewEventManager(emCtx)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := command.NewCommand(
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
			joinCommand: s.JoinCommand,
			ptmx:        ptmx,
			em:          em,
			writers:     writers,
			ctx:         ctx,
			logger:      s.Logger,
		}
		ph := passwordHandler{
			authorizedKeys: s.AuthorizedKeys,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		server := gssh.Server{
			HostSigners:     ss,
			Handler:         sh.HandleSession,
			PasswordHandler: ph.HandlePassword,
			PublicKeyHandler: func(ctx gssh.Context, key gssh.PublicKey) bool {
				// This function is never executed and it's as an indicator
				// to crypto/ssh that public key auth is enabled.
				// This allows the Proxy to convert the public key auth to
				// password auth with public key as the password in authorized
				// key format.
				return false
			},
		}
		g.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			// kill ssh sessionHandler
			cancel()
			// shut down ssh server
			server.Shutdown(ctx)
		})
	}

	return g.Run()
}

type passwordHandler struct {
	authorizedKeys []ssh.PublicKey
}

func (h *passwordHandler) HandlePassword(ctx gssh.Context, password string) bool {
	if len(h.authorizedKeys) == 0 {
		return true
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(password))
	if err != nil {
		return false
	}

	for _, k := range h.authorizedKeys {
		if gssh.KeysEqual(k, pk) {
			return true
		}
	}

	return false
}

type sessionHandler struct {
	joinCommand []string
	ptmx        *os.File
	em          *event.EventManager
	writers     *uio.MultiWriter
	ctx         context.Context
	logger      log.FieldLogger
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		io.WriteString(sess, "PTY is required.\n")
		sess.Exit(1)
	}

	var (
		g    run.Group
		err  error
		ptmx = h.ptmx
	)
	if len(h.joinCommand) > 0 {
		var cmd *exec.Cmd

		cmdCtx, cmdCancel := context.WithCancel(h.ctx)
		cmd, ptmx, err = startAttachCmd(cmdCtx, h.joinCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Info("error starting join command")
			sess.Exit(1)
			return
		}

		{
			// reattach output
			ctx, cancel := context.WithCancel(h.ctx)
			g.Add(func() error {
				_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
				return err
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
		h.writers.Append(sess)
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
			return nil
		}, func(err error) {
			tm.TerminalDetached()
			cancel()
		})
	}
	{
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
			sess.Exit(exitError.ExitCode())
		} else {
			sess.Exit(1)
		}
	} else {
		sess.Exit(0)
	}
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *os.File, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := pty.Start(cmd)

	return cmd, pty, err
}
