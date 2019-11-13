package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"

	"github.com/creack/pty"
	gssh "github.com/jingweno/ssh"
	"github.com/jingweno/upterm/client/internal"
	uio "github.com/jingweno/upterm/io"
	"github.com/jingweno/upterm/utils"
	"github.com/oklog/run"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func newSSHClient(
	clientID string,
	host string,
	attachCommand []string,
	ptmx *os.File,
	em *internal.EventManager,
	writers *uio.MultiWriter,
	logger log.FieldLogger,
) *sshClient {
	return &sshClient{
		clientID:      clientID,
		host:          host,
		attachCommand: attachCommand,
		ptmx:          ptmx,
		em:            em,
		writers:       writers,
		logger:        logger,
	}
}

type sshClient struct {
	host          string
	attachCommand []string
	ptmx          *os.File
	em            *internal.EventManager
	writers       *uio.MultiWriter

	clientID string

	client *ssh.Client
	ln     net.Listener

	logger log.FieldLogger
}

func (c *sshClient) Dial(ctx context.Context) error {
	user, err := user.Current()
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	c.client, err = ssh.Dial("tcp", c.host, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %w", err)
	}

	c.ln, err = c.client.Listen("unix", utils.SocketFile(c.clientID))
	if err != nil {
		return fmt.Errorf("unable to register TCP forward: %w", err)
	}

	go func() {
		<-ctx.Done()
		c.ln.Close()
		c.client.Close()
	}()

	return c.serveSSHServer(ctx)
}

func (c *sshClient) serveSSHServer(ctx context.Context) error {
	h := func(sess gssh.Session) {
		ptyReq, winCh, isPty := sess.Pty()
		if !isPty {
			io.WriteString(sess, "PTY is required.\n")
			sess.Exit(1)
		}

		var (
			g    run.Group
			err  error
			ptmx = c.ptmx
		)
		if len(c.attachCommand) > 0 {
			var cmd *exec.Cmd

			cmdCtx, cmdCancel := context.WithCancel(ctx)
			cmd, ptmx, err = startAttachCmd(cmdCtx, c.attachCommand, ptyReq.Term)
			if err != nil {
				c.logger.Println(err)
				sess.Exit(1)
				return
			}

			{
				// reattach output
				ctx, cancel := context.WithCancel(ctx)
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
			c.writers.Append(sess)
			defer c.writers.Remove(sess)
		}

		{
			// pty
			ctx, cancel := context.WithCancel(ctx)
			tm := c.em.TerminalEvent(xid.New().String(), ptmx)
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
			ctx, cancel := context.WithCancel(ctx)
			g.Add(func() error {
				_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
				return err
			}, func(err error) {
				cancel()
			})
		}

		if err := g.Run(); err != nil {
			sess.Exit(1)
		} else {
			sess.Exit(0)
		}
	}

	return gssh.Serve(c.ln, h)
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *os.File, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := pty.Start(cmd)

	return cmd, pty, err
}
