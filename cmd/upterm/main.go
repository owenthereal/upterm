package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"syscall"

	"github.com/creack/pty"
	"github.com/jingweno/upterm"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/google/shlex"
	gssh "github.com/jingweno/ssh"
	"github.com/rs/xid"
)

var (
	flagHost          string
	flagAttachCommand string

	rootCmd = &cobra.Command{
		Use:  "upterm",
		Long: "Share a terminal session.",
		Example: `  # Run $SHELL and client will attach to host's stdin, stdout and stderr
  upterm
  # Run 'bash' and client will attach with to host's stdin, stdout and stderr
  upterm bash
  # Run 'tmux new pair' and client will attach with 'tmux attach -t pair' after it connects
  upterm -t 'tmux attach -t pair' -- tmux new -t pair`,
		RunE: run,
	}

	logger *log.Logger
)

func init() {
	logger = log.New()

	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", "127.0.0.1:2222", "server host")
	rootCmd.PersistentFlags().StringVarP(&flagAttachCommand, "attach-command", "t", "", "attach command after client connects")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

func run(c *cobra.Command, args []string) error {
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
	conn, err := ssh.Dial("tcp", flagHost, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %w", err)
	}
	defer conn.Close()

	sessionID := xid.New().String()
	l, err := conn.Listen("unix", upterm.SocketFile(sessionID))
	if err != nil {
		return fmt.Errorf("unable to register TCP forward: %w", err)
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	em := NewEventManager(ctx)
	defer em.Stop()
	go em.HandleEvent()

	if err := printJoinCmd(sessionID); err != nil {
		return err
	}
	defer logger.Info("Bye!")

	if len(args) == 0 {
		args, err = shlex.Split(os.Getenv("SHELL"))
		if err != nil {
			return err
		}
	}

	return runCmd(ctx, l, em, args)
}

func runCmd(ctx context.Context, l net.Listener, em *EventManager, args []string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("unable to start pty: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	te := em.TerminalEvent("local", ptmx)
	defer te.TerminalDetached()

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			h, w, err := pty.Getsize(os.Stdin)
			if err != nil {
				logger.WithError(err).Info("error getting size of pty")
			}

			te.TerminalWindowChanged(w, h)
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	// Set stdin in raw mode.
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("unable to set terminal to raw mode: %w", err)
	}
	defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldState) }()

	// output
	writers := upterm.NewMultiWriter()
	writers.Append(os.Stdout)
	go func() {
		_, _ = io.Copy(writers, ptmx)
	}()

	// input
	go func() {
		io.Copy(ptmx, os.Stdin)
	}()

	// ssh server for remote access
	go serveSSHServer(ctx, l, em, ptmx, writers, flagAttachCommand)

	return cmd.Wait()
}

func serveSSHServer(ctx context.Context, l net.Listener, em *EventManager, ptmx *os.File, writers *upterm.MultiWriter, attachCommand string) error {
	h := func(sess gssh.Session) {
		ptyReq, winCh, isPty := sess.Pty()
		if !isPty {
			io.WriteString(sess, "PTY is required.\n")
			sess.Exit(1)
		}

		var err error
		if attachCommand != "" {
			// override ptmx
			ptmx, err = startAttachCmd(ctx, attachCommand, ptyReq.Term)
			if err != nil {
				logger.Println(err)
				sess.Exit(1)
			}
			defer ptmx.Close()

			// reattach output
			go func() {
				_, _ = io.Copy(sess, ptmx)
			}()
		} else {
			// output
			writers.Append(sess)
			defer writers.Remove(sess)
		}

		tm := em.TerminalEvent(xid.New().String(), ptmx)
		defer tm.TerminalDetached()

		// pty
		go func() {
			for win := range winCh {
				tm.TerminalWindowChanged(win.Width, win.Height)
			}
		}()

		// input
		_, err = io.Copy(ptmx, sess)
		if err != nil {
			logger.Println(err)
			sess.Exit(1)
		}

		sess.Exit(0)
	}

	return gssh.Serve(l, h)
}

func startAttachCmd(ctx context.Context, cstr, term string) (*os.File, error) {
	c, err := shlex.Split(cstr)
	if err != nil {
		return nil, fmt.Errorf("error parsing command %s: %w", cstr, err)
	}

	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	return pty.Start(cmd)
}

func printJoinCmd(sessionID string) error {
	host, port, err := net.SplitHostPort(flagHost)
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("ssh session: ssh %s@%s", sessionID, host)
	if port != "22" {
		cmd = fmt.Sprintf("%s -p %s", cmd, port)
	}

	logger.Info(cmd)

	return nil
}
