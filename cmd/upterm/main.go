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

	gssh "github.com/gliderlabs/ssh"
)

var (
	flagHost string
	flagAddr string

	rootCmd = &cobra.Command{
		Use:  "upterm",
		RunE: run,
	}

	logger *log.Logger
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", "0.0.0.0:2222", "server host")
	rootCmd.PersistentFlags().StringVarP(&flagAddr, "address", "a", "0.0.0.0:9000", "address to expose on the server")
	logger = log.New()
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

	l, err := conn.Listen("tcp", flagAddr)
	if err != nil {
		return fmt.Errorf("unable to register TCP forward: %w", err)
	}
	defer l.Close()

	return runCmd(context.Background(), l, args[0], args[1:]...)
}

func runCmd(ctx context.Context, l net.Listener, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("unable to start pty: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				logger.Printf("error resizing pty: %s", err)
			}
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
	writers := upterm.NewMultiWriter(os.Stdout)
	go func() {
		_, _ = io.Copy(writers, ptmx)
	}()

	// input
	go func() {
		io.Copy(ptmx, os.Stdin)
	}()

	go serveSSHServer(l, ptmx, writers)

	return cmd.Wait()
}

func serveSSHServer(l net.Listener, ptmx *os.File, writers *upterm.MultiWriter) error {
	h := func(sess gssh.Session) {
		defer writers.Remove(sess)

		// output
		go func() {
			writers.Append(sess)
		}()

		// input
		_, err := io.Copy(ptmx, sess)
		if err != nil {
			logger.Println(err)
			sess.Exit(1)
		}

		sess.Exit(0)
	}

	return gssh.Serve(l, h)
}
