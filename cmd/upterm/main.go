package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/jingweno/upterm"
	"github.com/jingweno/upterm/client"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/google/shlex"
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
		RunE: runE,
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

func runE(c *cobra.Command, args []string) error {
	var err error
	if len(args) == 0 {
		args, err = shlex.Split(os.Getenv("SHELL"))
		if err != nil {
			return err
		}
	}

	ctx := context.Background()

	writers := upterm.NewMultiWriter()

	emCtx, emCancel := context.WithCancel(ctx)
	em := client.NewEventManager(emCtx)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := client.NewCommand(args[0], args[1:], em, writers)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	client := client.New(flagHost, flagAttachCommand, ptmx, em, writers, logger)

	if err := printJoinCmd(client.ID()); err != nil {
		return err
	}
	defer logger.Info("Bye!")

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
		g.Add(func() error {
			return client.Dial(ctx)
		}, func(err error) {
			cancel()
		})
	}

	return g.Run()
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
