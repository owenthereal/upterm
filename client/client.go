package client

import (
	"context"
	"fmt"

	"github.com/jingweno/upterm"
	"github.com/jingweno/upterm/client/internal"
	"github.com/oklog/run"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
)

func NewClient(command, attachCommand []string, host string, logger log.FieldLogger) *Client {
	return &Client{
		host:          host,
		command:       command,
		attachCommand: attachCommand,
		clientID:      xid.New().String(),
		logger:        logger,
	}
}

type Client struct {
	host          string
	command       []string
	attachCommand []string
	clientID      string
	logger        log.FieldLogger
}

func (c *Client) ClientID() string {
	return c.clientID
}

func (c *Client) Run() error {
	ctx := context.Background()

	writers := upterm.NewMultiWriter()

	emCtx, emCancel := context.WithCancel(ctx)
	em := internal.NewEventManager(emCtx)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := newCommand(c.command[0], c.command[1:], em, writers)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	sshClient := newSSHClient(
		c.clientID,
		c.host,
		c.attachCommand,
		ptmx,
		em,
		writers,
		c.logger,
	)

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
			return sshClient.Dial(ctx)
		}, func(err error) {
			cancel()
		})
	}

	return g.Run()
}
