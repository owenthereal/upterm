package host

import (
	"context"
	"os"
	"time"

	ussh "github.com/jingweno/upterm/host/internal/ssh"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	Host           string
	SessionID      string
	KeepAlive      time.Duration
	Command        []string
	JoinCommand    []string
	Auths          []ssh.AuthMethod
	AuthorizedKeys []ssh.PublicKey
	Logger         log.FieldLogger
	Stdin          *os.File
	Stdout         *os.File
}

func (c *Host) Run(ctx context.Context) error {
	if c.SessionID == "" {
		c.SessionID = xid.New().String()
	}
	if c.Stdin == nil {
		c.Stdin = os.Stdin
	}
	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}

	sshClient := ussh.Client{
		Host:      c.Host,
		SessionID: c.SessionID,
		Auths:     c.Auths,
		KeepAlive: c.KeepAlive,
	}
	ln, err := sshClient.ReverseTunnel(ctx)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	sshServer := ussh.Server{
		Command:        c.Command,
		JoinCommand:    c.JoinCommand,
		AuthorizedKeys: c.AuthorizedKeys,
		Stdin:          c.Stdin,
		Stdout:         c.Stdout,
		Logger:         c.Logger,
	}

	return sshServer.ServeWithContext(ctx, ln)
}
