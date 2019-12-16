package host

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	ussh "github.com/jingweno/upterm/host/internal/ssh"
	"github.com/oklog/run"
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

	rt := ussh.ReverseTunnel{
		Host:      c.Host,
		SessionID: c.SessionID,
		Auths:     c.Auths,
		KeepAlive: c.KeepAlive,
	}
	if err := rt.Establish(ctx); err != nil {
		return err
	}
	defer rt.Close()

	adminSockDir, err := ioutil.TempDir("", "upterm")
	if err != nil {
		return err
	}
	defer os.RemoveAll(adminSockDir)

	adminSock := filepath.Join(adminSockDir, "admin.sock")

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		s := adminServer{SessionID: c.SessionID}
		g.Add(func() error {
			return s.Serve(ctx, adminSock)
		}, func(err error) {
			cancel()
			s.Shutdown(ctx)
		})
	}
	{

		ctx, cancel := context.WithCancel(ctx)
		sshServer := ussh.Server{
			Command:        c.Command,
			CommandEnv:     []string{fmt.Sprintf("UPTERM_ADMIN_SOCK=%s", adminSock)},
			JoinCommand:    c.JoinCommand,
			AuthorizedKeys: c.AuthorizedKeys,
			Stdin:          c.Stdin,
			Stdout:         c.Stdout,
			Logger:         c.Logger,
		}
		g.Add(func() error {
			return sshServer.ServeWithContext(ctx, rt.Listener())
		}, func(err error) {
			cancel()
		})
	}

	return g.Run()
}
