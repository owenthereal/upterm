package host

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	ussh "github.com/jingweno/upterm/host/internal/ssh"
	"github.com/jingweno/upterm/upterm"
	"github.com/oklog/run"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	Host            string
	SessionID       string
	KeepAlive       time.Duration
	Command         []string
	JoinCommand     []string
	Signers         []ssh.Signer
	AuthorizedKeys  []ssh.PublicKey
	AdminSocketFile string
	Logger          log.FieldLogger
	Stdin           *os.File
	Stdout          *os.File
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
	if c.AdminSocketFile == "" {
		adminSockDir, err := ioutil.TempDir("", "upterm")
		if err != nil {
			return err
		}
		defer os.RemoveAll(adminSockDir)

		c.AdminSocketFile = filepath.Join(adminSockDir, "admin.sock")
	}

	rt := ussh.ReverseTunnel{
		Host:      c.Host,
		SessionID: c.SessionID,
		Signers:   c.Signers,
		KeepAlive: c.KeepAlive,
	}
	info, err := rt.Establish(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		s := adminServer{
			SessionID: c.SessionID,
			Host:      c.Host,
			NodeAddr:  info.NodeAddr,
		}
		g.Add(func() error {
			return s.Serve(ctx, c.AdminSocketFile)
		}, func(err error) {
			s.Shutdown(ctx)
			cancel()
		})
	}
	{

		ctx, cancel := context.WithCancel(ctx)
		sshServer := ussh.Server{
			Command:        c.Command,
			CommandEnv:     []string{fmt.Sprintf("%s=%s", upterm.HostAdminSocketEnvVar, c.AdminSocketFile)},
			JoinCommand:    c.JoinCommand,
			Signers:        c.Signers,
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
