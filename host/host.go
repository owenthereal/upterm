package host

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/models"
	"github.com/jingweno/upterm/host/internal"
	"github.com/jingweno/upterm/upterm"
	"github.com/jingweno/upterm/utils"
	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	Host                   string
	KeepAliveDuration      time.Duration
	Command                []string
	ForceCommand           []string
	Signers                []ssh.Signer
	AuthorizedKeys         []ssh.PublicKey
	AdminSocketFile        string
	SessionCreatedCallback func(*models.APIGetSessionResponse) error
	ClientJoinedCallback   func(api.Client)
	ClientLeftCallback     func(api.Client)
	Logger                 log.FieldLogger
	Stdin                  *os.File
	Stdout                 *os.File
	ReadOnly               bool
}

func (c *Host) createAdminSocketDir(sessionID string) (string, error) {
	uptermDir, err := utils.UptermDir()
	if err != nil {
		return "", err
	}

	socketDir := filepath.Join(uptermDir, sessionID)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return "", err
	}

	return socketDir, nil
}

func (c *Host) Run(ctx context.Context) error {
	u, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("error parsing host url: %s", err)
	}

	if c.Stdin == nil {
		c.Stdin = os.Stdin
	}
	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}

	rt := internal.ReverseTunnel{
		Host:              u,
		Signers:           c.Signers,
		AuthorizedKeys:    c.AuthorizedKeys,
		KeepAliveDuration: c.KeepAliveDuration,
		Logger:            log.WithField("com", "reverse-tunnel"),
	}
	sessResp, err := rt.Establish(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	if c.AdminSocketFile == "" {
		adminSocketDir, err := c.createAdminSocketDir(sessResp.SessionID)
		if err != nil {
			return err
		}
		defer os.RemoveAll(adminSocketDir)

		c.AdminSocketFile = AdminSocketFile(adminSocketDir)
	}

	session := &models.APIGetSessionResponse{
		SessionID:    sessResp.SessionID,
		Host:         u.String(),
		NodeAddr:     sessResp.NodeAddr,
		Command:      c.Command,
		ForceCommand: c.ForceCommand,
	}

	if c.SessionCreatedCallback != nil {
		if err := c.SessionCreatedCallback(session); err != nil {
			return err
		}
	}

	clientRepo := internal.NewClientRepo()
	eventEmitter := emitter.New(1)

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		s := internal.AdminServer{
			Session:    session,
			ClientRepo: clientRepo,
		}
		g.Add(func() error {
			return s.Serve(ctx, c.AdminSocketFile)
		}, func(err error) {
			_ = s.Shutdown(ctx)
			cancel()
		})
	}
	{
		g.Add(func() error {
			for evt := range eventEmitter.On(upterm.EventClientJoined) {
				args := evt.Args
				if len(args) == 0 {
					continue
				}

				client, ok := args[0].(api.Client)
				if ok {
					_ = clientRepo.Add(client)
					if c.ClientJoinedCallback != nil {
						c.ClientJoinedCallback(client)
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off("*")
		})
	}
	{
		g.Add(func() error {
			for evt := range eventEmitter.On(upterm.EventClientLeft) {
				args := evt.Args
				if len(args) == 0 {
					continue
				}

				cid, ok := args[0].(string)
				if ok {
					client := clientRepo.Get(cid)
					clientRepo.Delete(cid)
					if c.ClientLeftCallback != nil && client != nil {
						c.ClientLeftCallback(*client)
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off("*")
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sshServer := internal.Server{
			Command:           c.Command,
			CommandEnv:        []string{fmt.Sprintf("%s=%s", upterm.HostAdminSocketEnvVar, c.AdminSocketFile)},
			ForceCommand:      c.ForceCommand,
			Signers:           c.Signers,
			AuthorizedKeys:    c.AuthorizedKeys,
			EventEmitter:      eventEmitter,
			KeepAliveDuration: c.KeepAliveDuration,
			Stdin:             c.Stdin,
			Stdout:            c.Stdout,
			Logger:            c.Logger,
			ReadOnly:          c.ReadOnly,
		}
		g.Add(func() error {
			return sshServer.ServeWithContext(ctx, rt.Listener())
		}, func(err error) {
			cancel()
		})
	}

	return g.Run()
}
