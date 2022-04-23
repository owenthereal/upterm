package host

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func NewPromptingHostKeyCallback(stdin io.Reader, stdout io.Writer, knownHostsFilename string) (ssh.HostKeyCallback, error) {
	if err := createFileIfNotExist(knownHostsFilename); err != nil {
		return nil, err
	}

	cb, err := knownhosts.New(knownHostsFilename)
	if err != nil {
		return nil, err
	}

	hkcb := hostKeyCallback{
		stdin:           stdin,
		stdout:          stdout,
		file:            knownHostsFilename,
		HostKeyCallback: cb,
	}

	return hkcb.checkHostKey, nil
}

const (
	markerCert = "@cert-authority"

	errKeyMismatch = `
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %s key sent by the remote host is
%s.
Please contact your system administrator.
Add correct host key in %s to get rid of this message.
Offending %s key in %s:%d`
	errNoAuthoritiesHostname = "ssh: no authorities for hostname"
)

type hostKeyCallback struct {
	stdin  io.Reader
	stdout io.Writer
	file   string
	ssh.HostKeyCallback
}

func (cb hostKeyCallback) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := cb.HostKeyCallback(hostname, remote, key); err != nil {
		kerr, ok := err.(*knownhosts.KeyError)
		// Return err if it's neither key error or no authrorities hostname error
		if !ok && !strings.HasPrefix(err.Error(), errNoAuthoritiesHostname) {
			return err
		}

		// If keer.Want is non-empty, there was a mismatch, which can signify a MITM attack
		if kerr != nil && len(kerr.Want) != 0 {
			kk := kerr.Want[0] // TODO: take care of multiple key mismatches
			fp := utils.FingerprintSHA256(kk.Key)
			kt := keyType(kk.Key.Type())
			return fmt.Errorf(errKeyMismatch, kt, fp, kk.Filename, kt, kk.Filename, kk.Line)
		}

		return cb.promptForConfirmation(hostname, remote, key)
	}

	return nil
}

func (cb hostKeyCallback) promptForConfirmation(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		key = cert.SignatureKey
	}

	fp := utils.FingerprintSHA256(key)
	fmt.Fprintf(cb.stdout, "The authenticity of host '%s (%s)' can't be established.\n", knownhosts.Normalize(hostname), knownhosts.Normalize(remote.String()))
	fmt.Fprintf(cb.stdout, "%s key fingerprint is %s.\n", keyType(key.Type()), fp)
	fmt.Fprintf(cb.stdout, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	reader := bufio.NewReader(cb.stdin)
	for {
		confirm, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		confirm = strings.TrimSpace(confirm)

		if confirm == "yes" || confirm == fp {
			return cb.appendHostLine(isCert, hostname, remote.String(), key)
		}

		if confirm == "no" {
			return fmt.Errorf("Host key verification failed.")
		}

		fmt.Fprintf(cb.stdout, "Please type 'yes', 'no' or the fingerprint: ")
	}
}

func (cb hostKeyCallback) appendHostLine(isCert bool, hostname, remote string, key ssh.PublicKey) error {
	f, err := os.OpenFile(cb.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// hostname and remote can be both IPs
	addr := []string{hostname}
	if hostname != remote {
		addr = append(addr, remote)
	}

	line := knownhosts.Line(addr, key)

	if isCert {
		line = fmt.Sprintf("%s %s", markerCert, line)
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}

	return nil
}

type Host struct {
	Host                   string
	KeepAliveDuration      time.Duration
	Command                []string
	ForceCommand           []string
	Signers                []ssh.Signer
	HostKeyCallback        ssh.HostKeyCallback
	AuthorizedKeys         []ssh.PublicKey
	AdminSocketFile        string
	SessionCreatedCallback func(*api.GetSessionResponse) error
	ClientJoinedCallback   func(*api.Client)
	ClientLeftCallback     func(*api.Client)
	Logger                 log.FieldLogger
	Stdin                  *os.File
	Stdout                 *os.File
	ReadOnly               bool
	VSCode                 bool
}

func (c *Host) Run(ctx context.Context) error {
	rand.Seed(time.Now().UTC().UnixNano())

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

	logger := c.Logger.WithField("server", u)

	logger.Info("Etablishing reverse tunnel")
	rt := internal.ReverseTunnel{
		Host:              u,
		Signers:           c.Signers,
		HostKeyCallback:   c.HostKeyCallback,
		AuthorizedKeys:    c.AuthorizedKeys,
		KeepAliveDuration: c.KeepAliveDuration,
		Logger:            c.Logger.WithField("com", "reverse-tunnel"),
	}
	sessResp, err := rt.Establish(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	if c.AdminSocketFile == "" {
		dir, err := utils.CreateUptermDir()
		if err != nil {
			return err
		}

		c.AdminSocketFile = filepath.Join(dir, AdminSocketFile(sessResp.SessionID))

		defer os.Remove(c.AdminSocketFile)
	}

	logger = logger.WithField("session", sessResp.SessionID)
	logger.Info("Established reverse tunnel")

	session := &api.GetSessionResponse{
		SessionId:    sessResp.SessionID,
		Host:         sessResp.AdvisedUri,
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

	logger = logger.WithFields(log.Fields{"cmd": c.Command, "force-cmd": c.ForceCommand})

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

				client, ok := args[0].(*api.Client)
				if ok {
					_ = clientRepo.Add(client)
					logger.WithField("client", client.Addr).Info("Client joined")
					if c.ClientJoinedCallback != nil {
						c.ClientJoinedCallback(client)
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off(upterm.EventClientJoined)
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
					if client != nil {
						logger.WithField("client", client.Addr).Info("Client left")
						clientRepo.Delete(cid)
						if c.ClientLeftCallback != nil && client != nil {
							c.ClientLeftCallback(client)
						}
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off(upterm.EventClientLeft)
		})
	}
	{
		logger.Info("Starting sshd server")
		defer logger.Info("Finishing sshd server")

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
			Logger:            c.Logger.WithField("com", "server"),
			ReadOnly:          c.ReadOnly,
			VSCode:            c.VSCode,
		}
		g.Add(func() error {
			return sshServer.ServeWithContext(ctx, rt.Listener())
		}, func(err error) {
			cancel()
		})
	}

	return g.Run()
}

func keyType(t string) string {
	return strings.ToUpper(strings.TrimPrefix(t, "ssh-"))
}

func createFileIfNotExist(file string) error {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}

		file, err := os.Create(file)
		if err != nil {
			return err
		}

		defer file.Close()
	}

	return nil
}
