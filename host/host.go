package host

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"log/slog"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
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
		// Return err if it's neither key error or no authorities hostname error
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
	_, _ = fmt.Fprintf(cb.stdout, "The authenticity of host '%s (%s)' can't be established.\n", knownhosts.Normalize(hostname), knownhosts.Normalize(remote.String()))
	_, _ = fmt.Fprintf(cb.stdout, "%s key fingerprint is %s.\n", keyType(key.Type()), fp)
	_, _ = fmt.Fprintf(cb.stdout, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	reader := bufio.NewReader(cb.stdin)
	for {
		confirm, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		confirm = strings.TrimSpace(confirm)

		if confirm == "yes" || confirm == fp {
			return cb.appendHostLine(isCert, hostname, key)
		}

		if confirm == "no" {
			return fmt.Errorf("Host key verification failed")
		}

		_, _ = fmt.Fprintf(cb.stdout, "Please type 'yes', 'no' or the fingerprint: ")
	}
}

func (cb hostKeyCallback) appendHostLine(isCert bool, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(cb.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	// Only store the hostname, not the IP address.
	// This prevents breakage when server IPs change due to:
	// - Load balancers and auto-scaling
	// - Cloud redeployments
	// - CDN/proxy rotation
	// - IPv6 address rotation
	// The security benefit of storing IPs is minimal in modern infrastructure
	// since we already trust DNS, and MITM attacks would need to compromise
	// both DNS and the host key.
	addr := []string{hostname}

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
	Host                           string
	KeepAliveDuration              time.Duration
	Command                        []string
	ForceCommand                   []string
	Signers                        []ssh.Signer
	HostKeyCallback                ssh.HostKeyCallback
	AuthorizedKeys                 []*AuthorizedKey
	AdminSocketFile                string
	SessionCreatedCallback         func(*api.GetSessionResponse) error
	ClientJoinedCallback           func(*api.Client)
	ClientLeftCallback             func(*api.Client)
	Logger                         *slog.Logger
	Stdin                          *os.File
	Stdout                         *os.File
	ReadOnly                       bool
	ForceForwardingInputForTesting bool
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

	var aks []ssh.PublicKey
	for _, ak := range c.AuthorizedKeys {
		aks = append(aks, ak.PublicKeys...)
	}

	logger := c.Logger.With("server", u.String())
	logger.Info("Establishing reverse tunnel")
	rt := internal.ReverseTunnel{
		Host:              u,
		Signers:           c.Signers,
		HostKeyCallback:   c.HostKeyCallback,
		AuthorizedKeys:    aks,
		KeepAliveDuration: c.KeepAliveDuration,
		Logger:            logger.With("component", "reverse-tunnel"),
	}
	sessResp, err := rt.Establish(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	// Check server version compatibility after establishing connection
	serverVersion := string(rt.ServerVersion())
	logger.Debug("detected server version", "server_version", serverVersion)

	// Check for version compatibility
	if result := version.CheckCompatibility(serverVersion); !result.Compatible {
		displayVersionWarning(c.Stdout, logger, result)
	}

	if c.AdminSocketFile == "" {
		dir, err := utils.CreateUptermRuntimeDir()
		if err != nil {
			return err
		}

		c.AdminSocketFile = filepath.Join(dir, AdminSocketFile(sessResp.SessionID))

		defer func() {
			_ = os.Remove(c.AdminSocketFile)
		}()
	}

	logger = logger.With("session", sessResp.SessionID)
	logger.Info("Established reverse tunnel")

	session := &api.GetSessionResponse{
		SessionId:      sessResp.SessionID,
		Host:           u.String(),
		NodeAddr:       sessResp.NodeAddr,
		SshUser:        sessResp.SshUser,
		Command:        c.Command,
		ForceCommand:   c.ForceCommand,
		AuthorizedKeys: toApiAuthorizedKeys(c.AuthorizedKeys),
	}

	if c.SessionCreatedCallback != nil {
		if err := c.SessionCreatedCallback(session); err != nil {
			return err
		}
	}

	clientRepo := internal.NewClientRepo()
	eventEmitter := emitter.New(1)

	logger = logger.With("cmd", c.Command, "force_cmd", c.ForceCommand)

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
					logger.Info("Client joined", "client", client.Addr)
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
						logger.Info("Client left", "client", client.Addr)
						clientRepo.Delete(cid)
						if c.ClientLeftCallback != nil {
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
			Command:                        c.Command,
			CommandEnv:                     []string{fmt.Sprintf("%s=%s", upterm.HostAdminSocketEnvVar, c.AdminSocketFile)},
			ForceCommand:                   c.ForceCommand,
			Signers:                        c.Signers,
			AuthorizedKeys:                 aks,
			EventEmitter:                   eventEmitter,
			KeepAliveDuration:              c.KeepAliveDuration,
			Stdin:                          c.Stdin,
			Stdout:                         c.Stdout,
			Logger:                         logger.With("component", "server"),
			ReadOnly:                       c.ReadOnly,
			ForceForwardingInputForTesting: c.ForceForwardingInputForTesting,
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

		defer func() {
			_ = file.Close()
		}()
	}

	return nil
}

func toApiAuthorizedKeys(aks []*AuthorizedKey) []*api.AuthorizedKey {
	var apiAks []*api.AuthorizedKey
	for _, ak := range aks {
		var fps []string
		for _, pk := range ak.PublicKeys {
			fps = append(fps, utils.FingerprintSHA256(pk))
		}

		apiAks = append(apiAks, &api.AuthorizedKey{
			PublicKeyFingerprints: fps,
			Comment:               ak.Comment,
		})
	}

	return apiAks
}

// displayVersionWarning prints a formatted version mismatch warning to the given writer
func displayVersionWarning(out io.Writer, logger *slog.Logger, result *version.CompatibilityResult) {
	messages := []struct {
		text     string
		debugMsg string
	}{
		{"[WARNING] VERSION MISMATCH DETECTED\n", "failed to display version warning header"},
		{result.Message + "\n", "failed to display version warning message"},
		{fmt.Sprintf("Host version:   %s\n", result.HostVersion), "failed to display host version"},
		{fmt.Sprintf("Server version: %s\n", result.ServerVersion), "failed to display server version"},
		{"\nThis may cause compatibility issues. Consider updating to matching versions.\n\n", "failed to display version warning footer"},
	}

	for _, msg := range messages {
		if _, err := fmt.Fprint(out, msg.text); err != nil {
			logger.Debug(msg.debugMsg, "error", err)
		}
	}
}
