package internal

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os/user"
	"strings"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	publickeyAuthError = "ssh: unable to authenticate, attempted methods [none]"
)

type ReverseTunnel struct {
	*ssh.Client

	Host              *url.URL
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	KeepAliveDuration time.Duration
	HostKeyCallback   ssh.HostKeyCallback
	Logger            log.FieldLogger

	ln net.Listener
}

func (c *ReverseTunnel) Close() {
	c.ln.Close()
	c.Client.Close()
}

func (c *ReverseTunnel) Listener() net.Listener {
	return c.ln
}

func (c *ReverseTunnel) Establish(ctx context.Context) (*server.CreateSessionResponse, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	var (
		auths          []ssh.AuthMethod
		publicKeys     [][]byte
		authorizedKeys [][]byte
	)
	for _, signer := range c.Signers {
		auths = append(auths, ssh.PublicKeys(signer))
		publicKeys = append(publicKeys, ssh.MarshalAuthorizedKey(signer.PublicKey()))
	}
	for _, ak := range c.AuthorizedKeys {
		authorizedKeys = append(authorizedKeys, ssh.MarshalAuthorizedKey(ak))
	}

	id := &api.Identifier{
		Id:   user.Username,
		Type: api.Identifier_HOST,
	}
	encodedID, err := api.EncodeIdentifier(id)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:          encodedID,
		Auth:          auths,
		ClientVersion: upterm.HostSSHClientVersion,
		// Enforce a restricted set of algorithms for security
		// TODO: make this configurable if necessary
		HostKeyAlgorithms: []string{
			ssh.CertAlgoED25519v01,
			ssh.CertAlgoRSASHA512v01,
			ssh.CertAlgoRSASHA256v01,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
		},
		HostKeyCallback: c.HostKeyCallback,
	}

	if isWSScheme(c.Host.Scheme) {
		u, _ := url.Parse(c.Host.String()) // clone
		u.User = url.UserPassword(encodedID, "")
		c.Client, err = ws.NewSSHClient(u, config, false)
	} else {
		c.Client, err = ssh.Dial("tcp", c.Host.Host, config)
	}

	if err != nil {
		return nil, sshDialError(c.Host.String(), err)
	}

	sessResp, err := c.createSession(user.Username, publicKeys, authorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	c.ln, err = c.Client.Listen("unix", sessResp.SessionID)
	if err != nil {
		return nil, fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

	// make sure connection is alive
	go keepAlive(ctx, c.KeepAliveDuration, func() {
		// TODO: ping with session ID
		_, _, err := c.Client.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		if err != nil {
			c.Logger.WithError(err).Error("error pinging server")
		}
	})

	return sessResp, nil
}

func (c *ReverseTunnel) createSession(user string, hostPublicKeys [][]byte, clientAuthorizedKeys [][]byte) (*server.CreateSessionResponse, error) {
	req := &server.CreateSessionRequest{
		HostUser:             user,
		HostPublicKeys:       hostPublicKeys,
		ClientAuthorizedKeys: clientAuthorizedKeys,
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	ok, body, err := c.Client.SendRequest(upterm.ServerCreateSessionRequestType, true, b)
	if err != nil {
		return nil, fmt.Errorf("error initializing session: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("could not initialize session: %s", body)
	}

	var resp server.CreateSessionResponse
	if err := proto.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshaling created session: %w", err)
	}

	return &resp, nil
}

func keepAlive(ctx context.Context, d time.Duration, fn func()) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

func isWSScheme(scheme string) bool {
	return scheme == "ws" || scheme == "wss"
}

type PermissionDeniedError struct {
	host string
	err  error
}

func (e *PermissionDeniedError) Error() string {
	return fmt.Sprintf("%s: Permission denied (publickey).", e.host)
}

func (e *PermissionDeniedError) Unwrap() error { return e.err }

func sshDialError(host string, err error) error {
	if strings.Contains(err.Error(), publickeyAuthError) {
		return &PermissionDeniedError{
			host: host,
			err:  err,
		}
	}

	return fmt.Errorf("ssh dial error: %w", err)
}
