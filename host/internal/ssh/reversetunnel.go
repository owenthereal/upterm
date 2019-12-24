package ssh

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strings"
	"time"

	"github.com/jingweno/upterm/upterm"
	"github.com/jingweno/upterm/utils"
	"golang.org/x/crypto/ssh"
)

const (
	publickeyAuthError = "ssh: unable to authenticate, attempted methods [none]"
)

type ReverseTunnel struct {
	*ssh.Client

	Host      string
	SessionID string
	Signers   []ssh.Signer
	KeepAlive time.Duration

	ln net.Listener
}

func (c *ReverseTunnel) Close() {
	c.ln.Close()
	c.Client.Close()
}

func (c *ReverseTunnel) Listener() net.Listener {
	return c.ln
}

func (c *ReverseTunnel) Establish(ctx context.Context) error {
	user, err := user.Current()
	if err != nil {
		return err
	}

	var auths []ssh.AuthMethod
	for _, signer := range c.Signers {
		auths = append(auths, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:            user.Username,
		Auth:            auths,
		ClientVersion:   upterm.HostSSHClientVersion,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	c.Client, err = ssh.Dial("tcp", c.Host, config)
	if err != nil {
		return sshDialError(c.Host, err)
	}

	c.ln, err = c.Client.Listen("unix", c.SessionID)
	if err != nil {
		return fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

	// make sure connection is alive
	go utils.KeepAlive(ctx, c.KeepAlive*time.Second, func() {
		c.Client.SendRequest(upterm.ServerPingRequestType, true, nil)
	})

	return nil
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
