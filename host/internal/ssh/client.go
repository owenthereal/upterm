package ssh

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strings"
	"time"

	"github.com/jingweno/upterm/utils"
	"golang.org/x/crypto/ssh"
)

const (
	publickeyAuthError = "ssh: unable to authenticate, attempted methods [none]"
)

type Client struct {
	*ssh.Client

	Host      string
	SessionID string
	Auths     []ssh.AuthMethod
	KeepAlive time.Duration

	ln net.Listener
}

func (c *Client) Close() {
	c.ln.Close()
	c.Client.Close()
}

func (c *Client) ReverseTunnel(ctx context.Context) (net.Listener, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            user.Username,
		Auth:            c.Auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	c.Client, err = ssh.Dial("tcp", c.Host, config)
	if err != nil {
		return nil, sshDialError(c.Host, err)
	}

	c.ln, err = c.Client.Listen("unix", utils.SocketFile(c.SessionID))
	if err != nil {
		return nil, fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

	// make sure connection is alive
	go utils.KeepAlive(ctx, c.KeepAlive*time.Second, func() {
		c.Client.SendRequest("ping", true, nil)
	})

	return c.ln, nil
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
