package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/user"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	publickeyAuthError = "ssh: unable to authenticate, attempted methods [none]"
)

type ReverseTunnel struct {
	*ssh.Client

	Host      *url.URL
	SessionID string
	Signers   []ssh.Signer
	KeepAlive time.Duration
	Logger    log.FieldLogger

	ln net.Listener
}

func (c *ReverseTunnel) Close() {
	c.ln.Close()
	c.Client.Close()
}

func (c *ReverseTunnel) Listener() net.Listener {
	return c.ln
}

func (c *ReverseTunnel) Establish(ctx context.Context) (*server.ServerInfo, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	var auths []ssh.AuthMethod
	for _, signer := range c.Signers {
		auths = append(auths, ssh.PublicKeys(signer))
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
		User:            encodedID,
		Auth:            auths,
		ClientVersion:   upterm.HostSSHClientVersion,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if c.Host.Scheme == "ws" || c.Host.Scheme == "wss" {
		auth := base64.StdEncoding.EncodeToString([]byte(encodedID + ":"))
		header := make(http.Header)
		header.Add("Authorization", "Basic "+auth)
		header.Add("Upterm-Client-Version", upterm.HostSSHClientVersion)
		wsc, _, err := websocket.DefaultDialer.Dial(c.Host.String(), header)
		if err != nil {
			return nil, err
		}
		// pass in addr without shceme for ssh
		cc, chans, reqs, err := ssh.NewClientConn(server.WrapWSConn(wsc), c.Host.Host, config)
		if err != nil {
			return nil, err
		}
		c.Client = ssh.NewClient(cc, chans, reqs)
	} else {
		c.Client, err = ssh.Dial("tcp", c.Host.Host, config)
	}

	if err != nil {
		return nil, sshDialError(c.Host.String(), err)
	}

	c.ln, err = c.Client.Listen("unix", c.SessionID)
	if err != nil {
		return nil, fmt.Errorf("unable to create reverse tunnel: %w", err)
	}

	// make sure connection is alive
	go keepAlive(ctx, c.KeepAlive*time.Second, func() {
		_, _, err := c.Client.SendRequest(upterm.ServerPingRequestType, true, nil)
		if err != nil {
			c.Logger.WithError(err).Error("error pinging server")
		}
	})

	return c.serverInfo()
}

func (c *ReverseTunnel) serverInfo() (*server.ServerInfo, error) {
	ok, body, err := c.Client.SendRequest(upterm.ServerServerInfoRequestType, true, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching server info: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("error fetching server info")
	}
	var info *server.ServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("error unmarshaling server info: %w", err)
	}

	return info, nil
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
