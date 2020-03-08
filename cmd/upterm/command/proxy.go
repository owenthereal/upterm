package command

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/upterm"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
)

func proxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Proxy a terminal session over WebSocket",
		Long:  "Proxy a terminal session over WebSocket. This must be used in conjunction with SSH ProxyCommand.",
		Example: `  # The host shares a session by running $SHELL over WebSocket
  upterm host --server wss://uptermd.upterm.dev

  # Join the shared terminal session over WebSocket
  ssh -o ProxyCommand='upterm proxy wss://bpi81h5grkrhrmuogp3g:MTI3LjAuMC4xOjIyMjI=@uptermd.upterm.dev' uptermd.uptermd.dev`,
		RunE: proxyRunE,
	}

	return cmd
}

func proxyRunE(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing WebSocket url")
	}

	u, err := url.Parse(args[0])
	if err != nil {
		return err
	}

	auth := base64.StdEncoding.EncodeToString([]byte(u.User.String()))

	header := make(http.Header)
	header.Add("Authorization", "Basic "+auth)
	header.Add("Upterm-Client-Version", upterm.ClientSSHClientVersion)

	u.User = nil // remove user & pass from the URL because they are not supported in the WebSocket spec
	wsc, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return err
	}

	conn := server.WrapWSConn(wsc)

	var o sync.Once
	close := func() {
		conn.Close()
	}

	var g run.Group
	{
		g.Add(func() error {
			_, err := io.Copy(conn, os.Stdin)
			return err
		}, func(err error) {
			o.Do(close)
		})
	}
	{
		g.Add(func() error {
			_, err := io.Copy(os.Stdout, conn)
			return err
		}, func(err error) {
			o.Do(close)
		})
	}

	err = g.Run()
	fmt.Println(err)

	return err
}
