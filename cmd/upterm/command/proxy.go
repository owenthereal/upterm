package command

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"

	"github.com/jingweno/upterm/ws"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
)

func proxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Proxy a terminal session over WebSocket",
		Long:  "Proxy a terminal session over WebSocket. This must be used in conjunction with SSH ProxyCommand.",
		Example: `  # The host shares a session by running $SHELL over WebSocket
  upterm host --server wss://uptermd.upterm.dev -- YOUR_COMMAND

  # A client connects to the host session via WebSocket
  ssh -o ProxyCommand='upterm proxy wss://TOKEN@uptermd.upterm.dev' TOKEN:uptermd.uptermd.dev:443`,
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

	conn, err := ws.NewWSConn(u, true)
	if err != nil {
		return err
	}

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

	return g.Run()
}
