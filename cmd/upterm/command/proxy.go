package command

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/oklog/run"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/ws"
	"github.com/spf13/cobra"
)

func proxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Proxy a terminal session via WebSocket",
		Long:  "Proxy a terminal session via WebSocket, to be used alongside SSH ProxyCommand.",
		Example: `  # Host shares a session running $SHELL over WebSocket:
  upterm host --server wss://uptermd.upterm.dev -- YOUR_COMMAND

  # Client connects to the host session via WebSocket:
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var g run.Group
	{
		g.Add(func() error {
			_, err := io.Copy(conn, uio.NewContextReader(ctx, os.Stdin))
			return err
		}, func(err error) {
			conn.Close()
			cancel()
		})
	}
	{
		g.Add(func() error {
			_, err := io.Copy(os.Stdout, uio.NewContextReader(ctx, conn))
			return err
		}, func(err error) {
			conn.Close()
			cancel()
		})
	}

	return g.Run()
}
