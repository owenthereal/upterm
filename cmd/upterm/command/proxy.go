package command

import (
	"context"
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
		Use:   "proxy [flags] URL",
		Short: "Proxy a terminal session via WebSocket",
		Long: `Carry ssh's connection to a session over a WebSocket, as its ProxyCommand:
the SSH line of a host on a ws:// or wss:// relay runs it.

URL is the ws:// or wss:// URL in the ProxyCommand of the host's SSH line.
upterm join is the simpler way to join such a session: it takes the
connect string on the host's Join line, and needs no ssh options.

Exit status: 0 when ssh closes the connection; 1 when it can't reach the
relay, or the relay closes it.`,
		Example: `  # A host shares a session over a WebSocket:
  upterm host --server wss://uptermd.upterm.dev

  # A guest joins with the SSH line the host prints, which runs upterm proxy:
  ssh -o ProxyCommand='upterm proxy wss://ID@uptermd.upterm.dev' ID@uptermd.upterm.dev:443

  # The simpler way:
  upterm join wss://ID@uptermd.upterm.dev`,
		Args: cobra.ExactArgs(1),
		RunE: proxyRunE,
	}

	cmd.Flags().StringVar(&flagProxy, "proxy", "", "HTTP proxy to reach the relay through (e.g. http://proxy.example.com:3128). Without it, HTTPS_PROXY/HTTP_PROXY are used.")

	return cmd
}

func proxyRunE(c *cobra.Command, args []string) error {
	u, err := url.Parse(args[0])
	if err != nil {
		return err
	}

	proxyURL, err := parseProxyURL(flagProxy)
	if err != nil {
		return err
	}

	conn, err := ws.NewWSConn(u, true, proxyURL)
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
			_ = conn.Close()
			cancel()
		})
	}
	{
		g.Add(func() error {
			_, err := io.Copy(os.Stdout, uio.NewContextReader(ctx, conn))
			return err
		}, func(err error) {
			_ = conn.Close()
			cancel()
		})
	}

	return g.Run()
}
