package command

import (
	"net"

	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagRouterHost         string
	flagRouterUpstreamHost string
	flagRouterHostKeys     []string
)

func routerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "router",
		Short: "Router daemon",
		RunE:  routerRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagRouterHost, "host", "", defaultHost("2223"), "host (required)")
	cmd.PersistentFlags().StringVarP(&flagRouterUpstreamHost, "upstream-host", "", defaultHost("2222"), "host (required)")
	cmd.PersistentFlags().StringSliceVarP(&flagRouterHostKeys, "host-key", "", nil, "host private key")

	return cmd
}

func routerRunE(c *cobra.Command, args []string) error {
	logger := log.New().WithFields(log.Fields{
		"host": flagRouterHost,
	})

	privateKeys, err := readFiles(flagRouterHostKeys)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", flagRouterHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger.Info("starting server")

	signers, err := utils.CreateSigners(privateKeys)
	if err != nil {
		return err
	}

	router := &server.GlobalRouter{
		HostSigners:  signers,
		UpstreamHost: flagRouterUpstreamHost,
		Logger:       log.New().WithField("app", "router"),
	}

	return router.Serve(ln)
}
