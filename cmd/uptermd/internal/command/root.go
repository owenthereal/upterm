package command

import (
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagHost         string
	flagHostKeys     []string
	flagUpstreamNode bool
	flagNetwork      string
	flagNetworkOpts  []string
	flagMetricAddr   string
)

func Root(logger log.FieldLogger) *cobra.Command {
	rootCmd := &rootCmd{logger}
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm daemon",
		RunE:  rootCmd.Run,
	}

	cmd.PersistentFlags().StringVarP(&flagHost, "host", "", utils.DefaultLocalhost("2222"), "host (required)")
	cmd.PersistentFlags().StringSliceVarP(&flagHostKeys, "host-key", "", nil, "host private key")

	cmd.PersistentFlags().StringVarP(&flagNetwork, "network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceVarP(&flagNetworkOpts, "network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().StringVarP(&flagMetricAddr, "metric-addr", "", utils.DefaultLocalhost("8080"), "metric server address (required)")

	cmd.PersistentFlags().BoolVarP(&flagUpstreamNode, "upstream-node", "", false, "indicate that the server is one of the upstream nodes")
	_ = cmd.PersistentFlags().MarkHidden("upstream-node")

	return cmd
}

type rootCmd struct {
	logger log.FieldLogger
}

func (cmd *rootCmd) Run(c *cobra.Command, args []string) error {
	opt := server.ServerOpt{
		Addr:         flagHost,
		KeyFiles:     flagHostKeys,
		Network:      flagNetwork,
		NetworkOpt:   flagNetworkOpts,
		UpstreamNode: flagUpstreamNode,
		MetricAddr:   flagMetricAddr,
	}

	logger := cmd.logger.WithFields(log.Fields{
		"host":         flagHost,
		"metric-addr":  flagMetricAddr,
		"network":      flagNetwork,
		"network-opts": flagNetworkOpts,
	})
	logger.Info("starting server")
	defer logger.Info("shutting down sterver")

	return server.StartServer(opt)
}
