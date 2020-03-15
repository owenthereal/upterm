package command

import (
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagSSHAddr     string
	flagWSAddr      string
	flagPrivateKeys []string
	flagNetwork     string
	flagNetworkOpts []string
	flagMetricAddr  string
)

func Root(logger log.FieldLogger) *cobra.Command {
	rootCmd := &rootCmd{logger}
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm daemon",
		RunE:  rootCmd.Run,
	}

	cmd.PersistentFlags().StringVarP(&flagSSHAddr, "ssh-addr", "", "", "ssh server address")
	cmd.PersistentFlags().StringVarP(&flagWSAddr, "ws-addr", "", "", "websocket server address")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "", nil, "server private key")

	cmd.PersistentFlags().StringVarP(&flagNetwork, "network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceVarP(&flagNetworkOpts, "network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().StringVarP(&flagMetricAddr, "metric-addr", "", utils.DefaultLocalhost("9090"), "metric server address (required)")

	return cmd
}

type rootCmd struct {
	logger log.FieldLogger
}

func (cmd *rootCmd) Run(c *cobra.Command, args []string) error {
	if flagSSHAddr == "" && flagWSAddr == "" {
		flagSSHAddr = utils.DefaultLocalhost("2222")
	}

	opt := server.Opt{
		SSHAddr:    flagSSHAddr,
		WSAddr:     flagWSAddr,
		KeyFiles:   flagPrivateKeys,
		Network:    flagNetwork,
		NetworkOpt: flagNetworkOpts,
		MetricAddr: flagMetricAddr,
	}

	logger := cmd.logger.WithFields(log.Fields{
		"ssh-host":     flagSSHAddr,
		"ws-host":      flagWSAddr,
		"metric-addr":  flagMetricAddr,
		"network":      flagNetwork,
		"network-opts": flagNetworkOpts,
	})
	logger.Info("starting server")
	defer logger.Info("shutting down sterver")

	return server.Start(opt)
}
