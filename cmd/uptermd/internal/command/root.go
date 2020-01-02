package command

import (
	"fmt"
	"net"
	"strings"

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
)

func Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm daemon",
		RunE:  rootRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagHost, "host", "", utils.DefaultLocalhost("2222"), "host (required)")
	cmd.PersistentFlags().StringSliceVarP(&flagHostKeys, "host-key", "", nil, "host private key")

	cmd.PersistentFlags().StringVarP(&flagNetwork, "network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceVarP(&flagNetworkOpts, "network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().BoolVarP(&flagUpstreamNode, "upstream-node", "", false, "indicate that the server is one of the upstream nodes")
	_ = cmd.PersistentFlags().MarkHidden("upstream-node")

	return cmd
}

func rootRunE(c *cobra.Command, args []string) error {
	provider := server.Networks.Get(flagNetwork)
	if provider == nil {
		return fmt.Errorf("unsupport network provider %q", flagNetwork)
	}

	opts := parseNetworkOpts(flagNetworkOpts)
	if err := provider.SetOpts(opts); err != nil {
		return fmt.Errorf("network provider option error: %s", err)
	}

	logger := log.New().WithFields(log.Fields{
		"host": flagHost,
	})
	logger.WithFields(log.Fields{
		"network":      provider.Name(),
		"network-opts": provider.Opts(),
	}).Infof("using network provider %s", provider.Name())

	signers, err := utils.CreateSignersFromFiles(flagHostKeys)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", flagHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	s := &server.Server{
		HostSigners:     signers,
		NodeAddr:        flagHost,
		NetworkProvider: provider,
		UpstreamNode:    flagUpstreamNode,
		Logger:          log.New().WithField("app", "uptermd"),
	}

	logger.Info("starting server")
	return s.Serve(ln)
}

func parseNetworkOpts(opts []string) server.NetworkOptions {
	result := make(server.NetworkOptions)
	for _, opt := range opts {
		split := strings.SplitN(opt, "=", 2)
		result[split[0]] = split[1]
	}

	return result
}
