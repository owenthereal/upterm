package command

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/jingweno/upterm/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagServerHost         string
	flagServerHostKeys     []string
	flagServerUpstreamNode bool
	flagNetwork            string
	flagNetworkOpts        []string
)

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run server",
		RunE:  serverRunE,
	}

	cmd.PersistentFlags().StringVarP(&flagServerHost, "host", "", defaultHost("2222"), "host (required)")
	cmd.PersistentFlags().StringSliceVarP(&flagServerHostKeys, "host-key", "", nil, "host private key")
	cmd.PersistentFlags().BoolVarP(&flagServerUpstreamNode, "upstream-node", "", false, "indicate that the server is one of the upstream nodes")

	cmd.PersistentFlags().StringVarP(&flagNetwork, "network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceVarP(&flagNetworkOpts, "network-opt", "", nil, "network provider option")

	return cmd
}

func parseNetworkOpts(opts []string) server.NetworkOptions {
	result := make(server.NetworkOptions)
	for _, opt := range opts {
		split := strings.SplitN(opt, "=", 2)
		result[split[0]] = split[1]
	}

	return result
}

func serverRunE(c *cobra.Command, args []string) error {
	provider := server.Networks.Get(flagNetwork)
	if provider == nil {
		return fmt.Errorf("unsupport network provider %q", flagNetwork)
	}

	opts := parseNetworkOpts(flagNetworkOpts)
	if err := provider.SetOpts(opts); err != nil {
		return fmt.Errorf("network provider option error: %s", err)
	}

	logger := log.New().WithFields(log.Fields{
		"host": flagServerHost,
	})
	logger.WithFields(log.Fields{"network": provider.Name(), "network-opts": provider.Opts()}).Infof("using network provider %s", provider.Name())

	privateKeys, err := readFiles(flagServerHostKeys)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", flagServerHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger.Info("starting server")

	s := &server.Server{
		NodeAddr:        flagServerHost,
		HostPrivateKeys: privateKeys,
		NetworkProvider: provider,
		UpstreamNode:    flagServerUpstreamNode,
		Logger:          logger,
	}

	return s.Serve(ln)
}

func defaultHost(defaultPort string) string {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	return fmt.Sprintf("127.0.0.1:%s", port)
}

func defaultHostAddr() string {
	if addr := os.Getenv("UPTERM_HOST_ADDR"); addr != "" {
		return addr
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			networkIp, ok := addr.(*net.IPNet)
			if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
				return networkIp.IP.String()
			}
		}
	}

	return "127.0.0.1"
}

func readFiles(paths []string) ([][]byte, error) {
	var privateKeys [][]byte
	for _, p := range paths {
		b, err := ioutil.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", p, err)
		}

		privateKeys = append(privateKeys, b)
	}

	return privateKeys, nil
}
