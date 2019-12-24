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
	flagHost        string
	flagHostKeys    []string
	flagNetwork     string
	flagNetworkOpts []string
)

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm daemon",
		RunE:  rootRunE,
	}

	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", defaultHost("2222"), "host (required)")
	rootCmd.PersistentFlags().StringSliceVarP(&flagHostKeys, "host-key", "", nil, "host private key")

	rootCmd.PersistentFlags().StringVarP(&flagNetwork, "network", "", "mem", "network provider used to communicate between components")
	rootCmd.PersistentFlags().StringSliceVarP(&flagNetworkOpts, "network-opt", "", nil, "network provider option")

	return rootCmd
}

func parseNetworkOpts(opts []string) server.NetworkOptions {
	result := make(server.NetworkOptions)
	for _, opt := range opts {
		split := strings.SplitN(opt, "=", 2)
		result[split[0]] = split[1]
	}

	return result
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

	privateKeys, err := readFiles(flagHostKeys)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", flagHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger := log.New().WithFields(log.Fields{
		"host":         flagHost,
		"network":      provider.Name(),
		"network-opts": provider.Opts(),
	})
	logger.Info("starting server")

	s := &server.Server{
		HostPrivateKeys: privateKeys,
		NetworkProvider: provider,
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