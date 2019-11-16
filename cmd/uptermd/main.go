package main

import (
	"fmt"
	"io/ioutil"
	"net"

	"github.com/jingweno/upterm/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	flagHost      string
	flagHostKeys  []string
	flagSocketDir string

	rootCmd = &cobra.Command{
		Use:  "uptermd",
		RunE: run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", "127.0.0.1:2222", "host")
	rootCmd.PersistentFlags().StringSliceVarP(&flagHostKeys, "host-key", "", nil, "host private key")
	rootCmd.PersistentFlags().StringVarP(&flagSocketDir, "socket-dir", "", "/tmp", "directory to put reverse Unix sockets")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	logger := log.New()

	var privates []ssh.Signer
	for _, k := range flagHostKeys {
		privateBytes, err := ioutil.ReadFile(k)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		privates = append(privates, private)
	}

	ln, err := net.Listen("tcp", flagHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger.WithFields(log.Fields{"host": flagHost, "socket-dir": flagSocketDir}).Info("starting ssh server")

	s := server.New(privates, flagSocketDir, logger)
	return s.Serve(ln)
}
