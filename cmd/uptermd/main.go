package main

import (
	"net"

	"github.com/jingweno/upterm/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagHost      string
	flagSocketDir string

	rootCmd = &cobra.Command{
		Use:  "uptermd",
		RunE: run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", "127.0.0.1:2222", "host")
	rootCmd.PersistentFlags().StringVarP(&flagSocketDir, "socket-dir", "", "/tmp", "directory to put reverse Unix sockets")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	logger := log.New()

	ln, err := net.Listen("tcp", flagHost)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger.WithFields(log.Fields{"host": flagHost, "socket-dir": flagSocketDir}).Info("starting ssh server")

	s := server.New(flagSocketDir, logger)
	return s.Serve(ln)
}
