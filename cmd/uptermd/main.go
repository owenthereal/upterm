package main

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagPort int

	rootCmd = &cobra.Command{
		Use:  "uptermd",
		RunE: run,
	}

	logger *log.Logger
)

func init() {
	rootCmd.PersistentFlags().IntVarP(&flagPort, "port", "p", 22, "port")
	logger = log.New()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	forwardHandler := &ssh.ForwardedTCPHandler{}

	server := ssh.Server{
		Addr: fmt.Sprintf(":%d", flagPort),
		Handler: ssh.Handler(func(s ssh.Session) {
			// Disable ssh
			s.Exit(1)
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			// TODO: restrict port range
			logger.WithFields(log.Fields{"host": host, "port": port}).Info("attemt to bind")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	logger.WithField("port", flagPort).Info("starting ssh server")
	return server.ListenAndServe()
}
