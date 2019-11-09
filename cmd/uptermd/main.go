package main

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	"github.com/jingweno/upterm"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagPort      int
	flagSocketDir string

	rootCmd = &cobra.Command{
		Use:  "uptermd",
		RunE: run,
	}

	logger *log.Logger
)

func init() {
	rootCmd.PersistentFlags().IntVarP(&flagPort, "port", "p", 22, "port")
	rootCmd.PersistentFlags().StringVarP(&flagSocketDir, "socket-dir", "d", "/tmp", "the directory to create reverse Unix sockets")
	logger = log.New()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	tcph := &ssh.ForwardedTCPHandler{}
	uh := upterm.NewForwardedUnixHandler(flagSocketDir, logger.WithField("struct", "SSHForwardedUnixHandler"))
	h := upterm.NewSSHProxyHandler(flagSocketDir, logger.WithField("struct", "SSHProxyHandler"))

	server := ssh.Server{
		Addr:    fmt.Sprintf(":%d", flagPort),
		Handler: ssh.Handler(h.Handle),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			// TODO: restrict port range
			logger.WithFields(log.Fields{"host": host, "port": port}).Info("attemt to bind")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":                          tcph.HandleSSHRequest,
			"cancel-tcpip-forward":                   tcph.HandleSSHRequest,
			"streamlocal-forward@openssh.com":        uh.HandleSSHRequest,
			"cancel-streamlocal-forward@openssh.com": uh.HandleSSHRequest,
		},
	}

	logger.WithField("port", flagPort).Info("starting ssh server")
	return server.ListenAndServe()
}
