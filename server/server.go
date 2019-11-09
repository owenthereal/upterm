package server

import (
	"github.com/jingweno/ssh"
	log "github.com/sirupsen/logrus"
)

func New(host, socketDir string, logger log.FieldLogger) *Server {
	return &Server{
		host:      host,
		socketDir: socketDir,
		logger:    logger,
	}
}

type Server struct {
	host      string
	socketDir string
	logger    log.FieldLogger
}

func (s *Server) ListenAndServe() error {
	sh := newStreamlocalForwardHandler(s.socketDir, s.logger.WithField("handler", "streamlocalForwardHandler"))
	ph := newSSHProxyHandler(s.socketDir, s.logger.WithField("handler", "sshProxyHandler"))

	server := ssh.Server{
		Addr:    s.host,
		Handler: ph.Handler,
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			s.logger.WithFields(log.Fields{"tunnel-host": host, "tunnel-port": port}).Info("attempt to bind")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			streamlocalForwardChannelType:      sh.Handler,
			cancelStreamlocalForwardChanneType: sh.Handler,
		},
	}

	return server.ListenAndServe()
}
