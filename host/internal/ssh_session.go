package internal

import (
	gssh "charm.land/ssh"
	"golang.org/x/crypto/ssh"
)

// rawSessionHandler keeps the SSH library's PTY request and window handling,
// but sends output directly to the channel. Upterm already owns a real PTY;
// the library's emulated PTY writer would turn LF into CRLF a second time,
// breaking cursor positioning in programs such as GNU Screen (#288, #278).
func rawSessionHandler(srv *gssh.Server, conn *ssh.ServerConn, newChan ssh.NewChannel, ctx gssh.Context) {
	channel := &sessionChannel{NewChannel: newChan}
	// These are the fields DefaultSessionHandler reads in charm.land/ssh v0.4.3;
	// recheck them when upgrading the dependency. Build this configuration per
	// channel so the captured output cannot leak to another session on the same
	// connection, and do not copy the running server's mutexes.
	sessionServer := &gssh.Server{
		Handler: func(sess gssh.Session) {
			srv.Handler(&rawSession{Session: sess, channel: channel.channel})
		},
		PtyCallback:            srv.PtyCallback,
		PtyHandler:             srv.PtyHandler,
		SessionRequestCallback: srv.SessionRequestCallback,
		SubsystemHandlers:      srv.SubsystemHandlers,
	}
	gssh.DefaultSessionHandler(sessionServer, conn, channel, ctx)
}

// Capture the underlying channel when DefaultSessionHandler accepts it.
type sessionChannel struct {
	ssh.NewChannel
	channel ssh.Channel
}

func (c *sessionChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	channel, requests, err := c.NewChannel.Accept()
	c.channel = channel
	return channel, requests, err
}

type rawSession struct {
	gssh.Session
	channel ssh.Channel
}

func (s *rawSession) Write(p []byte) (int, error) {
	return s.channel.Write(p)
}
