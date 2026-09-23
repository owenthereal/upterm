package internal

import (
	"sync"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

type forwardingPresenceKey struct{}

// Observe acceptance rather than permission: the library checks permission
// before dialing the target, and either the dial or channel acceptance can fail.
// Keep its protocol handling and proxy implementation intact.
func forwardingHandler(events *emitter.Emitter) gssh.ChannelHandler {
	return func(srv *gssh.Server, conn *ssh.ServerConn, channel ssh.NewChannel, ctx gssh.Context) {
		gssh.DirectTCPIPHandler(srv, conn, &forwardingChannel{NewChannel: channel, accepted: func() {
			once := ctx.Value(forwardingPresenceKey{}).(*sync.Once)
			once.Do(func() {
				guest := ctx.Value(authenticatedGuestKey{}).(authenticatedGuest)
				id := clientEventID(ctx.SessionID())
				events.Emit(upterm.EventForwardingClientJoined, &api.Client{
					Id: id, Version: guest.auth.ClientVersion, Addr: guest.auth.RemoteAddr,
					PublicKeyFingerprint: utils.FingerprintSHA256(guest.key), Kind: api.Client_GUEST,
				})
				// Presence belongs to the SSH transport, including gaps between forwards.
				// The lifecycle consumer reconciles a left delivered before its join.
				go func() {
					<-ctx.Done()
					emitClientLeftEvent(events, id)
				}()
			})
		}}, ctx)
	}
}

type forwardingChannel struct {
	ssh.NewChannel
	accepted func()
}

func (c *forwardingChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	channel, requests, err := c.NewChannel.Accept()
	if err == nil {
		c.accepted()
	}
	return channel, requests, err
}
