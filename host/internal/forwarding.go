package internal

import (
	"net"
	"slices"
	"strconv"
	"sync"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

type forwardingPresenceKey struct{}

// maxForwardDestinations bounds the destinations a jump lists. Past it the
// connection's forwards are counted rather than listed, so a guest opening
// forwards to one address after another cannot grow the session's answer
// without limit.
const maxForwardDestinations = 16

// forwardingPresence is one guest connection's forwarding: the presence it
// publishes once, at its first accepted forward, and where its forwards go.
// Installed on every connection before authentication.
type forwardingPresence struct {
	once sync.Once

	mu       sync.Mutex
	dests    []string
	unlisted uint32
}

// opened records an accepted forward to dest.
func (p *forwardingPresence) opened(dest string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case slices.Contains(p.dests, dest):
	case len(p.dests) < maxForwardDestinations:
		p.dests = append(p.dests, dest)
	default:
		p.unlisted++
	}
}

// describe sets c's destinations to what the connection has opened so far.
func (p *forwardingPresence) describe(c *api.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.ForwardDestinations = slices.Clone(p.dests)
	c.UnlistedForwards = p.unlisted
}

// Forwards is where a session's jumps go: each forwarding client's
// destinations, by client ID, for as long as its connection lasts. The
// forwarding handler writes it as forwards are accepted, and GetSession reads
// it, rather than either going through the client events: those are delivered
// on separate channels, so a later destination could be applied after its
// client's departure and bring it back. The zero value is ready to use.
type Forwards struct {
	mu   sync.Mutex
	byID map[string]*forwardingPresence
}

func (f *Forwards) add(id string, p *forwardingPresence) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byID == nil {
		f.byID = make(map[string]*forwardingPresence)
	}
	f.byID[id] = p
}

func (f *Forwards) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byID, id)
}

// describe returns clients with each forwarding client's destinations filled
// in, on a copy: the repo's own are shared with whoever else was handed them.
func (f *Forwards) describe(clients []*api.Client) []*api.Client {
	if f == nil {
		return clients
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*api.Client, len(clients))
	for i, c := range clients {
		p, ok := f.byID[c.GetId()]
		if c.GetKind() != api.Client_FORWARD || !ok {
			out[i] = c
			continue
		}
		c = proto.Clone(c).(*api.Client)
		p.describe(c)
		out[i] = c
	}
	return out
}

// forwardDestination is where a direct-tcpip channel asks to go, as host:port,
// or "" for a request that cannot be read (which the library refuses anyway).
func forwardDestination(ch ssh.NewChannel) string {
	var req struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(ch.ExtraData(), &req); err != nil {
		return ""
	}
	return net.JoinHostPort(req.DestAddr, strconv.FormatUint(uint64(req.DestPort), 10))
}

// Observe acceptance rather than permission: the library checks permission
// before dialing the target, and either the dial or channel acceptance can fail.
// Keep its protocol handling and proxy implementation intact.
func forwardingHandler(events *emitter.Emitter, forwards *Forwards) gssh.ChannelHandler {
	return func(srv *gssh.Server, conn *ssh.ServerConn, channel ssh.NewChannel, ctx gssh.Context) {
		presence, ok := ctx.Value(forwardingPresenceKey{}).(*forwardingPresence)
		if !ok || presence == nil {
			_ = channel.Reject(ssh.ConnectionFailed, "forwarding connection metadata unavailable")
			return
		}
		guest, ok := ctx.Value(authenticatedGuestKey{}).(authenticatedGuest)
		if !ok || guest.auth == nil || guest.key == nil {
			_ = channel.Reject(ssh.ConnectionFailed, "forwarding connection metadata unavailable")
			return
		}
		dest := forwardDestination(channel)

		gssh.DirectTCPIPHandler(srv, conn, &forwardingChannel{NewChannel: channel, accepted: func() {
			if dest != "" {
				presence.opened(dest)
			}
			presence.once.Do(func() {
				id := clientEventID(ctx.SessionID())
				// Registered before the join is emitted, so a reader that
				// sees the client sees where it goes.
				if forwards != nil {
					forwards.add(id, presence)
				}
				client := &api.Client{
					Id: id, Version: guest.auth.ClientVersion, Addr: guest.auth.RemoteAddr,
					PublicKeyFingerprint: utils.FingerprintSHA256(guest.key), Kind: api.Client_FORWARD,
				}
				presence.describe(client)
				events.Emit(upterm.EventForwardingClientJoined, client)
				// Presence belongs to the SSH transport, including gaps between forwards.
				// The lifecycle consumer reconciles a left delivered before its join.
				go func() {
					<-ctx.Done()
					// The departure carries the jump as it ended, so the leave
					// callback names every destination, not the join's first.
					// A copy: the joined client is shared with the repo's
					// readers. Emitted before the registry forgets it, so a
					// session info in between still sees the destinations.
					final := proto.Clone(client).(*api.Client)
					presence.describe(final)
					events.Emit(upterm.EventClientLeft, id, final)
					if forwards != nil {
						forwards.remove(id)
					}
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
