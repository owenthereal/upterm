package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/consent"
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

type forwardingPolicy struct {
	ReadOnly, Disabled, AllowAny, AllowLoopback bool
	Checker                                     consent.PermissionChecker
}

// The address and decimal port form the complete consent subject, and the same
// tuple is used by the dial. Never resolve names to qualify for loopback trust.
func authorizeForward(ctx context.Context, p forwardingPolicy, client consent.ClientInfo, address string, port uint32) error {
	if p.ReadOnly {
		return fmt.Errorf("upterm: this session is read-only, so it doesn't allow port forwarding")
	}
	if p.Disabled {
		return fmt.Errorf("upterm: port forwarding is disabled for this session")
	}
	if port == 0 || port > 65535 || address == "" || strings.ContainsRune(address, 0) {
		return fmt.Errorf("invalid forwarding destination")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.AllowAny {
		return nil
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsLoopback() {
		return fmt.Errorf("upterm: forwarding requires a literal loopback IP address")
	}
	if p.AllowLoopback {
		return nil
	}
	if p.Checker == nil {
		return consent.ErrUnavailable
	}
	decision, err := p.Checker.CheckPermission(ctx, consent.OpForward, client, address, strconv.FormatUint(uint64(port), 10))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if decision != consent.AllowConnection && decision != consent.AllowGuest {
		return consent.ErrDenied
	}
	return nil
}

// Boundary records cover grants and denials that never reach a consent manager,
// including custom checkers. Manager records retain their own review identities;
// requestID identifies this open even when no review exists or a grant is cached.
func logForwardPermission(logger *slog.Logger, client consent.ClientInfo, requestID, address string, port uint32, err error) {
	outcome := "allowed"
	switch {
	case errors.Is(err, consent.ErrUnavailable):
		outcome = "unavailable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, consent.ErrTimeout):
		outcome = "timeout"
	case errors.Is(err, context.Canceled), errors.Is(err, consent.ErrCanceled):
		outcome = "canceled"
	case errors.Is(err, consent.ErrOverloaded):
		outcome = "overloaded"
	case errors.Is(err, consent.ErrStale):
		outcome = "stale"
	case errors.Is(err, consent.ErrSubjectTooLarge):
		outcome = "subject_too_large"
	case err != nil:
		outcome = "denied"
	}
	reason := ""
	if err != nil {
		reason = forwardLogText(err.Error())
	}
	logger.Info("forwarding permission policy", "outcome", outcome,
		"capability", consent.CapabilityForward, "operation", consent.OpForward,
		"subjects", []string{forwardLogText(address), forwardLogText(strconv.FormatUint(uint64(port), 10))},
		"fingerprint", forwardLogText(client.Fingerprint), "connection_id", forwardLogText(client.ConnectionID),
		"request_id", forwardLogText(requestID), "reason", reason)
}

func forwardLogText(text string) string {
	if len(text) > 256 {
		text = text[:256] + "..."
	}
	return strconv.QuoteToASCII(text)
}

// Pending opens have no per-channel CLOSE notification until acceptance. The
// arrival deadline bounds consent and dial; accepted traffic retains only the
// original transport and host lifetime.
func forwardingHandler(events *emitter.Emitter, forwards *Forwards, policy forwardingPolicy, hostCtx context.Context, logger *slog.Logger) gssh.ChannelHandler {
	if logger == nil {
		logger = slog.Default()
	}
	var requestSequence atomic.Uint64
	return func(_ *gssh.Server, _ *ssh.ServerConn, channel ssh.NewChannel, ctx gssh.Context) {
		arrived := time.Now()
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
		var req struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(channel.ExtraData(), &req); err != nil {
			_ = channel.Reject(ssh.ConnectionFailed, "invalid forwarding request")
			return
		}
		transferCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stopHost := context.AfterFunc(hostCtx, cancel)
		defer stopHost()
		if hostCtx.Err() != nil {
			cancel()
		}
		openCtx, cancelOpen := context.WithDeadline(transferCtx, arrived.Add(consent.PermissionTimeout))
		defer cancelOpen()
		// Cancellation propagation through an SSH context can be asynchronous.
		// Recheck the original owners synchronously at every side-effect boundary.
		openError := func() error {
			for _, parent := range []context.Context{ctx, hostCtx, openCtx} {
				if err := parent.Err(); err != nil {
					return err
				}
			}
			if deadline, ok := openCtx.Deadline(); ok && !time.Now().Before(deadline) {
				return context.DeadlineExceeded
			}
			return nil
		}
		client := consent.ClientInfo{ConnectionID: ctx.SessionID(), Fingerprint: utils.FingerprintSHA256(guest.key)}
		requestID := "forward-" + strconv.FormatUint(requestSequence.Add(1), 10)
		permissionErr := openError()
		if permissionErr == nil {
			permissionErr = authorizeForward(openCtx, policy, client, req.DestAddr, req.DestPort)
		}
		if permissionErr == nil {
			permissionErr = openError()
		}
		logForwardPermission(logger, client, requestID, req.DestAddr, req.DestPort, permissionErr)
		if permissionErr != nil {
			_ = channel.Reject(ssh.Prohibited, permissionErr.Error())
			return
		}
		dest := net.JoinHostPort(req.DestAddr, strconv.FormatUint(uint64(req.DestPort), 10))
		dialer := net.Dialer{Timeout: 10 * time.Second}
		// A host-supplied audit sink can block or observe cancellation itself.
		// Preserve the original-owner check immediately before dialing.
		if err := openError(); err != nil {
			logForwardPermission(logger, client, requestID, req.DestAddr, req.DestPort, err)
			_ = channel.Reject(ssh.Prohibited, err.Error())
			return
		}
		socket, err := dialer.DialContext(openCtx, "tcp", dest)
		if err != nil {
			_ = channel.Reject(ssh.ConnectionFailed, err.Error())
			return
		}
		defer func() { _ = socket.Close() }()
		if err := openError(); err != nil {
			_ = channel.Reject(ssh.Prohibited, err.Error())
			return
		}
		stream, requests, err := channel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = stream.Close() }()
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
		cancelOpen()
		// Close both endpoints on either transport loss or host shutdown. This also
		// unblocks copies whose peer stopped reading, and joins every worker below.
		stopCopies := context.AfterFunc(transferCtx, func() { _ = socket.Close(); _ = stream.Close() })
		defer stopCopies()
		requestsDone := make(chan struct{})
		var workers sync.WaitGroup
		workers.Go(func() {
			for {
				select {
				case request, ok := <-requests:
					if !ok {
						// Requests close on accepted channel CLOSE, not stdin EOF.
						cancel()
						return
					}
					if request.WantReply {
						_ = request.Reply(false, nil)
					}
				case <-requestsDone:
					return
				case <-transferCtx.Done():
					return
				}
			}
		})
		var copies sync.WaitGroup
		copies.Go(func() {
			_, _ = io.Copy(socket, stream)
			if tcp, ok := socket.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		})
		copies.Go(func() { _, _ = io.Copy(stream, socket); _ = stream.CloseWrite() })
		copies.Wait()
		close(requestsDone)
		// Close performs ordinary channel cleanup. If Reply holds the channel
		// write lock while blocked on transport output, Close can block too;
		// the bounded outer Host.Run/tunnel teardown owns transport closure.
		_ = stream.Close()
		workers.Wait()
	}
}
