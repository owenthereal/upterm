package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type forwardingTestContext struct {
	gssh.Context
	values map[any]any
}

func (c forwardingTestContext) Value(key any) any { return c.values[key] }

type rejectingForwardingChannel struct {
	ssh.NewChannel
	extraDataCalls int
	acceptCalls    int
	rejectReason   ssh.RejectionReason
	rejectMessage  string
}

func (c *rejectingForwardingChannel) ExtraData() []byte {
	c.extraDataCalls++
	return ssh.Marshal(&struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{"127.0.0.1", 22, "127.0.0.1", 1})
}

func (c *rejectingForwardingChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	c.acceptCalls++
	return nil, nil, errors.New("unexpected Accept")
}

func (c *rejectingForwardingChannel) Reject(reason ssh.RejectionReason, message string) error {
	c.rejectReason = reason
	c.rejectMessage = message
	return nil
}

func TestForwardingRejectsMissingConnectionMetadata(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	validGuest := authenticatedGuest{auth: &server.AuthRequest{}, key: key}

	tests := []struct {
		name    string
		corrupt func(map[any]any)
	}{
		{"missing presence state", func(values map[any]any) { delete(values, forwardingPresenceKey{}) }},
		{"wrong presence state", func(values map[any]any) { values[forwardingPresenceKey{}] = "wrong" }},
		{"typed nil presence state", func(values map[any]any) { values[forwardingPresenceKey{}] = (*forwardingPresence)(nil) }},
		{"missing guest", func(values map[any]any) { delete(values, authenticatedGuestKey{}) }},
		{"wrong guest", func(values map[any]any) { values[authenticatedGuestKey{}] = "wrong" }},
		{"guest without auth", func(values map[any]any) { values[authenticatedGuestKey{}] = authenticatedGuest{key: key} }},
		{"guest without key", func(values map[any]any) {
			values[authenticatedGuestKey{}] = authenticatedGuest{auth: &server.AuthRequest{}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presence := &forwardingPresence{}
			values := map[any]any{forwardingPresenceKey{}: presence, authenticatedGuestKey{}: validGuest}
			tt.corrupt(values)
			ctx := forwardingTestContext{values: values}
			channel := &rejectingForwardingChannel{}
			events := emitter.New(1)
			joined := events.On(upterm.EventForwardingClientJoined)
			permissionCalls := 0
			srv := &gssh.Server{LocalPortForwardingCallback: func(gssh.Context, string, uint32) bool {
				permissionCalls++
				return false // A mistaken delegation still cannot dial a target.
			}}

			forwardingHandler(events, &Forwards{}, forwardingPolicy{}, context.Background(), context.Background(), discardLogger())(srv, nil, channel, ctx)

			require.Equal(t, ssh.ConnectionFailed, channel.rejectReason)
			require.Contains(t, channel.rejectMessage, "metadata")
			require.Zero(t, channel.extraDataCalls, "library handler must not run")
			require.Zero(t, permissionCalls, "forwarding permission must not be checked")
			require.Zero(t, channel.acceptCalls)
			select {
			case <-joined:
				t.Fatal("invalid forwarding metadata announced guest presence")
			default:
			}
			consumed := false
			presence.once.Do(func() { consumed = true })
			require.True(t, consumed, "invalid metadata must not consume presence latch")
		})
	}
}

type forwardPermissionFunc func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error)

func (f forwardPermissionFunc) CheckPermission(ctx context.Context, op consent.Operation, c consent.ClientInfo, subjects ...string) (consent.Decision, error) {
	return f(ctx, op, c, subjects...)
}
func (forwardPermissionFunc) ClearConnection(string) {}

func TestForwardingPolicy(t *testing.T) {
	for _, tt := range []struct {
		name, address                                  string
		port                                           uint32
		readonly, disabled, any, loopback, grant, want bool
	}{
		{name: "default denies", address: "127.0.0.1", port: 22},
		{name: "consent", address: "127.0.0.1", port: 22, grant: true, want: true},
		{name: "second IPv4", address: "127.0.0.2", port: 65535, loopback: true, want: true},
		{name: "native IPv6", address: "::1", port: 1, loopback: true, want: true},
		{name: "localhost loopback", address: "localhost", port: 22, loopback: true, grant: true},
		{name: "localhost unrestricted", address: "localhost", port: 22, any: true, want: true},
		{name: "hostname unrestricted", address: "example.invalid", port: 22, any: true, want: true},
		{name: "nonloopback consent", address: "192.0.2.1", port: 22, grant: true},
		{name: "mapped IPv6", address: "::ffff:127.0.0.1", port: 22, loopback: true, grant: true},
		{name: "zoned IPv6", address: "::1%lo0", port: 22, loopback: true, grant: true},
		{name: "malformed", address: "127.000.0.1", port: 22, loopback: true, grant: true},
		{name: "bracketed", address: "[::1]", port: 22, loopback: true, grant: true},
		{name: "empty", port: 22, any: true},
		{name: "zero port", address: "127.0.0.1", any: true},
		{name: "overflow port", address: "127.0.0.1", port: 65536, any: true},
		{name: "maximum uint32 port", address: "127.0.0.1", port: 4294967295, any: true},
		{name: "readonly unrestricted", address: "localhost", port: 22, readonly: true, any: true, grant: true},
		{name: "readonly loopback", address: "127.0.0.1", port: 22, readonly: true, loopback: true, grant: true},
		{name: "readonly consent", address: "127.0.0.1", port: 22, readonly: true, grant: true},
		{name: "disabled unrestricted", address: "localhost", port: 22, disabled: true, any: true, grant: true},
		{name: "disabled loopback", address: "127.0.0.1", port: 22, disabled: true, loopback: true, grant: true},
		{name: "disabled consent", address: "127.0.0.1", port: 22, disabled: true, grant: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			checker := forwardPermissionFunc(func(_ context.Context, op consent.Operation, c consent.ClientInfo, subjects ...string) (consent.Decision, error) {
				calls++
				require.Equal(t, consent.OpForward, op)
				require.Equal(t, consent.ClientInfo{Fingerprint: "guest", ConnectionID: "connection"}, c)
				require.Equal(t, []string{tt.address, strconv.FormatUint(uint64(tt.port), 10)}, subjects)
				if tt.grant {
					return consent.AllowGuest, nil
				}
				return consent.Deny, nil
			})
			p := forwardingPolicy{ReadOnly: tt.readonly, Disabled: tt.disabled, AllowAny: tt.any, AllowLoopback: tt.loopback, Checker: checker}
			err := authorizeForward(context.Background(), p, consent.ClientInfo{Fingerprint: "guest", ConnectionID: "connection"}, tt.address, tt.port)
			if tt.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if tt.name != "consent" && tt.name != "default denies" {
				require.Zero(t, calls, "hard denials and pregrants must not ask")
			}
		})
	}
	require.ErrorIs(t, authorizeForward(context.Background(), forwardingPolicy{}, consent.ClientInfo{}, "127.0.0.1", 22), consent.ErrUnavailable)
}

type forwardPrompter func(context.Context, consent.Prompt) (consent.Decision, error)

func (f forwardPrompter) Prompt(ctx context.Context, p consent.Prompt) (consent.Decision, error) {
	return f(ctx, p)
}

// A destination-scoped grant must not silently authorize another tuple.
func TestForwardingPolicyGrantTuples(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		prompts := make(chan consent.Prompt, 4)
		answers := make(chan consent.Decision)
		manager := consent.NewManager(forwardPrompter(func(ctx context.Context, p consent.Prompt) (consent.Decision, error) {
			prompts <- p
			select {
			case d := <-answers:
				return d, nil
			case <-ctx.Done():
				return consent.Deny, ctx.Err()
			}
		}), slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer manager.Close()
		p := forwardingPolicy{Checker: manager}
		c := consent.ClientInfo{Fingerprint: "guest", ConnectionID: "one"}
		call := func(addr string, port uint32) <-chan error {
			result := make(chan error, 1)
			go func() { result <- authorizeForward(context.Background(), p, c, addr, port) }()
			synctest.Wait()
			return result
		}
		first := call("127.0.0.1", 22)
		require.Equal(t, []string{"127.0.0.1", "22"}, (<-prompts).Subjects)
		answers <- consent.AllowConnection
		require.NoError(t, <-first)
		require.NoError(t, <-call("127.0.0.1", 22))
		different := call("127.0.0.1", 23)
		require.Equal(t, []string{"127.0.0.1", "23"}, (<-prompts).Subjects)
		answers <- consent.AllowGuest
		require.NoError(t, <-different)
		require.NoError(t, <-call("::1", 24))
		require.Error(t, <-call("localhost", 22), "guest-wide consent must not broaden literal tier")
		require.Empty(t, prompts)
	})
}

func TestForwardingPolicyConsentLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		prompts := make(chan struct{}, 2)
		var reviews atomic.Int32
		// A prompter honors cancellation however far it got: Close waits for
		// every review, including those of flights re-formed after it filled.
		manager := consent.NewManager(forwardPrompter(func(ctx context.Context, _ consent.Prompt) (consent.Decision, error) {
			reviews.Add(1)
			select {
			case prompts <- struct{}{}:
			case <-ctx.Done():
				return consent.Deny, ctx.Err()
			}
			<-ctx.Done()
			return consent.Deny, ctx.Err()
		}), slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer manager.Close()
		client := consent.ClientInfo{Fingerprint: "guest", ConnectionID: "one"}
		// Waiters join one at a time, so the flight's origin is always the
		// oldest waiter still waiting.
		cancels := make([]context.CancelFunc, consent.MaxWaitersPerConnection)
		results := make([]chan error, consent.MaxWaitersPerConnection)
		for i := range cancels {
			ctx, cancel := context.WithCancel(context.Background())
			cancels[i], results[i] = cancel, make(chan error, 1)
			go func() {
				results[i] <- authorizeForward(ctx, forwardingPolicy{Checker: manager}, client, "127.0.0.1", 22)
			}()
			synctest.Wait()
		}
		require.Len(t, prompts, 1, "same tuple coalesces")
		require.ErrorIs(t, authorizeForward(context.Background(), forwardingPolicy{Checker: manager}, client, "127.0.0.1", 22), consent.ErrOverloaded)
		// Canceling each origin in turn re-forms the flight for the next waiter
		// under a new prompt. Every one of those reviews has to end for Close.
		for i, cancel := range cancels {
			cancel()
			synctest.Wait()
			require.ErrorIs(t, <-results[i], consent.ErrCanceled)
			for _, later := range results[i+1:] {
				require.Empty(t, later, "canceling one waiter resolved another")
			}
			require.EqualValues(t, min(i+2, consent.MaxWaitersPerConnection), reviews.Load(), "the survivors' flight was not re-formed")
		}
	})
}

type forwardHandlerContext struct {
	gssh.Context
	parent context.Context
	values map[any]any
}

func (c forwardHandlerContext) Value(key any) any { return c.values[key] }
func (c forwardHandlerContext) SessionID() string { return "connection" }

// Explicit methods resolve the two embedded Context interfaces.
func (c forwardHandlerContext) Deadline() (time.Time, bool) { return c.parent.Deadline() }
func (c forwardHandlerContext) Done() <-chan struct{}       { return c.parent.Done() }
func (c forwardHandlerContext) Err() error                  { return c.parent.Err() }

type forwardOpen struct {
	ssh.NewChannel
	address      string
	port         uint32
	accepts      atomic.Int32
	rejection    string
	rejectReason ssh.RejectionReason
}

func (c *forwardOpen) ExtraData() []byte {
	return ssh.Marshal(&struct {
		Address    string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{c.address, c.port, "127.0.0.1", 1})
}
func (c *forwardOpen) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	c.accepts.Add(1)
	return nil, nil, errors.New("peer closed before acceptance")
}
func (c *forwardOpen) Reject(reason ssh.RejectionReason, message string) error {
	c.rejectReason = reason
	c.rejection = message
	return nil
}

func forwardContext(t *testing.T, parent context.Context) forwardHandlerContext {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return forwardHandlerContext{parent: parent, values: map[any]any{forwardingPresenceKey{}: &forwardingPresence{}, authenticatedGuestKey{}: authenticatedGuest{auth: &server.AuthRequest{}, key: key}}}
}

// Removing any cancellation/pregrant check or dialing before permission must
// create a real, observable connection to this accepting listener.
func TestForwardingConsentCancellation(t *testing.T) {
	for _, mode := range []string{"denied", "unavailable primary", "transport", "host", "session", "expired", "late checker grant", "late host checker grant", "read-only unrestricted", "disabled unrestricted"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()
			transport, cancel := context.WithCancel(context.Background())
			defer cancel()
			host, cancelHost := context.WithCancel(context.Background())
			defer cancelHost()
			session, endSession := context.WithCancel(context.Background())
			defer endSession()
			if mode == "expired" {
				var deadlineCancel context.CancelFunc
				transport, deadlineCancel = context.WithDeadline(transport, time.Now().Add(-time.Second))
				defer deadlineCancel()
			}
			c := forwardContext(t, transport)
			open := &forwardOpen{address: "127.0.0.1", port: uint32(ln.Addr().(*net.TCPAddr).Port)}
			asked := make(chan struct{}, 1)
			checker := forwardPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
				asked <- struct{}{}
				switch mode {
				case "transport", "host", "session":
					<-ctx.Done()
					return consent.AllowGuest, nil
				case "late host checker grant":
					cancelHost()
					return consent.AllowGuest, nil
				case "late checker grant":
					cancel()
					return consent.AllowGuest, nil
				case "unavailable primary":
					return consent.Deny, consent.ErrUnavailable
				default:
					return consent.Deny, consent.ErrDenied
				}
			})
			policy := forwardingPolicy{Checker: checker, ReadOnly: mode == "read-only unrestricted", Disabled: mode == "disabled unrestricted", AllowAny: mode == "read-only unrestricted" || mode == "disabled unrestricted"}
			done := make(chan struct{})
			go func() {
				forwardingHandler(emitter.New(1), &Forwards{}, policy, host, session, discardLogger())(nil, nil, open, c)
				close(done)
			}()
			if mode == "transport" || mode == "host" || mode == "session" {
				select {
				case <-asked:
				case <-time.After(time.Second):
					t.Fatal("permission not requested")
				}
				require.Zero(t, open.accepts.Load())
				switch mode {
				case "transport":
					cancel()
				case "host":
					cancelHost()
				default:
					endSession()
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("pending forward did not finish")
			}
			require.Zero(t, open.accepts.Load(), "accept must follow uncanceled permission")
			require.NotEmpty(t, open.rejection)
			require.NotContains(t, open.rejection, "--allow-local-tcp-forwarding")
			require.NoError(t, ln.SetDeadline(time.Now().Add(20*time.Millisecond)))
			conn, err := ln.Accept()
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err, "denied request reached listener")
		})
	}
}

func TestForwardingFailedAcceptDoesNotAnnounce(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	transport, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := forwardContext(t, transport)
	open := &forwardOpen{address: "127.0.0.1", port: uint32(ln.Addr().(*net.TCPAddr).Port)}
	events := emitter.New(1)
	joined := events.On(upterm.EventForwardingClientJoined)
	done := make(chan struct{})
	go func() {
		forwardingHandler(events, &Forwards{}, forwardingPolicy{AllowLoopback: true}, context.Background(), context.Background(), discardLogger())(nil, nil, open, c)
		close(done)
	}()
	require.NoError(t, ln.SetDeadline(time.Now().Add(time.Second)))
	socket, err := ln.Accept()
	require.NoError(t, err)
	defer func() { _ = socket.Close() }()
	require.NoError(t, socket.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = io.Copy(io.Discard, socket)
	require.NoError(t, err, "failed channel acceptance must close dialed socket")
	<-done
	require.EqualValues(t, 1, open.accepts.Load())
	select {
	case <-joined:
		t.Fatal("failed acceptance announced presence")
	default:
	}
}

func TestForwardingConsentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), consent.PermissionTimeout)
		defer cancel()
		checker := forwardPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
			time.Sleep(61 * time.Second) // A custom checker ignores cancellation and returns late.
			return consent.AllowGuest, nil
		})
		result := make(chan error, 1)
		go func() {
			result <- authorizeForward(ctx, forwardingPolicy{Checker: checker}, consent.ClientInfo{}, "127.0.0.1", 22)
		}()
		time.Sleep(consent.PermissionTimeout)
		require.ErrorIs(t, <-result, context.DeadlineExceeded)
	})
}

// A channel CLOSE must release a forward even when its target keeps its write
// side open after stdin EOF. A sibling proves cleanup is local to this channel.
func TestForwardingAcceptedChannelCloseStopsTransfer(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	firstDone := make(chan struct{})
	var opened atomic.Int32
	var handlers sync.WaitGroup
	handle := forwardingHandler(emitter.New(1), &Forwards{}, forwardingPolicy{AllowLoopback: true}, context.Background(), context.Background(), discardLogger())
	srv := &gssh.Server{
		HostSigners:      []gssh.Signer{signer},
		PublicKeyHandler: func(gssh.Context, gssh.PublicKey) bool { return true },
		ConnCallback: func(ctx gssh.Context, conn net.Conn) net.Conn {
			ctx.SetValue(forwardingPresenceKey{}, &forwardingPresence{})
			ctx.SetValue(authenticatedGuestKey{}, authenticatedGuest{auth: &server.AuthRequest{}, key: signer.PublicKey()})
			return conn
		},
		ChannelHandlers: map[string]gssh.ChannelHandler{"direct-tcpip": func(srv *gssh.Server, conn *ssh.ServerConn, ch ssh.NewChannel, ctx gssh.Context) {
			handlers.Add(1)
			defer handlers.Done()
			first := opened.Add(1) == 1
			handle(srv, conn, ch, ctx)
			if first {
				close(firstDone)
			}
		}},
	}
	serverDone := make(chan struct{})
	go func() { _ = srv.Serve(listener); close(serverDone) }()
	t.Cleanup(func() { _ = srv.Close(); _ = listener.Close(); <-serverDone; handlers.Wait() })
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	first, err := client.Dial("tcp", target.Addr().String())
	require.NoError(t, err)
	silent, err := target.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = silent.Close() })
	require.NoError(t, first.Close())
	require.NoError(t, silent.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = silent.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	// The target deliberately remains open. Channel cleanup must not need its
	// EOF or a transport/host shutdown, and must not close a sibling transport.
	sibling, err := client.Dial("tcp", target.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sibling.Close() })
	echo, err := target.Accept()
	require.NoError(t, err)
	echoDone := make(chan struct{})
	go func() { _, _ = io.Copy(echo, echo); _ = echo.Close(); close(echoDone) }()
	t.Cleanup(func() { _ = echo.Close(); <-echoDone })
	_, err = sibling.Write([]byte("sibling"))
	require.NoError(t, err)
	data := make([]byte, len("sibling"))
	_, err = io.ReadFull(sibling, data)
	require.NoError(t, err)
	require.Equal(t, "sibling", string(data))
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("closed forwarding channel retained its handler/socket while transport and silent target remained open")
	}
}

// forwardingRigTimeout bounds every wait on a forwardingRig, so a forward that
// wedges fails its own test rather than timing out the package.
const forwardingRigTimeout = 10 * time.Second

// forwardingRig is one guest connection to a server serving forwardingHandler
// alone, and a target it may forward to. Only its first forward is observed.
type forwardingRig struct {
	client *ssh.Client
	target net.Listener
	// stopped closes the first time the handler ends the forward's way back
	// to the guest: a CloseWrite or Close of the channel.
	stopped chan struct{}
	// handled closes once the forward's handler has returned.
	handled chan struct{}
	// reads, when the rig holds reads, is what the handler's reads of the
	// channel wait for: nothing the guest sends leaves the channel until
	// releaseReads, which the rig's cleanup also calls.
	reads       chan struct{}
	releaseOnce sync.Once
}

// releaseReads lets the handler read the channel, if the rig was holding its
// reads. Any number of calls.
func (r *forwardingRig) releaseReads() {
	r.releaseOnce.Do(func() {
		if r.reads != nil {
			close(r.reads)
		}
	})
}

func startForwardingRig(t *testing.T, hostCtx context.Context, holdReads bool) *forwardingRig {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	rig := &forwardingRig{target: target, stopped: make(chan struct{}), handled: make(chan struct{})}
	if holdReads {
		rig.reads = make(chan struct{})
	}
	var opened atomic.Int32
	var handlers sync.WaitGroup
	handle := forwardingHandler(emitter.New(1), &Forwards{}, forwardingPolicy{AllowLoopback: true}, hostCtx, context.Background(), discardLogger())
	srv := &gssh.Server{
		HostSigners:      []gssh.Signer{signer},
		PublicKeyHandler: func(gssh.Context, gssh.PublicKey) bool { return true },
		ConnCallback: func(ctx gssh.Context, conn net.Conn) net.Conn {
			ctx.SetValue(forwardingPresenceKey{}, &forwardingPresence{})
			ctx.SetValue(authenticatedGuestKey{}, authenticatedGuest{auth: &server.AuthRequest{}, key: signer.PublicKey()})
			return conn
		},
		ChannelHandlers: map[string]gssh.ChannelHandler{"direct-tcpip": func(srv *gssh.Server, conn *ssh.ServerConn, ch ssh.NewChannel, ctx gssh.Context) {
			handlers.Add(1)
			defer handlers.Done()
			if opened.Add(1) != 1 {
				handle(srv, conn, ch, ctx)
				return
			}
			defer close(rig.handled)
			var once sync.Once
			handle(srv, conn, &stopObservedOpen{NewChannel: ch, stop: func() { once.Do(func() { close(rig.stopped) }) }, reads: rig.reads}, ctx)
		}},
	}
	serverDone := make(chan struct{})
	go func() { _ = srv.Serve(listener); close(serverDone) }()
	t.Cleanup(func() { _ = srv.Close(); _ = listener.Close(); <-serverDone; handlers.Wait() })
	// Registered after the server's cleanup, so it runs before it: a read
	// held here isn't woken by closing the transport, and the server's
	// cleanup waits for the handler making it. A test that fails before
	// releasing the reads then fails, rather than hanging.
	t.Cleanup(rig.releaseReads)
	rig.client, err = ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rig.client.Close() })
	return rig
}

// stopObservedOpen accepts the real channel, reporting the handler's first
// CloseWrite or Close of it, and holding its reads until reads closes.
type stopObservedOpen struct {
	ssh.NewChannel
	stop  func()
	reads <-chan struct{}
}

func (o *stopObservedOpen) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	ch, requests, err := o.NewChannel.Accept()
	if err != nil {
		return nil, nil, err
	}
	return &stopObservedChannel{Channel: ch, stop: o.stop, reads: o.reads}, requests, nil
}

type stopObservedChannel struct {
	ssh.Channel
	stop  func()
	reads <-chan struct{}
}

func (c *stopObservedChannel) Read(p []byte) (int, error) {
	if c.reads != nil {
		<-c.reads
	}
	return c.Channel.Read(p)
}

func (c *stopObservedChannel) CloseWrite() error { c.stop(); return c.Channel.CloseWrite() }
func (c *stopObservedChannel) Close() error      { c.stop(); return c.Channel.Close() }

// awaitForwardStopped waits for the handler to end the way back to the guest.
func (r *forwardingRig) awaitForwardStopped(t *testing.T) {
	t.Helper()
	select {
	case <-r.stopped:
	case <-time.After(forwardingRigTimeout):
		t.Fatal("forward never stopped its way back to the guest")
	}
}

// forwardingUpload is within one channel window, so the guest's write
// completes without the forward having read any of it.
func forwardingUpload() []byte {
	upload := make([]byte, 1<<20)
	for i := range upload {
		upload[i] = byte(i % 251)
	}
	return upload
}

// A guest that closes its forward straight after writing to it has still sent
// all of it: the target is given everything the channel had received before
// the CLOSE, then EOF, however late it starts reading. Only the way back to
// the guest, which can no longer be written to, stops at once.
func TestForwardingChannelCloseDeliversWhatTheGuestSent(t *testing.T) {
	rig := startForwardingRig(t, context.Background(), true)
	conn, err := rig.client.Dial("tcp", rig.target.Addr().String())
	require.NoError(t, err)
	target, err := rig.target.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	upload := forwardingUpload()
	_, err = conn.Write(upload)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	// The forward reads nothing from the channel until it has acted on the
	// CLOSE, so all of the upload is still there then, however much the
	// sockets to the target could have taken -- on Linux, close to a window.
	rig.awaitForwardStopped(t)
	rig.releaseReads()
	require.NoError(t, target.SetReadDeadline(time.Now().Add(forwardingRigTimeout)))
	got, err := io.ReadAll(target)
	require.NoError(t, err)
	require.Equal(t, len(upload), len(got), "bytes delivered")
	require.True(t, bytes.Equal(upload, got), "delivered bytes differ from the upload")
	select {
	case <-rig.handled:
	case <-time.After(forwardingRigTimeout):
		t.Fatal("forward's handler outlived its delivered upload")
	}
}

// Transport loss and a host stop end a forward at once, whatever it has yet
// to deliver -- with the guest's CLOSE still being delivered, too. They close
// both ends rather than wait for a drain. The forward's reads of the channel
// are held across the stop, so no drain can finish and end the transfer
// first: only the stop can, and both ends must have seen it before the reads
// are let go.
func TestForwardingTransportLossAndHostStopEndTheTransfer(t *testing.T) {
	for _, source := range []string{"transport", "host"} {
		for _, guestClosed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/guest closed=%t", source, guestClosed), func(t *testing.T) {
				hostCtx, stopHost := context.WithCancel(context.Background())
				defer stopHost()
				rig := startForwardingRig(t, hostCtx, true)
				conn, err := rig.client.Dial("tcp", rig.target.Addr().String())
				require.NoError(t, err)
				target, err := rig.target.Accept()
				require.NoError(t, err)
				t.Cleanup(func() { _ = target.Close() })
				_, err = conn.Write(forwardingUpload())
				require.NoError(t, err)
				guestDone := make(chan struct{})
				if guestClosed {
					close(guestDone)
					require.NoError(t, conn.Close())
					// The forward has taken the CLOSE and owes the target the
					// whole upload, which it can't read yet.
					rig.awaitForwardStopped(t)
				} else {
					go func() { defer close(guestDone); _, _ = io.Copy(io.Discard, conn) }()
				}
				if source == "transport" {
					require.NoError(t, rig.client.Close())
				} else {
					stopHost()
				}
				// The stop closed the target's side: it reads its end, a clean
				// one, since the target sent nothing that went unread -- not
				// the deadline.
				require.NoError(t, target.SetReadDeadline(time.Now().Add(forwardingRigTimeout)))
				_, err = io.Copy(io.Discard, target)
				require.NoError(t, err, "target's side wasn't closed at the stop")
				select {
				case <-guestDone:
				case <-time.After(forwardingRigTimeout):
					t.Fatal("guest's side of the forward stayed open")
				}
				rig.releaseReads()
				select {
				case <-rig.handled:
				case <-time.After(forwardingRigTimeout):
					t.Fatal("forward's handler outlived the stop")
				}
			})
		}
	}
}

func forwardingAuditRecords(t *testing.T, data string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		records = append(records, record)
	}
	return records
}

// A destination upterm doesn't forward to is named back to the guest, with
// the fix where a loopback one is what the guest meant: localhost, in any
// case and with or without its final dot, or a name under it, which upterm
// never resolves, or a loopback address in a form it doesn't take. Any other
// name, and an address somewhere else, gets no such advice, since 127.0.0.1
// is not where it asked to go. The destination is the guest's own input, so
// what is echoed of it is bounded and plain, and the refusal is still made
// before anything is asked or dialed.
func TestForwardingRefusalNamesTheDestination(t *testing.T) {
	const rule = "upterm forwards only to literal loopback addresses"
	for _, tt := range []struct {
		name, address string
		port          uint32
		want          string
	}{
		{"localhost", "localhost", 8080, "upterm: forwarding to localhost:8080 refused: " + rule + "; use 127.0.0.1:8080 or [::1]:8080"},
		{"localhost in capitals", "LOCALHOST", 8080, "upterm: forwarding to LOCALHOST:8080 refused: " + rule + "; use 127.0.0.1:8080 or [::1]:8080"},
		{"localhost with its final dot", "localhost.", 8080, "upterm: forwarding to localhost.:8080 refused: " + rule + "; use 127.0.0.1:8080 or [::1]:8080"},
		{"a name under localhost", "app.localhost", 3000, "upterm: forwarding to app.localhost:3000 refused: " + rule + "; use 127.0.0.1:3000 or [::1]:3000"},
		{"a name under localhost, in capitals, with its final dot", "App.LocalHost.", 3000, "upterm: forwarding to App.LocalHost.:3000 refused: " + rule + "; use 127.0.0.1:3000 or [::1]:3000"},
		{"a name elsewhere", "db.internal", 5432, "upterm: forwarding to db.internal:5432 refused: " + rule},
		{"another name elsewhere", "db.example.com", 5432, "upterm: forwarding to db.example.com:5432 refused: " + rule},
		{"a name that only starts like localhost", "localhost.example.com", 5432, "upterm: forwarding to localhost.example.com:5432 refused: " + rule},
		{"mapped loopback", "::ffff:127.0.0.1", 22, "upterm: forwarding to [::ffff:127.0.0.1]:22 refused: " + rule + "; use 127.0.0.1:22 or [::1]:22"},
		{"zoned loopback", "::1%lo0", 22, "upterm: forwarding to [::1%lo0]:22 refused: " + rule + "; use 127.0.0.1:22 or [::1]:22"},
		{"remote IPv4", "192.0.2.1", 5432, "upterm: forwarding to 192.0.2.1:5432 refused: " + rule},
		{"remote IPv6", "2001:db8::1", 5432, "upterm: forwarding to [2001:db8::1]:5432 refused: " + rule},
		{"zoned remote", "fe80::1%en0", 22, "upterm: forwarding to [fe80::1%en0]:22 refused: " + rule},
		{"controls", "x\x1b]0;owned\a\r\nb\u0085", 80, "upterm: forwarding to x?]0;owned???b?:80 refused: " + rule},
		{"invalid UTF-8", "x\xff", 80, "upterm: forwarding to x?:80 refused: " + rule},
		// At most 255 bytes of it, the ellipsis that says it was cut among
		// them, and cut between characters.
		{"long", strings.Repeat("a", 4096), 80, "upterm: forwarding to " + strings.Repeat("a", 252) + "…:80 refused: " + rule},
		{"long, cut inside a character", strings.Repeat("a", 251) + "é" + strings.Repeat("b", 4096), 80, "upterm: forwarding to " + strings.Repeat("a", 251) + "…:80 refused: " + rule},
		{"a hostname's longest", strings.Repeat("a", 253), 80, "upterm: forwarding to " + strings.Repeat("a", 253) + ":80 refused: " + rule},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asked := false
			policy := forwardingPolicy{Checker: forwardPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
				asked = true
				return consent.AllowGuest, nil
			})}
			for _, p := range []forwardingPolicy{policy, {AllowLoopback: true}} {
				open := &forwardOpen{address: tt.address, port: tt.port}
				forwardingHandler(emitter.New(1), &Forwards{}, p, context.Background(), context.Background(), discardLogger())(nil, nil, open, forwardContext(t, context.Background()))
				require.Equal(t, ssh.Prohibited, open.rejectReason)
				require.Equal(t, tt.want, open.rejection)
				require.Zero(t, open.accepts.Load())
			}
			require.False(t, asked, "a destination upterm doesn't forward to is never offered for approval")
		})
	}
}

// What a refused guest is told: the session's own rule, or why approval
// didn't happen in its terms, never the internal error behind it.
const (
	forwardUnavailableRefusal = "upterm: port forwarding denied; nothing on the host can approve it now. The host can attach its terminal or run with --allow-forwarding=loopback."
	forwardDeniedRefusal      = "upterm: the host denied this port forward."
	forwardTimeoutRefusal     = "upterm: port forwarding denied; the request timed out before it was approved."
	forwardCanceledRefusal    = "upterm: port forwarding request canceled."
)

func TestForwardingAuditPolicyOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name, outcome, address, refusal                  string
		policy                                           forwardingPolicy
		decision                                         consent.Decision
		err                                              error
		cancelBefore, hostBefore, sessionBefore, expired bool
		lateTransport, lateHost, lateSession             bool
	}{
		{name: "read-only", outcome: "denied", refusal: "upterm: this session is read-only, so it doesn't allow port forwarding", policy: forwardingPolicy{ReadOnly: true, AllowAny: true}},
		{name: "disabled", outcome: "denied", refusal: "upterm: port forwarding is disabled for this session", policy: forwardingPolicy{Disabled: true, AllowLoopback: true}},
		{name: "ineligible hostname", outcome: "denied", refusal: "upterm: forwarding to localhost:PORT refused: upterm forwards only to literal loopback addresses; use 127.0.0.1:PORT or [::1]:PORT", address: "localhost", policy: forwardingPolicy{AllowLoopback: true}},
		{name: "ineligible remote address", outcome: "denied", refusal: "upterm: forwarding to 192.0.2.1:PORT refused: upterm forwards only to literal loopback addresses", address: "192.0.2.1", policy: forwardingPolicy{AllowLoopback: true}},
		{name: "unrestricted pregrant", outcome: "allowed", policy: forwardingPolicy{AllowAny: true}},
		{name: "loopback pregrant", outcome: "allowed", policy: forwardingPolicy{AllowLoopback: true}},
		{name: "nil checker", outcome: "unavailable", refusal: forwardUnavailableRefusal},
		{name: "custom connection grant", outcome: "allowed", decision: consent.AllowConnection},
		{name: "custom guest grant", outcome: "allowed", decision: consent.AllowGuest},
		{name: "custom host denial", outcome: "denied", refusal: forwardDeniedRefusal, err: consent.ErrDenied},
		{name: "custom deny decision", outcome: "denied", refusal: forwardDeniedRefusal},
		{name: "custom unavailable", outcome: "unavailable", refusal: forwardUnavailableRefusal, err: fmt.Errorf("primary: %w", consent.ErrUnavailable)},
		{name: "custom canceled", outcome: "canceled", refusal: forwardCanceledRefusal, err: context.Canceled},
		{name: "custom consent canceled", outcome: "canceled", refusal: forwardCanceledRefusal, err: consent.ErrCanceled},
		{name: "custom timeout", outcome: "timeout", refusal: forwardTimeoutRefusal, err: context.DeadlineExceeded},
		{name: "custom consent timeout", outcome: "timeout", refusal: forwardTimeoutRefusal, err: consent.ErrTimeout},
		{name: "custom overloaded", outcome: "overloaded", refusal: "upterm: port forwarding denied; too many permission requests are waiting. Try again later.", err: consent.ErrOverloaded},
		{name: "custom late answer", outcome: "stale", refusal: "upterm: port forwarding denied; the host's answer came after the request ended.", err: consent.ErrStale},
		{name: "custom subject overflow", outcome: "subject_too_large", refusal: "upterm: port forwarding denied; the destination is too long to review.", err: consent.ErrSubjectTooLarge},
		{name: "custom other failure", outcome: "denied", refusal: "upterm: port forwarding denied.", err: errors.New("checker failed")},
		{name: "transport canceled before checker", outcome: "canceled", refusal: forwardCanceledRefusal, cancelBefore: true},
		{name: "host canceled before checker", outcome: "canceled", refusal: forwardCanceledRefusal, hostBefore: true},
		{name: "session ended before checker", outcome: "canceled", refusal: forwardCanceledRefusal, sessionBefore: true},
		{name: "deadline expired before checker", outcome: "timeout", refusal: forwardTimeoutRefusal, expired: true},
		{name: "custom late transport allowance", outcome: "canceled", refusal: forwardCanceledRefusal, decision: consent.AllowGuest, lateTransport: true},
		{name: "custom late host allowance", outcome: "canceled", refusal: forwardCanceledRefusal, decision: consent.AllowGuest, lateHost: true},
		{name: "custom late session allowance", outcome: "canceled", refusal: forwardCanceledRefusal, decision: consent.AllowGuest, lateSession: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer func() { _ = listener.Close() }()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			host, cancelHost := context.WithCancel(context.Background())
			defer cancelHost()
			if tt.cancelBefore {
				cancel()
			}
			if tt.hostBefore {
				cancelHost()
			}
			session, endSession := context.WithCancel(context.Background())
			defer endSession()
			if tt.sessionBefore {
				endSession()
			}
			if tt.expired {
				var stop context.CancelFunc
				parent, stop = context.WithDeadline(parent, time.Now().Add(-time.Second))
				defer stop()
			}
			ctx := forwardContext(t, parent)
			checked := false
			policy := tt.policy
			if strings.HasPrefix(tt.name, "custom") || tt.cancelBefore || tt.hostBefore || tt.sessionBefore || tt.expired {
				policy.Checker = forwardPermissionFunc(func(_ context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
					checked = true
					if tt.lateTransport {
						cancel()
					}
					if tt.lateHost {
						cancelHost()
					}
					if tt.lateSession {
						endSession()
					}
					return tt.decision, tt.err
				})
			}
			address := tt.address
			if address == "" {
				address = "127.0.0.1"
			}
			open := &forwardOpen{address: address, port: uint32(listener.Addr().(*net.TCPAddr).Port)}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			forwardingHandler(emitter.New(1), &Forwards{}, policy, host, session, logger)(nil, nil, open, ctx)
			records := forwardingAuditRecords(t, logs.String())
			require.Len(t, records, 1)
			record := records[0]
			require.Equal(t, "forwarding permission policy", record["msg"])
			require.Equal(t, "forward", record["capability"])
			require.Equal(t, "forward", record["operation"])
			require.Equal(t, tt.outcome, record["outcome"])
			require.Equal(t, []any{strconv.QuoteToASCII(address), strconv.QuoteToASCII(strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))}, record["subjects"])
			guest := ctx.values[authenticatedGuestKey{}].(authenticatedGuest)
			require.Equal(t, strconv.QuoteToASCII(utils.FingerprintSHA256(guest.key)), record["fingerprint"])
			require.Equal(t, `"connection"`, record["connection_id"])
			requestID, err := strconv.Unquote(record["request_id"].(string))
			require.NoError(t, err)
			require.NotEmpty(t, requestID)
			if tt.outcome == "allowed" {
				require.Empty(t, record["reason"])
				require.EqualValues(t, 1, open.accepts.Load())
			} else {
				require.NotEmpty(t, record["reason"])
				require.Zero(t, open.accepts.Load())
			}
			// The listener's port, where a refusal names the destination.
			require.Equal(t, strings.ReplaceAll(tt.refusal, "PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)), open.rejection)
			if tt.cancelBefore || tt.hostBefore || tt.sessionBefore || tt.expired {
				require.False(t, checked, "canceled request must be recorded without asking")
			}
			if tt.lateTransport || tt.lateHost || tt.lateSession {
				require.True(t, checked)
			}
		})
	}
}

func TestForwardingAuditBoundsUntrustedText(t *testing.T) {
	for _, handler := range []string{"json", "text"} {
		t.Run(handler, func(t *testing.T) {
			for _, subject := range []bool{true, false} {
				t.Run(fmt.Sprintf("subject_%v", subject), func(t *testing.T) {
					hostile := "bad\x1b\r\n" + strings.Repeat("x", 8192) + "SECRET_TAIL"
					var logs bytes.Buffer
					var sink slog.Handler = slog.NewJSONHandler(&logs, nil)
					if handler == "text" {
						sink = slog.NewTextHandler(&logs, nil)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					c := forwardContext(t, ctx)
					policy := forwardingPolicy{Checker: forwardPermissionFunc(func(_ context.Context, _ consent.Operation, _ consent.ClientInfo, subjects ...string) (consent.Decision, error) {
						require.Equal(t, []string{"127.0.0.1", "22"}, subjects)
						return consent.Deny, errors.New(hostile)
					})}
					address := "127.0.0.1"
					if subject {
						address = hostile
					}
					open := &forwardOpen{address: address, port: 22}
					forwardingHandler(emitter.New(1), &Forwards{}, policy, context.Background(), context.Background(), slog.New(sink))(nil, nil, open, c)
					data := logs.String()
					require.NotEmpty(t, data)
					require.Less(t, len(data), 4096)
					require.NotContains(t, data, "SECRET_TAIL")
					require.NotContains(t, data, "\x1b")
					require.NotContains(t, data, "\r")
					require.Equal(t, 1, strings.Count(data, "\n"), "guest fields cannot inject audit records")
					if handler == "json" {
						record := forwardingAuditRecords(t, data)[0]
						field := record["reason"]
						if subject {
							field = record["subjects"].([]any)[0]
						}
						projected := field.(string)
						require.NotContains(t, projected, "\x1b")
						require.NotContains(t, projected, "\n")
						require.NotContains(t, projected, "\r")
						original, err := strconv.Unquote(projected)
						require.NoError(t, err)
						require.True(t, strings.HasPrefix(original, "bad\x1b\r\n"))
						require.True(t, strings.HasSuffix(original, "..."))
					}
				})
			}
		})
	}
}

func TestForwardingAuditPreservesManagerEvents(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	manager := consent.NewManager(forwardPrompter(func(context.Context, consent.Prompt) (consent.Decision, error) { return consent.AllowConnection, nil }), logger)
	defer manager.Close()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := forwardContext(t, parent)
	handle := forwardingHandler(emitter.New(1), &Forwards{}, forwardingPolicy{Checker: manager}, context.Background(), context.Background(), logger)
	for range 2 {
		handle(nil, nil, &forwardOpen{address: "127.0.0.1", port: uint32(listener.Addr().(*net.TCPAddr).Port)}, c)
	}
	manager.Close()
	records := forwardingAuditRecords(t, logs.String())
	var boundary, managed []map[string]any
	for _, record := range records {
		switch record["msg"] {
		case "forwarding permission policy":
			boundary = append(boundary, record)
		case "consent decision":
			managed = append(managed, record)
		}
	}
	require.Len(t, boundary, 2)
	require.Len(t, managed, 2)
	require.Equal(t, "allowed", boundary[0]["outcome"])
	require.Equal(t, "allowed", boundary[1]["outcome"])
	require.NotEqual(t, boundary[0]["request_id"], boundary[1]["request_id"], "same-connection opens retain separate audit identities")
	require.Equal(t, "allow_connection", managed[0]["outcome"])
	requestID, err := strconv.Unquote(managed[0]["request_id"].(string))
	require.NoError(t, err)
	require.NotEmpty(t, requestID, "manager still records its review identity")
}

type forwardingAuditWriterFunc func([]byte) (int, error)

func (f forwardingAuditWriterFunc) Write(data []byte) (int, error) { return f(data) }

func TestForwardingAuditCancellationDuringLogging(t *testing.T) {
	for _, owner := range []string{"transport", "host"} {
		t.Run(owner, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer func() { _ = listener.Close() }()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			host, cancelHost := context.WithCancel(context.Background())
			defer cancelHost()
			var logs bytes.Buffer
			writer := forwardingAuditWriterFunc(func(data []byte) (int, error) {
				if owner == "transport" {
					cancel()
				} else {
					cancelHost()
				}
				return logs.Write(data)
			})
			logger := slog.New(slog.NewJSONHandler(writer, nil))
			open := &forwardOpen{address: "127.0.0.1", port: uint32(listener.Addr().(*net.TCPAddr).Port)}
			forwardingHandler(emitter.New(1), &Forwards{}, forwardingPolicy{AllowLoopback: true}, host, context.Background(), logger)(nil, nil, open, forwardContext(t, parent))
			records := forwardingAuditRecords(t, logs.String())
			require.NotEmpty(t, records)
			require.Equal(t, "canceled", records[len(records)-1]["outcome"], "synchronous logging must not hide owner loss before dial")
			require.Equal(t, records[0]["request_id"], records[len(records)-1]["request_id"])
			require.Zero(t, open.accepts.Load())
			require.NoError(t, listener.SetDeadline(time.Now().Add(20*time.Millisecond)))
			conn, err := listener.Accept()
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err, "owner lost during audit write must prevent dial")
		})
	}
}
