package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	otherSessionID = "44444444-4444-4444-8444-444444444444"
	openSSHVersion = "SSH-2.0-OpenSSH_9.9"
)

// guestVersions are the clients a guest may connect with: plain ssh, an
// upterm client, and upterm join.
var guestVersions = []string{openSSHVersion, upterm.ClientSSHClientVersion, upterm.JoinSSHClientVersion}

// guestHost is a delegated host's end of its guests' connections: an SSH
// server of the host's run key behind its forward. It records every guest
// the relay vouches for, and every channel and request it is asked for, and
// answers each yes: a session's shell, exec or subsystem echoes, or floods
// when flood is set, and a direct TCP/IP channel echoes.
type guestHost struct {
	flood atomic.Bool
	// written counts what floods wrote.
	written atomic.Int64

	mu       sync.Mutex
	joined   []*AuthRequest
	channels []*hostChannel
	conns    []net.Conn
	// served is the host's end of each guest's SSH connection.
	served  []*ssh.ServerConn
	workers sync.WaitGroup
}

// hostChannel is one channel a guest's relay opened to the host.
type hostChannel struct {
	kind     string
	mu       sync.Mutex
	requests []string
	closed   chan struct{}
}

func (c *hostChannel) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests...)
}

func newGuestHost(t *testing.T, client *ssh.Client, hostKey ssh.Signer, id string, relayKey ssh.PublicKey) *guestHost {
	t.Helper()
	ln, err := client.Listen("unix", id)
	require.NoError(t, err)
	h := &guestHost{}
	checker := UserCertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return sameKey(k, relayKey) }}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auth, _, err := checker.Authenticate(meta.User(), key)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.joined = append(h.joined, auth)
		h.mu.Unlock()
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(hostKey)
	h.workers.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns = append(h.conns, conn)
			h.mu.Unlock()
			h.workers.Go(func() { h.serve(conn, config) })
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		h.mu.Lock()
		for _, c := range h.conns {
			_ = c.Close()
		}
		h.mu.Unlock()
		joined := make(chan struct{})
		go func() { defer close(joined); h.workers.Wait() }()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Error("the guests' host did not stop")
		}
	})
	return h
}

func (h *guestHost) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	h.mu.Lock()
	h.served = append(h.served, sconn)
	h.mu.Unlock()
	h.workers.Go(func() { ssh.DiscardRequests(reqs) })
	for nc := range chans {
		if nc.ChannelType() != "session" && nc.ChannelType() != "direct-tcpip" {
			_ = nc.Reject(ssh.Prohibited, "no")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		hc := &hostChannel{kind: nc.ChannelType(), closed: make(chan struct{})}
		h.mu.Lock()
		h.channels = append(h.channels, hc)
		h.mu.Unlock()
		h.workers.Go(func() {
			defer close(hc.closed)
			defer func() { _ = ch.Close() }()
			if hc.kind == "direct-tcpip" {
				h.workers.Go(func() { _, _ = io.Copy(ch, ch) })
			}
			started := false
			for r := range requests {
				hc.mu.Lock()
				hc.requests = append(hc.requests, r.Type)
				hc.mu.Unlock()
				_ = r.Reply(true, nil)
				if started || (r.Type != "shell" && r.Type != "exec" && r.Type != "subsystem") {
					continue
				}
				started = true
				if h.flood.Load() {
					h.workers.Go(func() {
						chunk := bytes.Repeat([]byte("x"), 32<<10)
						for {
							n, err := ch.Write(chunk)
							h.written.Add(int64(n))
							if err != nil {
								return
							}
						}
					})
					continue
				}
				h.workers.Go(func() { _, _ = io.Copy(ch, ch) })
			}
		})
	}
}

func (h *guestHost) guests() []*AuthRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*AuthRequest(nil), h.joined...)
}

func (h *guestHost) opened() []*hostChannel {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*hostChannel(nil), h.channels...)
}

// connection is the host's end of the nth guest connection to reach it,
// from 1, once it has.
func (h *guestHost) connection(t *testing.T, n int) *ssh.ServerConn {
	t.Helper()
	var conn *ssh.ServerConn
	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(h.served) < n {
			return false
		}
		conn = h.served[n-1]
		return true
	}, 5*time.Second, 10*time.Millisecond, "the guest never reached the host")
	return conn
}

// delegatedHostFixture is a host registered current on a relay with an
// authority, for an external session, taking guests.
type delegatedHostFixture struct {
	proven
	client     *ssh.Client
	externalID string
	// user is the guest user the relay answered the registration with: its
	// own encoding of the route.
	user   string
	guests *guestHost
}

func registerDelegatedHost(t *testing.T, ts *delegatedTestServer, externalID string) *delegatedHostFixture {
	t.Helper()
	host := newProven(t)
	client := dialHost(t, ts.addr, ts.signer, nil)
	ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, &DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalID}))
	require.True(t, ok, "%q", body)
	var resp CreateSessionResponse
	require.NoError(t, proto.Unmarshal(body, &resp))
	require.NotEmpty(t, resp.SshUser)
	return &delegatedHostFixture{
		proven: host, client: client, externalID: externalID, user: resp.SshUser,
		guests: newGuestHost(t, client, host.key, host.id(), ts.signer.PublicKey()),
	}
}

// target is the registration's own target, allowing capabilities.
func (h *delegatedHostFixture) target(capabilities ...string) Target {
	return Target{AccountID: fixtureAccountID, SessionID: h.externalID, RoutingID: h.id(), RunPublicKey: h.key.PublicKey(), Capabilities: capabilities}
}

// allowing admits every guest to target, and hands each guest it admits to
// guests when that is set.
func allowing(target Target, guests chan<- *Guest) func(context.Context, *Guest, GuestRequest) (Admission, error) {
	return func(_ context.Context, g *Guest, _ GuestRequest) (Admission, error) {
		if guests != nil {
			guests <- g
		}
		return Admission{Verdict: VerdictAllow, Target: target}, nil
	}
}

func showing(message string) func(context.Context, *Guest, GuestRequest) (Admission, error) {
	return func(context.Context, *Guest, GuestRequest) (Admission, error) {
		return Admission{Verdict: VerdictMessage, Message: []byte(message)}, nil
	}
}

// dialDelegatedGuestAs connects to addr as a guest of user with key,
// recording any banner the relay sends.
func dialDelegatedGuestAs(t *testing.T, addr, user, version string, key ssh.Signer) (*ssh.Client, *[]string, error) {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 10*time.Second)
	require.NoError(t, err)
	return guestOver(t, nc, addr, user, version, key)
}

// dialDelegatedGuestOverWS connects to the WebSocket listener at addr as a
// guest of user with key, for the session id on the node encodedNode names.
func dialDelegatedGuestOverWS(t *testing.T, addr, id, encodedNode, user string, key ssh.Signer) (*ssh.Client, *[]string, error) {
	t.Helper()
	nc, err := ws.NewWSConn(&url.URL{Scheme: "ws", Host: addr, User: url.UserPassword(id, encodedNode)}, true, nil)
	require.NoError(t, err)
	return guestOver(t, nc, addr, user, upterm.ClientSSHClientVersion, key)
}

func guestOver(t *testing.T, nc net.Conn, addr, user, version string, key ssh.Signer) (*ssh.Client, *[]string, error) {
	t.Helper()
	var banners []string
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, &ssh.ClientConfig{
		User:            user,
		ClientVersion:   version,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  func(m string) error { banners = append(banners, m); return nil },
		Timeout:         10 * time.Second,
	})
	if err != nil {
		_ = nc.Close()
		return nil, &banners, err
	}
	client := ssh.NewClient(c, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, &banners, nil
}

// runSession runs a session on client, with a terminal when pty is set, and
// returns what it wrote to stdout and stderr and how it exited.
func runSession(t *testing.T, client *ssh.Client, pty bool, command string) (string, string, error) {
	t.Helper()
	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	if pty {
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	}
	if command == "" {
		require.NoError(t, sess.Shell())
		err = sess.Wait()
	} else {
		err = sess.Run(command)
	}
	return stdout.String(), stderr.String(), err
}

func requireExit(t *testing.T, err error, status int) {
	t.Helper()
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, status, exit.ExitStatus())
}

// probeOnly is a key whose holder asks whether the relay would take it and
// then can't sign: a query and nothing more.
type probeOnly struct {
	ssh.Signer
	asked *atomic.Bool
}

func (p probeOnly) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	p.asked.Store(true)
	return nil, errors.New("this key only queries")
}

// encodedNode is the node half of user, the relay's embedded encoding of a
// route.
func encodedNode(t *testing.T, user string) string {
	t.Helper()
	_, node, ok := strings.Cut(user, ":")
	require.True(t, ok, "%q is no embedded route", user)
	return node
}

// Every way a guest can name a delegated session -- a user the authority
// claims, the routing ID, or the relay's own encoding of the route -- goes to
// the authority, from every client, once the guest has signed and on SSH
// ingress only, and goes no further than the authority lets it. A key that is
// only queried never reaches it, nor does a user that names nothing, nor a
// guest over WebSocket, direct or bridged.
func TestDelegatedEveryEnabledIngress(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	guestKey := newProven(t).key
	users := map[string]string{"claimed": claimPrefix + "work", "claimed alone": claimPrefix, "routing ID": host.id(), "relay's encoding": host.user}

	calls := 0
	for name, user := range users {
		for _, version := range guestVersions {
			t.Run("refused/"+name+"/"+version, func(t *testing.T) {
				guest, banners, err := dialDelegatedGuestAs(t, ts.addr, user, version, guestKey)
				require.Error(t, err, "a guest the authority did not admit got in")
				require.Nil(t, guest)
				require.Empty(t, *banners)
				calls++
				admissions, _ := authority.guests()
				require.Len(t, admissions, calls, "the authority was not asked exactly once")
				asked := admissions[calls-1]
				require.Equal(t, user, asked.request.User)
				if strings.HasPrefix(user, claimPrefix) {
					require.Nil(t, asked.request.Home, "a claimed user's request named a home")
				} else {
					require.NotNil(t, asked.request.Home)
					require.Equal(t, host.id(), asked.request.Home.Ref().RoutingID)
					require.Equal(t, AuthorityDelegated, asked.request.Home.Ref().Authority)
				}
				require.True(t, sameKey(guestKey.PublicKey(), asked.guest.Key))
				require.Equal(t, utils.FingerprintSHA256(guestKey.PublicKey()), asked.guest.Fingerprint)
				require.True(t, validUUID(asked.guest.ConnectionID), asked.guest.ConnectionID)
				require.Equal(t, asked.guest.ConnectionID, asked.guest.Origin.ConnectionID)
				require.Equal(t, Ingress_INGRESS_SSH, asked.guest.Origin.Ingress)
				require.Equal(t, "test-machine", asked.guest.Origin.NodeID)
				require.Equal(t, "127.0.0.1", asked.guest.Origin.Source)
				require.Equal(t, "127.0.0.1", asked.guest.Source.(*net.TCPAddr).IP.String())
				require.Empty(t, host.guests.guests(), "a refused guest reached the host")
			})
		}
	}
	admissions, _ := authority.guests()
	ids := map[string]bool{}
	for _, a := range admissions {
		ids[a.guest.ConnectionID] = true
	}
	require.Len(t, ids, len(admissions), "two admissions shared a connection ID")

	t.Run("a query alone", func(t *testing.T) {
		before, _ := authority.guests()
		var asked atomic.Bool
		_, err := ssh.Dial("tcp", ts.addr, &ssh.ClientConfig{
			User:            claimPrefix + "work",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(probeOnly{guestKey, &asked})},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		})
		require.Error(t, err)
		require.True(t, asked.Load(), "the relay refused the query, so the key was never asked to sign")
		after, _ := authority.guests()
		require.Len(t, after, len(before), "an unsigned query reached the authority")
	})

	t.Run("a user that names nothing", func(t *testing.T) {
		before, _ := authority.guests()
		for _, user := range []string{"unclaimed-work", "abc", host.id() + "x"} {
			_, _, err := dialDelegatedGuestAs(t, ts.addr, user, openSSHVersion, guestKey)
			require.Error(t, err, user)
		}
		after, _ := authority.guests()
		require.Len(t, after, len(before), "the authority was asked about a user that names nothing")
	})

	authority.admitWith(allowing(host.target("shell"), nil))
	t.Run("over WebSocket", func(t *testing.T) {
		before, _ := authority.guests()
		for _, user := range []string{claimPrefix + "work", host.id(), host.user} {
			_, _, err := dialDelegatedGuestOverWS(t, ts.wsAddr, host.id(), encodedNode(t, host.user), user, guestKey)
			require.Error(t, err, "a delegated guest was admitted over WebSocket as %s", user)
		}
		after, _ := authority.guests()
		require.Len(t, after, len(before), "a WebSocket guest reached the authority")
		require.Empty(t, host.guests.guests(), "a WebSocket guest reached the host")
	})

	joined := 0
	for name, user := range users {
		for _, version := range guestVersions {
			t.Run("allowed/"+name+"/"+version, func(t *testing.T) {
				guest, _, err := dialDelegatedGuestAs(t, ts.addr, user, version, guestKey)
				require.NoError(t, err)
				_ = guest.Close()
				joined++
				require.Eventually(t, func() bool { return len(host.guests.guests()) == joined }, 5*time.Second, 10*time.Millisecond)
				auth := host.guests.guests()[joined-1]
				require.Equal(t, string(ssh.MarshalAuthorizedKey(guestKey.PublicKey())), string(auth.AuthorizedKey), "the host was not told the guest's key")
				require.Equal(t, version, auth.ClientVersion)
			})
		}
	}
}

// An allowed guest goes to the registration its admission names and nowhere
// else, whatever its user names: not to the route its user names, not to a
// route of another external session or another key, and not to another relay
// node, even if the store says the route is there.
func TestDelegatedOpaqueRouteCannotBypassTheAuthority(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	a := registerDelegatedHost(t, ts, externalSessionID)
	b := registerDelegatedHost(t, ts, otherSessionID)
	key := newProven(t).key
	authority.admitWith(allowing(b.target("shell"), nil))
	for _, user := range []string{a.id(), a.user} {
		_, _, err := dialDelegatedGuestAs(t, ts.addr, user, openSSHVersion, key)
		require.Error(t, err)
	}
	require.Empty(t, a.guests.guests())
	require.Empty(t, b.guests.guests())
	guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, key)
	require.NoError(t, err)
	_ = guest.Close()
	for name, change := range map[string]func(*Target){"session": func(v *Target) { v.SessionID = otherSessionID }, "run key": func(v *Target) { v.RunPublicKey = b.key.PublicKey() }, "account": func(v *Target) { v.AccountID = externalSessionID }, "route": func(v *Target) { v.RoutingID = newProven(t).id() }} {
		t.Run(name, func(t *testing.T) {
			target := a.target("shell")
			change(&target)
			authority.admitWith(allowing(target, nil))
			_, _, err := dialDelegatedGuestAs(t, ts.addr, a.user, openSSHVersion, key)
			require.Error(t, err)
			require.Empty(t, a.guests.guests())
		})
	}

	// Nor to a local session on the relay, whatever the authority names.
	t.Run("a local registration", func(t *testing.T) {
		local := newProven(t)
		client := dialHost(t, ts.addr, ts.signer, nil)
		ok, body := sendCreate(t, client, local.delegatedRequest(t, client, 1, nil))
		require.True(t, ok, "%q", body)
		host := newGuestHost(t, client, local.key, local.id(), ts.signer.PublicKey())
		home, found := ts.sshd().Lookup(local.id())
		require.True(t, found)
		ref := home.Ref()
		authority.admitWith(allowing(Target{Registration: ref, AccountID: ref.AccountID, SessionID: ref.SessionID, RoutingID: ref.RoutingID, RunPublicKey: local.key.PublicKey(), Capabilities: []string{"shell"}}, nil))
		_, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, key)
		require.Error(t, err, "an authority admitted a guest to a local session")
		require.Empty(t, host.guests(), "an authority's guest reached a local session's host")
	})
}

// A claimed user the authority says to show a message to is let in to a
// session that shows it and nothing else: on a shell's stdout, with carriage
// returns for a terminal, on an exec's stderr, exiting 1 either way.
// Everything else a guest can ask for is refused, nothing reaches the host,
// and a guest that asks for nothing is let go once the handshake's budget
// has passed.
func TestDelegatedMessage(t *testing.T) {
	const message = "the session is not running (last seen unknown).\n"
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority, func(s *Server) { s.HandshakeTimeout = 6 * time.Second })
	host := registerDelegatedHost(t, ts, externalSessionID)
	guestKey := newProven(t).key
	authority.admitWith(showing(message))
	connect := func(t *testing.T) *ssh.Client {
		t.Helper()
		guest, banners, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, guestKey)
		require.NoError(t, err, "a guest to be shown why it can't be admitted was refused instead")
		require.Empty(t, *banners)
		return guest
	}

	t.Run("shell", func(t *testing.T) {
		stdout, stderr, err := runSession(t, connect(t), false, "")
		requireExit(t, err, 1)
		require.Equal(t, message, stdout)
		require.Empty(t, stderr)
	})
	t.Run("shell with a terminal", func(t *testing.T) {
		stdout, _, err := runSession(t, connect(t), true, "")
		requireExit(t, err, 1)
		require.Equal(t, strings.ReplaceAll(message, "\n", "\r\n"), stdout)
	})
	t.Run("exec", func(t *testing.T) {
		stdout, stderr, err := runSession(t, connect(t), false, "uptime")
		requireExit(t, err, 1)
		require.Empty(t, stdout)
		require.Equal(t, message, stderr)
	})
	t.Run("exec with a terminal", func(t *testing.T) {
		stdout, stderr, err := runSession(t, connect(t), true, "uptime")
		requireExit(t, err, 1)
		require.Empty(t, stdout)
		require.Equal(t, strings.ReplaceAll(message, "\n", "\r\n"), stderr)
	})
	t.Run("nothing that controls a terminal", func(t *testing.T) {
		authority.admitWith(showing("the \x1b[31msession\x1b]0;x\x07 is\r reconnecting\x9b\xff.\n"))
		t.Cleanup(func() { authority.admitWith(showing(message)) })
		stdout, _, err := runSession(t, connect(t), false, "")
		requireExit(t, err, 1)
		require.Equal(t, "the �[31msession�]0;x� is� reconnecting��.\n", stdout)
	})

	t.Run("everything else is refused", func(t *testing.T) {
		guest := connect(t)
		sess, err := guest.NewSession()
		require.NoError(t, err)
		defer func() { _ = sess.Close() }()
		require.Error(t, sess.RequestSubsystem("sftp"), "a subsystem was served")
		require.Error(t, sess.Setenv("LANG", "C"), "an environment variable was taken")
		for _, request := range []string{"x11-req", "auth-agent-req@openssh.com", "signal"} {
			ok, err := sess.SendRequest(request, true, nil)
			require.NoError(t, err)
			require.False(t, ok, request)
		}
		_, err = guest.NewSession()
		require.Error(t, err, "a second session was opened")
		_, err = guest.Dial("tcp", "127.0.0.1:22")
		require.Error(t, err, "a direct TCP/IP channel was opened")
		_, err = guest.Listen("tcp", "127.0.0.1:0")
		require.Error(t, err, "remote forwarding was granted")
		ok, _, err := guest.SendRequest("streamlocal-forward@openssh.com", true, ssh.Marshal(&streamlocalChannelForwardMsg{SocketPath: host.id()}))
		require.NoError(t, err)
		require.False(t, ok)
		// The one session still shows the message.
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		require.NoError(t, sess.Shell())
		requireExit(t, sess.Wait(), 1)
		require.Equal(t, message, stdout.String())
	})

	t.Run("asking for nothing", func(t *testing.T) {
		guest := connect(t)
		ended := make(chan struct{})
		go func() { defer close(ended); _ = guest.Wait() }()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Fatal("an idle guest was kept past the handshake budget")
		}
	})

	require.Empty(t, host.guests.guests(), "a guest shown a message reached the host")
	_, unreached := authority.guests()
	require.Empty(t, unreached)
}

// A guest the authority refuses is refused as any unknown key is, and told
// nothing: no banner, no message, whatever the authority refused it for and
// whatever the refusal carried.
func TestRefusalTellsStrangersNothing(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	stranger := newProven(t).key

	refusals := map[string]func(context.Context, *Guest, GuestRequest) (Admission, error){
		"denied": nil,
		"denied, with a message": func(context.Context, *Guest, GuestRequest) (Admission, error) {
			return Admission{Verdict: VerdictDeny, Message: []byte("the session is not running (last seen unknown).\n"), Target: host.target("shell")}, nil
		},
		"an error": func(context.Context, *Guest, GuestRequest) (Admission, error) {
			return Admission{Verdict: VerdictMessage, Message: []byte("the session is reconnecting\n")}, errors.New("authority unavailable")
		},
		"an unknown verdict": func(context.Context, *Guest, GuestRequest) (Admission, error) {
			return Admission{Verdict: 7, Message: []byte("the session is reconnecting\n"), Target: host.target("shell")}, nil
		},
		"waiting on nothing": func(context.Context, *Guest, GuestRequest) (Admission, error) {
			return Admission{Verdict: VerdictWaiting, Message: []byte("Approve this SSH key\n")}, nil
		},
	}
	var first string
	for name, refusal := range refusals {
		t.Run(name, func(t *testing.T) {
			authority.admitWith(refusal)
			for _, user := range []string{claimPrefix + "work", claimPrefix + "missing", host.id()} {
				_, banners, err := dialDelegatedGuestAs(t, ts.addr, user, openSSHVersion, stranger)
				require.Error(t, err)
				require.Empty(t, *banners, "a refused guest was sent a banner")
				if first == "" {
					first = err.Error()
				}
				require.Equal(t, first, err.Error(), "refusals differ by what was refused")
			}
		})
	}
	require.Contains(t, first, "unable to authenticate")
	require.Empty(t, host.guests.guests())
	admissions, unreached := authority.guests()
	require.Len(t, admissions, 3*len(refusals), "a refusal was not the authority's")
	require.Empty(t, unreached)
}

// The zero Verdict is VerdictDeny, so an admission left empty refuses.
func TestVerdictZeroIsDeny(t *testing.T) {
	require.Equal(t, VerdictDeny, Verdict(0))
	require.Equal(t, []Verdict{0, 1, 2, 3}, []Verdict{VerdictDeny, VerdictAllow, VerdictMessage, VerdictWaiting})
}

// A guest offers its keys in turn on one connection, and the authority
// decides each as its own admission. Closing one it refused closes nothing:
// not the admission of the key it went on to allow, which only its own guest
// closes.
func TestRefusedGuestClosesNothing(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	refused, allowed := newProven(t).key, newProven(t).key
	guests := make(chan *Guest, 2)
	authority.admitWith(func(_ context.Context, g *Guest, _ GuestRequest) (Admission, error) {
		guests <- g
		if sameKey(g.Key, refused.PublicKey()) {
			return Admission{}, nil
		}
		return Admission{Verdict: VerdictAllow, Target: host.target("shell")}, nil
	})
	guest, err := ssh.Dial("tcp", ts.addr, &ssh.ClientConfig{
		User:            claimPrefix + "work",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(refused, allowed)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = guest.Close() })
	first, second := awaitGuest(t, guests), awaitGuest(t, guests)
	require.True(t, sameKey(first.Key, refused.PublicKey()))
	require.True(t, sameKey(second.Key, allowed.PublicKey()))
	require.NotNil(t, second.Home(), "an allowed guest was bound to no home")
	require.Equal(t, host.id(), second.Home().Ref().RoutingID)

	sess, err := guest.NewSession()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	returnsAtOnce(t, "Close", first.Close)
	returnsAtOnce(t, "ForceClose", first.ForceClose)
	_, err = io.WriteString(stdin, "still here")
	require.NoError(t, err)
	requireRead(t, stdout, "still here")
	select {
	case <-second.Done():
		t.Fatal("closing a refused key's guest closed the admission that followed it")
	default:
	}

	second.Close()
	requireDone(t, second, 10*time.Second)
}

// awaitGuest is the guest the authority was asked about next.
func awaitGuest(t *testing.T, guests <-chan *Guest) *Guest {
	t.Helper()
	select {
	case g := <-guests:
		return g
	case <-time.After(10 * time.Second):
		t.Fatal("the authority admitted no guest")
		return nil
	}
}

func requireDone(t *testing.T, g *Guest, within time.Duration) {
	t.Helper()
	select {
	case <-g.Done():
	case <-time.After(within):
		t.Fatalf("the guest's connection did not end within %s", within)
	}
}

// returnsAtOnce fails the test unless fn returns within a short bound,
// whatever it is waiting on.
func returnsAtOnce(t *testing.T, name string, fn func()) {
	t.Helper()
	returned := make(chan struct{})
	go func() { defer close(returned); fn() }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatalf("%s waited on something", name)
	}
}

// requireRead reads exactly want from r.
func requireRead(t *testing.T, r io.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, got)
		read <- err
	}()
	select {
	case err := <-read:
		require.NoError(t, err)
		require.Equal(t, want, string(got))
	case <-time.After(10 * time.Second):
		t.Fatalf("never read %q", want)
	}
}

// Closing an admitted guest never waits on what the guest, the host or the
// authority are blocked on: a host's output the guest has stopped reading, or
// a decision the authority has yet to make. Forced, the connection ends at
// once; in order, it ends no later than the relay's drain bound.
func TestBlockedCopyDoesNotBlockClosure(t *testing.T) {
	stalled := func(t *testing.T) (*Guest, *guestHost) {
		t.Helper()
		authority := &fakeAuthority{}
		ts := newDelegatedTestServer(t, authority)
		host := registerDelegatedHost(t, ts, externalSessionID)
		host.guests.flood.Store(true)
		guests := make(chan *Guest, 1)
		authority.admitWith(allowing(host.target("shell"), guests))
		guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, newProven(t).key)
		require.NoError(t, err)
		g := awaitGuest(t, guests)
		// A shell whose output is never read: the window fills, then the
		// relay's copy to the guest blocks, then the host's to the relay.
		ch, reqs, err := guest.OpenChannel("session", nil)
		require.NoError(t, err)
		go ssh.DiscardRequests(reqs)
		ok, err := ch.SendRequest("shell", true, nil)
		require.NoError(t, err)
		require.True(t, ok)
		var last int64
		require.Eventually(t, func() bool {
			n := host.guests.written.Load()
			still := n > 0 && n == last
			last = n
			return still
		}, 20*time.Second, 250*time.Millisecond, "the host's output never stalled")
		return g, host.guests
	}

	t.Run("forced", func(t *testing.T) {
		g, host := stalled(t)
		returnsAtOnce(t, "ForceClose", g.ForceClose)
		requireDone(t, g, 2*time.Second)
		for _, c := range host.opened() {
			select {
			case <-c.closed:
			case <-time.After(2 * time.Second):
				t.Fatal("the host's channel outlived the guest's connection")
			}
		}
	})

	t.Run("in order, then forced", func(t *testing.T) {
		g, _ := stalled(t)
		returnsAtOnce(t, "Close", g.Close)
		returnsAtOnce(t, "ForceClose", g.ForceClose)
		requireDone(t, g, 2*time.Second)
	})

	t.Run("in order alone", func(t *testing.T) {
		g, _ := stalled(t)
		returnsAtOnce(t, "Close", g.Close)
		requireDone(t, g, sshForwardDrainTimeout+5*time.Second)
	})

	for name, closeIt := range map[string]func(*Guest){"a pending decision, forced": (*Guest).ForceClose, "a pending decision, in order": (*Guest).Close} {
		t.Run(name, func(t *testing.T) {
			pendingDecision(t, closeIt)
		})
	}
}

// pendingDecision closes, with closeIt, a guest whose decision the authority
// holds until its context ends.
func pendingDecision(t *testing.T, closeIt func(*Guest)) {
	t.Helper()
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	guests := make(chan *Guest, 1)
	cancelled := make(chan struct{})
	authority.admitWith(func(ctx context.Context, g *Guest, _ GuestRequest) (Admission, error) {
		guests <- g
		<-ctx.Done()
		close(cancelled)
		return Admission{Verdict: VerdictAllow}, nil
	})
	// A guest that, refused, goes quiet rather than leaving: its second look
	// for a key waits until the test ends. Only the relay can end its
	// connection then.
	key := newProven(t).key
	quiet := make(chan struct{})
	var looked atomic.Int32
	keys := func() ([]ssh.Signer, error) {
		if looked.Add(1) > 1 {
			<-quiet
			return nil, errors.New("gone quiet")
		}
		return []ssh.Signer{key}, nil
	}
	dialed := make(chan error, 1)
	go func() {
		client, err := ssh.Dial("tcp", ts.addr, &ssh.ClientConfig{
			User:            claimPrefix + "work",
			Auth:            []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PublicKeysCallback(keys), 2)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		if err == nil {
			_ = client.Close()
		}
		dialed <- err
	}()
	g := awaitGuest(t, guests)
	returnsAtOnce(t, "closing", func() { closeIt(g) })
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the authority's decision outlived the connection it was for")
	}
	requireDone(t, g, 2*time.Second)
	close(quiet)
	require.Error(t, <-dialed)
	admissions, _ := authority.guests()
	require.Len(t, admissions, 1, "a closed connection's guest was asked about again")
}

// awaitChannels waits for the host to have been opened n channels.
func awaitChannels(t *testing.T, host *guestHost, n int) []*hostChannel {
	t.Helper()
	require.Eventually(t, func() bool { return len(host.opened()) >= n }, 5*time.Second, 10*time.Millisecond)
	return host.opened()
}

// Every channel an admitted guest has open closes with it -- its shell, its
// SFTP and its forwarding -- whether the authority closes it, in order or by
// force, or a final decision on its host's registration does. A final
// decision also withdraws that registration's route, while the host keeps
// its connection for its reports.
func TestRevocationClosesEveryChannel(t *testing.T) {
	type admitted struct {
		ts    *delegatedTestServer
		host  *delegatedHostFixture
		guest *Guest
		shell *ssh.Session
		sftp  *ssh.Session
		tcp   net.Conn
	}
	admit := func(t *testing.T, authority *fakeAuthority) admitted {
		t.Helper()
		ts := newDelegatedTestServer(t, authority)
		host := registerDelegatedHost(t, ts, externalSessionID)
		guests := make(chan *Guest, 1)
		authority.admitWith(allowing(host.target("shell", "exec", "sftp", "direct-tcpip"), guests))
		guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, newProven(t).key)
		require.NoError(t, err)
		a := admitted{ts: ts, host: host, guest: awaitGuest(t, guests)}
		a.shell, err = guest.NewSession()
		require.NoError(t, err)
		a.shell.Stdout = io.Discard
		require.NoError(t, a.shell.Shell())
		a.sftp, err = guest.NewSession()
		require.NoError(t, err)
		a.sftp.Stdout = io.Discard
		require.NoError(t, a.sftp.RequestSubsystem("sftp"))
		a.tcp, err = guest.Dial("tcp", "10.0.0.1:22")
		require.NoError(t, err)
		_, err = a.tcp.Write([]byte("ping"))
		require.NoError(t, err)
		buf := make([]byte, 4)
		_, err = io.ReadFull(a.tcp, buf)
		require.NoError(t, err)
		awaitChannels(t, host.guests, 3)
		return a
	}
	requireAllClosed := func(t *testing.T, a admitted) {
		t.Helper()
		for name, wait := range map[string]func() error{"shell": a.shell.Wait, "sftp": a.sftp.Wait} {
			ended := make(chan struct{})
			go func() { defer close(ended); _ = wait() }()
			select {
			case <-ended:
			case <-time.After(10 * time.Second):
				t.Fatalf("the guest's %s outlived its closure", name)
			}
		}
		read := make(chan error, 1)
		go func() {
			_, err := a.tcp.Read(make([]byte, 1))
			read <- err
		}()
		select {
		case err := <-read:
			require.Error(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("the guest's forwarding outlived its closure")
		}
		for _, c := range a.host.guests.opened() {
			select {
			case <-c.closed:
			case <-time.After(10 * time.Second):
				t.Fatalf("the host's %s channel outlived the guest's closure", c.kind)
			}
		}
	}

	t.Run("closed in order", func(t *testing.T) {
		a := admit(t, &fakeAuthority{})
		a.guest.Close()
		requireAllClosed(t, a)
		requireDone(t, a.guest, 10*time.Second)
	})

	t.Run("closed by force", func(t *testing.T) {
		a := admit(t, &fakeAuthority{})
		a.guest.ForceClose()
		requireAllClosed(t, a)
		requireDone(t, a.guest, 10*time.Second)
	})

	finalDecision := func(t *testing.T, authority *fakeAuthority, decide func(t *testing.T, a admitted)) {
		a := admit(t, authority)
		decide(t, a)
		requireAllClosed(t, a)
		_, err := a.ts.SessionManager.GetSession(a.host.id())
		require.Error(t, err, "a final decision left the registration's route")

		// A stale allow can't reach a retired home.
		_, _, err = dialDelegatedGuestAs(t, a.ts.addr, claimPrefix+"work", openSSHVersion, newProven(t).key)
		require.Error(t, err)
		require.Len(t, a.host.guests.guests(), 1)

		// The host is still connected, for its reports.
		ok, body := sendControl(t, a.host.client, ready(2))
		require.True(t, ok, "%q", body)
	}

	t.Run("a pushed final decision", func(t *testing.T) {
		finalDecision(t, &fakeAuthority{}, func(t *testing.T, a admitted) {
			// The host refuses the decision; the relay withdraws the route
			// whatever it answers.
			_, err := a.ts.runtime().PushDecision(t.Context(), &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2})
			require.Error(t, err)
		})
	})

	t.Run("a final control reply", func(t *testing.T) {
		authority := &fakeAuthority{}
		finalDecision(t, authority, func(t *testing.T, a admitted) {
			authority.answer(nil, func(c Report) (*DelegatedControlReply, error) {
				return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: c.Request.Sequence, Disposition: DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: 2}, nil
			})
			ok, body := sendControl(t, a.host.client, ready(1))
			require.True(t, ok, "%q", body)
		})
	})

	t.Run("a current decision", func(t *testing.T) {
		a := admit(t, &fakeAuthority{})
		_, _ = a.ts.runtime().PushDecision(t.Context(), &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 2})
		_, err := a.ts.SessionManager.GetSession(a.host.id())
		require.NoError(t, err, "a current decision withdrew the route")
		_, err = a.tcp.Write([]byte("ping"))
		require.NoError(t, err)
		_, err = io.ReadFull(a.tcp, make([]byte, 4))
		require.NoError(t, err, "a current decision closed a guest")
	})
}

// An admitted guest can do what its admission's capabilities allow and
// nothing else: whatever the authority left out, and agent forwarding, X11
// and remote forwarding, which no capability allows, are refused at the relay
// and never reach the host, each in its turn.
func TestDelegatedCapabilitiesBoundTheGuest(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	guestKey := newProven(t).key
	connect := func(t *testing.T, capabilities ...string) *ssh.Client {
		t.Helper()
		authority.admitWith(allowing(host.target(capabilities...), nil))
		guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, guestKey)
		require.NoError(t, err)
		return guest
	}
	requests := func() []string {
		var all []string
		for _, c := range host.guests.opened() {
			all = append(all, c.asked()...)
		}
		return all
	}

	t.Run("shell only", func(t *testing.T) {
		guest := connect(t, "shell")
		sess, err := guest.NewSession()
		require.NoError(t, err)
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		require.Error(t, sess.Start("uptime"), "exec was allowed")
		require.Error(t, sess.RequestSubsystem("sftp"), "sftp was allowed")
		for _, request := range []string{"x11-req", "auth-agent-req@openssh.com"} {
			ok, err := sess.SendRequest(request, true, nil)
			require.NoError(t, err)
			require.False(t, ok, request)
		}
		require.NoError(t, sess.Shell())
		_, err = guest.Dial("tcp", "10.0.0.1:22")
		require.Error(t, err, "forwarding was allowed")
		_, err = guest.Listen("tcp", "127.0.0.1:0")
		require.Error(t, err, "remote forwarding was allowed")
		awaitChannels(t, host.guests, 1)
		require.Eventually(t, func() bool { return len(requests()) == 2 }, 5*time.Second, 10*time.Millisecond)
		require.Equal(t, []string{"pty-req", "shell"}, requests())
		_ = sess.Close()
	})

	t.Run("an unknown capability", func(t *testing.T) {
		guest := connect(t, "everything")
		_, err := guest.NewSession()
		require.Error(t, err, "a session was opened")
	})

	t.Run("every capability", func(t *testing.T) {
		guest := connect(t, "shell", "exec", "sftp", "direct-tcpip")
		before := len(host.guests.opened())
		exec, err := guest.NewSession()
		require.NoError(t, err)
		require.NoError(t, exec.Start("uptime"))
		sftp, err := guest.NewSession()
		require.NoError(t, err)
		require.NoError(t, sftp.RequestSubsystem("sftp"))
		tcp, err := guest.Dial("tcp", "10.0.0.1:22")
		require.NoError(t, err)
		opened := awaitChannels(t, host.guests, before+3)[before:]
		kinds := map[string]int{}
		for _, c := range opened {
			kinds[c.kind]++
		}
		require.Equal(t, map[string]int{"session": 2, "direct-tcpip": 1}, kinds)
		_ = tcp.Close()
		_ = exec.Close()
		_ = sftp.Close()
	})
}

// A host opens nothing toward an admitted guest: agent forwarding, remote
// forwarding and X11 channels, which no capability allows, are refused at the
// relay as prohibited, and the guest is never asked.
func TestDelegatedHostOpensNothingTowardTheGuest(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	authority.admitWith(allowing(host.target("shell", "exec", "sftp", "direct-tcpip"), nil))

	// The guest's own connection, so that every channel opened toward it, of
	// whatever type, reaches the test.
	var served sync.WaitGroup
	t.Cleanup(served.Wait)
	nc, err := net.DialTimeout("tcp", ts.addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nc.Close() })
	guest, opens, requests, err := ssh.NewClientConn(nc, ts.addr, &ssh.ClientConfig{
		User:            claimPrefix + "work",
		ClientVersion:   openSSHVersion,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newProven(t).key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = guest.Close() })
	asked := make(chan string, 16)
	served.Go(func() { ssh.DiscardRequests(requests) })
	served.Go(func() {
		for open := range opens {
			asked <- open.ChannelType()
			_ = open.Reject(ssh.ConnectionFailed, "the guest was asked")
		}
	})

	toGuest := host.guests.connection(t, 1)
	for _, kind := range []string{"auth-agent@openssh.com", "forwarded-tcpip", "x11"} {
		_, _, err := toGuest.OpenChannel(kind, nil)
		var refused *ssh.OpenChannelError
		require.ErrorAs(t, err, &refused, kind)
		require.Equal(t, ssh.Prohibited, refused.Reason, kind)
		require.Equal(t, errNotPermitted, refused.Message, kind)
	}
	// Each open was answered before the next was sent, so none of them is
	// still on its way to the guest.
	select {
	case kind := <-asked:
		t.Fatalf("the relay asked the guest to take a %s channel", kind)
	default:
	}
}

// A relay with an authority that admits nobody admits no guest, even one
// naming a current delegated session whose host takes guests; the same host
// and guests on a relay with nothing composed get in.
func TestDelegatedRelayRefusesGuestsWithoutAnAllow(t *testing.T) {
	guestKey := newProven(t).key
	versions := []string{openSSHVersion, upterm.ClientSSHClientVersion}

	standalone := newServingTestServer(t, slog.New(slog.DiscardHandler))
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	host := newProven(t)
	client := dialHost(t, standalone.sshAddr, signer, nil)
	ok, body := host.register(t, client, string(client.SessionID()), 1)
	require.True(t, ok, "%q", body)
	var resp CreateSessionResponse
	require.NoError(t, proto.Unmarshal(body, &resp))
	echoGuests(t, client, host.key, host.id())
	for _, version := range versions {
		guest, _, err := dialDelegatedGuestAs(t, standalone.sshAddr, resp.SshUser, version, guestKey)
		require.NoError(t, err, version)
		_ = guest.Close()
	}

	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	delegated := registerDelegatedHost(t, ts, externalSessionID)
	for _, version := range versions {
		for _, user := range []string{delegated.user, delegated.id(), claimPrefix + "work"} {
			_, _, err := dialDelegatedGuestAs(t, ts.addr, user, version, guestKey)
			require.Error(t, err, "a relay with an authority admitted a %s guest as %s", version, user)
		}
	}
	require.Empty(t, delegated.guests.guests())
	admissions, _ := authority.guests()
	require.Len(t, admissions, 3*len(versions), "a refusal was not the authority's")
}

// A guest's user is classified the same way in both routing modes, before
// the authority hears of it: a relay session ID, with or without a node
// address, is never offered to Claims, and every other user is, exactly
// once per key it offers and once more when it signs. The one difference
// routing makes: Consul routing reads a suffix that isn't a node address as
// no part of the session ID, so with nothing composed such a user reaches
// the session, and with an authority composed it is no session ID, and is
// refused as unknown.
func TestClassificationInBothRoutingModes(t *testing.T) {
	sessionIDs := []string{"abcdefghijklmnopqrst", "abcdefghijklmnopqrst:", "abcdefghijklmnopqrst:bm9kZQ==", "Abcdefghijklmnopqrs1"}
	offered := []string{claimPrefix + "alice", "abc", "abcdefghijklmnopqrstu", "a.b", "abcdefghijklmnopqrst:!!"}
	for _, user := range sessionIDs {
		require.True(t, isSessionUser(user), user)
	}
	for _, user := range offered {
		require.False(t, isSessionUser(user), user)
	}
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			// A remote session's home, reached over a hop: a node from before
			// the gate, which serves whatever hop it is sent.
			upstream, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
			node := func(authority Authority) (*sshProxy, string) {
				proxy, addr, _, _ := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: upstream}, func(p *sshProxy) {
					p.listener = listenerPublic
					p.authorities = &gateFixtureRegistry{}
					p.NodeID = "ingress-machine"
					p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(p.Logger), routing.NewEncodeDecoder(mode))
					if authority != nil {
						p.authority, p.AuthorityEnabled, p.AuthorityComposed = authority, true, true
					}
					_, err := p.SessionManager.CreateSession(&Session{ID: "abcdefghijklmnopqrst", NodeAddr: "legacy:2222", HostPublicKeys: []ssh.PublicKey{p.HostSigners[0].PublicKey()}})
					require.NoError(t, err)
				})
				return proxy, addr
			}
			authority := &fakeAuthority{}
			_, composed := node(authority)
			key := certTestSigner(t)
			var want []string
			for _, user := range append(append([]string(nil), sessionIDs...), offered...) {
				guest, _, err := dialDelegatedGuestAs(t, composed, user, openSSHVersion, key)
				if err == nil {
					_ = guest.Close()
				}
				if isSessionUser(user) {
					continue
				}
				want = append(want, user)
				if strings.HasPrefix(user, claimPrefix) {
					// Asked again once it signed, and then refused by Admit.
					want = append(want, user)
				}
			}
			require.Equal(t, want, authority.claims(), "Claims was asked about other users than these")
			admissions, _ := authority.guests()
			require.Len(t, admissions, 1, "only the claimed user reached Admit")
			require.Equal(t, claimPrefix+"alice", admissions[0].request.User)

			const suffixed = "abcdefghijklmnopqrst:!!"
			_, plain := node(nil)
			guest, _, err := dialDelegatedGuestAs(t, plain, suffixed, openSSHVersion, key)
			if mode == routing.ModeConsul {
				require.NoError(t, err, "nothing composed, Consul routing no longer reads %q as its session", suffixed)
				_ = guest.Close()
			} else {
				require.Error(t, err, "embedded routing read %q as a session", suffixed)
			}
			_, _, err = dialDelegatedGuestAs(t, composed, suffixed, openSSHVersion, key)
			require.Error(t, err, "with an authority composed, %q reached a session", suffixed)
		})
	}
}

// A relay session ID's guest is never shown a message or a waiting screen:
// from the authority, either is taken as a refusal, as any unknown key's. A
// claimed user's is shown it.
func TestMessagesAndWaitingOnlyForClaimedUsers(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := registerDelegatedHost(t, ts, externalSessionID)
	key := newProven(t).key
	verdicts := map[string]func(context.Context, *Guest, GuestRequest) (Admission, error){
		"message": showing("the session is reconnecting\n"),
		"waiting": func(_ context.Context, g *Guest, req GuestRequest) (Admission, error) {
			return Admission{Verdict: VerdictWaiting, Message: []byte("Approve this key\n"), Waiting: &WaitingScreen{
				OfferID: fixtureAccountID, AttemptID: externalSessionID, Address: req.User, KeyFingerprint: g.Fingerprint,
				ExpiredMessage: []byte("expired\n"), ApprovedMessage: []byte("approved\n"), Expires: time.Now().Add(time.Minute),
				Await: func(ctx context.Context) (Target, error) { <-ctx.Done(); return Target{}, ctx.Err() },
			}}, nil
		},
	}
	for name, verdict := range verdicts {
		t.Run(name, func(t *testing.T) {
			authority.admitWith(verdict)
			for _, user := range []string{host.id(), host.user} {
				_, banners, err := dialDelegatedGuestAs(t, ts.addr, user, openSSHVersion, key)
				require.ErrorContains(t, err, "unable to authenticate", "a session ID's guest was let in to be shown a %s", name)
				require.Empty(t, *banners)
			}
			guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, key)
			require.NoError(t, err, "a claimed user wasn't shown its %s", name)
			_ = guest.Close()
		})
	}
	admissions, _ := authority.guests()
	require.Len(t, admissions, 3*len(verdicts))
	require.Empty(t, host.guests.guests())
}

// An allow is checked once more just before forwarding begins: one that
// expires meanwhile is refused, and the guest's host is opened no channel,
// while one that lasts is forwarded.
func TestExpiredAllowNeverForwards(t *testing.T) {
	for _, lasts := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "lasting"}[lasts], func(t *testing.T) {
			arrived, release := make(chan time.Time, 1), make(chan struct{})
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority, func(s *Server) { s.beforeGuestForward = func() { arrived <- time.Now(); <-release } })
			host := registerDelegatedHost(t, ts, externalSessionID)
			untils := make(chan time.Time, 1)
			authority.admitWith(func(context.Context, *Guest, GuestRequest) (Admission, error) {
				until := time.Now().Add(2 * time.Second)
				if lasts {
					until = time.Now().Add(time.Hour)
				}
				untils <- until
				return Admission{Verdict: VerdictAllow, Sequence: 1, AllowUntil: until, Target: host.target("shell")}, nil
			})
			key := newProven(t).key
			// The guest opens a session once it is in: the host is opened a
			// channel only once forwarding has begun.
			opened := make(chan error, 1)
			go func() {
				opened <- func() error {
					nc, err := net.DialTimeout("tcp", ts.addr, 10*time.Second)
					if err != nil {
						return err
					}
					c, chans, reqs, err := ssh.NewClientConn(nc, ts.addr, &ssh.ClientConfig{User: claimPrefix + "work", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
					if err != nil {
						_ = nc.Close()
						return err
					}
					client := ssh.NewClient(c, chans, reqs)
					defer func() { _ = client.Close() }()
					sess, err := client.NewSession()
					if err != nil {
						return err
					}
					return sess.Close()
				}()
			}()
			var at time.Time
			select {
			case at = <-arrived:
			case <-time.After(10 * time.Second):
				t.Fatal("the allowed guest's forwarding never began")
			}
			until := <-untils
			require.True(t, at.Before(until), "the hook arrived once the allow had expired, so it tests nothing")
			if !lasts {
				for !time.Now().After(until) {
					time.Sleep(time.Until(until) + time.Millisecond)
				}
			}
			close(release)
			select {
			case err := <-opened:
				if lasts {
					require.NoError(t, err)
				} else {
					require.Error(t, err, "an expired allow was forwarded")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the guest went on")
			}
			if lasts {
				awaitChannels(t, host.guests, 1)
			} else {
				require.Empty(t, host.guests.opened(), "an expired allow's host was opened a channel")
			}
		})
	}
}

// unreachableAuthority hands each Unreachable call's context to calls and
// answers with text once release is closed or the context ends.
type unreachableAuthority struct {
	*fakeAuthority
	calls   chan context.Context
	release chan struct{}
	text    string
}

func (a *unreachableAuthority) Unreachable(ctx context.Context, _ *Guest, _ Target) []byte {
	a.calls <- ctx
	select {
	case <-a.release:
	case <-ctx.Done():
	}
	return []byte(a.text)
}

// A guest allowed to a target the relay can't reach is shown what the
// authority says of it, as a message is shown. The authority's context ends
// with the guest, or once half the handshake's budget has passed.
func TestUnreachableIsBoundedAndShownAsAMessage(t *testing.T) {
	for _, ends := range []string{"budget", "guest", "answered"} {
		t.Run(ends, func(t *testing.T) {
			client, peer := forwardTestPair(t, nil, nil)
			guest := ssh.NewClient(client.conn, client.channels, client.requests)
			t.Cleanup(func() { _ = guest.Close() })
			stage := 10 * time.Second
			if ends == "budget" {
				stage = time.Second
			}
			authority := &unreachableAuthority{fakeAuthority: &fakeAuthority{}, calls: make(chan context.Context, 1), release: make(chan struct{}), text: "the \x1b[31msession\x07 is unreachable\n"}
			g := newGuestConn(t.Context(), nil)
			g.authenticated = true
			g.guest = &Guest{ConnectionID: "unreachable", conn: g}
			g.admission = Admission{Verdict: VerdictAllow, Target: Target{RoutingID: sessionRoute, Capabilities: []string{"shell"}}}
			routing := &SSHRouting{Auth: &proxyAuth{authority: authority}}
			before := time.Now()
			served := make(chan error, 1)
			go func() {
				served <- routing.serveDelegatedGuest(t.Context(), g, peer, stage, newSSHRoutingInstruments(provider.NewDiscardProvider()))
			}()
			var ctx context.Context
			select {
			case ctx = <-authority.calls:
			case <-time.After(10 * time.Second):
				t.Fatal("the authority was never asked what to show")
			}
			after := time.Now()
			deadline, ok := ctx.Deadline()
			require.True(t, ok, "the authority's context has no deadline")
			require.False(t, deadline.Before(before.Add(stage)) || deadline.After(after.Add(stage)), "the authority's context ends at %v, not half the handshake's budget after it was asked", deadline.Sub(before))
			switch ends {
			case "budget":
				select {
				case <-ctx.Done():
					require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
				case <-time.After(10 * time.Second):
					t.Fatal("the authority's context outlived the budget")
				}
			case "guest":
				g.guest.Close()
				select {
				case <-ctx.Done():
					require.ErrorIs(t, ctx.Err(), context.Canceled)
				case <-time.After(time.Second):
					t.Fatal("the authority's context outlived the guest")
				}
				require.NoError(t, <-served)
				return
			case "answered":
				close(authority.release)
			}
			stdout, _, err := runSession(t, guest, true, "")
			requireExit(t, err, 1)
			require.Equal(t, "the �[31msession� is unreachable\r\n", stdout)
			require.NoError(t, <-served)
		})
	}
}

// A dark authority decides nothing, and is asked nothing: a user it would
// claim is no session ID, and is refused as unknown, and a delegated
// session's guest is refused as unknown too.
func TestDarkAuthorityIsAskedNothing(t *testing.T) {
	authority := &fakeAuthority{}
	authority.admitWith(showing("unexpected authority call\n"))
	ts := newDelegatedTestServer(t, authority, func(s *Server) { s.Extensions.Enabled = false })
	key := newProven(t).key
	for _, user := range []string{claimPrefix + "work", sessionRoute} {
		_, banners, err := dialDelegatedGuestAs(t, ts.addr, user, openSSHVersion, key)
		require.ErrorContains(t, err, "unable to authenticate", user)
		require.Empty(t, *banners)
	}
	require.Zero(t, authority.calls(), "a dark authority was asked")
}

// Admit is asked with what is left of the handshake's budget, half of the
// handshake timeout from when the connection came in, and never more than 5
// seconds.
func TestAdmitKeepsTheHandshakeBudget(t *testing.T) {
	for _, tc := range []struct {
		handshake, budget time.Duration
	}{{6 * time.Second, 3 * time.Second}, {30 * time.Second, 5 * time.Second}} {
		t.Run(tc.handshake.String(), func(t *testing.T) {
			type asked struct {
				at       time.Time
				deadline time.Time
				ok       bool
			}
			calls := make(chan asked, 1)
			authority := &fakeAuthority{}
			authority.admitWith(func(ctx context.Context, _ *Guest, _ GuestRequest) (Admission, error) {
				deadline, ok := ctx.Deadline()
				calls <- asked{time.Now(), deadline, ok}
				return Admission{}, nil
			})
			ts := newDelegatedTestServer(t, authority, func(s *Server) { s.HandshakeTimeout = tc.handshake })
			before := time.Now()
			_, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, newProven(t).key)
			require.Error(t, err)
			a := <-calls
			require.True(t, a.ok, "Admit's context has no deadline")
			require.False(t, a.deadline.Before(before.Add(tc.budget)) || a.deadline.After(a.at.Add(tc.budget)),
				"Admit's context ends %v after the dial, not within its budget of %v", a.deadline.Sub(before), tc.budget)
		})
	}
}

// An allow without a sequence binds the guest to nothing, and is refused
// before the guest reaches its target, whether its home is on this node or on
// another: the guest's connection is closed as it authenticates, as an allowed
// guest's is whenever its admission fails. The same allow with a sequence
// admits it.
func TestAllowWithoutASequenceIsRefused(t *testing.T) {
	t.Run("a home on this node", func(t *testing.T) {
		for _, sequence := range []uint64{0, 1} {
			authority := &fakeAuthority{asIs: true}
			ts := newDelegatedTestServer(t, authority)
			host := registerDelegatedHost(t, ts, externalSessionID)
			authority.admitWith(func(context.Context, *Guest, GuestRequest) (Admission, error) {
				return Admission{Verdict: VerdictAllow, Sequence: sequence, AllowUntil: time.Now().Add(45 * time.Second), Target: host.target("shell")}, nil
			})
			guest, _, err := dialDelegatedGuestAs(t, ts.addr, claimPrefix+"work", openSSHVersion, newProven(t).key)
			if sequence == 0 {
				require.Error(t, err, "an allow without a sequence admitted the guest")
				require.Empty(t, host.guests.guests(), "an allow without a sequence reached the host")
				continue
			}
			require.NoError(t, err, "an allow with a sequence was refused")
			_ = guest.Close()
			require.Eventually(t, func() bool { return len(host.guests.guests()) == 1 }, 5*time.Second, 10*time.Millisecond)
		}
	})

	t.Run("a home on another node", func(t *testing.T) {
		for _, sequence := range []uint64{0, 1} {
			home := delegatedGateHome(t)
			authority := &fakeAuthority{asIs: true}
			authority.admitWith(func(context.Context, *Guest, GuestRequest) (Admission, error) {
				allow := homeAllow(home, time.Now().Add(45*time.Second))
				allow.Sequence = sequence
				return allow, nil
			})
			_, addr, _, signer := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: home.addr}, enabledIngress(authority, home))
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sessionRoute, "home:2222")
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
			if sequence == 0 {
				require.Error(t, err, "an allow without a sequence admitted the guest")
				require.Zero(t, home.dialer.calls.Load(), "an allow without a sequence reached the home's host")
				continue
			}
			require.NoError(t, err, "an allow with a sequence was refused")
			_ = c.Close()
			require.Eventually(t, func() bool { return home.dialer.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
		}
	})
}

// A verdict Admit returns once its context has ended is refused, as a late
// allow is, whatever it is: the guest is refused as any unknown key is, and
// shown no message and no screen. The same verdicts returned in time are
// shown.
func TestLateVerdictIsRefused(t *testing.T) {
	for _, verdict := range []string{"message", "waiting"} {
		for _, late := range []bool{true, false} {
			t.Run(verdict+map[bool]string{true: "/late", false: "/in time"}[late], func(t *testing.T) {
				// A late verdict waits out Admit's 5 s, so the cases run
				// side by side.
				t.Parallel()
				a := newApproval(time.Now().Add(time.Minute))
				decide := showing("the session is reconnecting\n")
				if verdict == "waiting" {
					decide = waitingOn(waitingMessage, a)
				}
				authority := &fakeAuthority{}
				authority.admitWith(func(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
					if late {
						<-ctx.Done()
					}
					return decide(ctx, g, req)
				})
				// A handshake long enough that Admit's 5 s, not the
				// handshake's budget, ends first.
				ts := newDelegatedTestServer(t, authority, func(s *Server) { s.HandshakeTimeout = 12 * time.Second })
				guest, banners, err := dialDelegatedGuestAs(t, ts.addr, waitingUser, openSSHVersion, newProven(t).key)
				if late {
					require.ErrorContains(t, err, "unable to authenticate", "a %s verdict returned after Admit's deadline let the guest in", verdict)
					require.Empty(t, *banners)
					return
				}
				require.NoError(t, err, "a %s verdict returned in time was refused", verdict)
				if verdict == "waiting" {
					startWaitingShell(t, guest, a, waitingMessage, nil, "")
					return
				}
				stdout, _, err := runSession(t, guest, false, "")
				requireExit(t, err, 1)
				require.Equal(t, "the session is reconnecting\n", stdout)
			})
		}
	}
}
