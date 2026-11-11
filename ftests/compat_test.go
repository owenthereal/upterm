//go:build compat

package ftests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// The builds this build's relay must share a fleet with: the releases v0.40.0
// and v0.41.1, and a72f5571, a master commit between them. make test-compat
// installs each into UPTERM_COMPAT_BIN/<name>/.
var compatBaselines = []string{"v0.40.0", "a72f5571", "v0.41.1"}

// The releases whose upterm hosts read this build's relay version. Both read
// the whole version, which this build's own client no longer does.
var compatHostReleases = []string{"v0.40.0", "v0.41.1"}

// compatJoinBound is how long a cross-node join may take on listeners that
// accept a PROXY header. Such a listener's banner waits on the client's first
// bytes, for up to 10 s, so a hop client that read the banner before writing
// would take that long.
const compatJoinBound = 5 * time.Second

// compatQuietBound is how long a host is watched for an authentication that
// must never come. A home that dials its host does so within milliseconds of
// the hop authenticating.
const compatQuietBound = time.Second

// TestMixedVersionFleets runs this build's relay beside released ones, each
// started with the flags it supports, laid out as a fleet migrating to this
// build is: this build's nodes have a public listener and an internal one,
// which their route records name, and the released ones keep the listeners
// they have.
func TestMixedVersionFleets(t *testing.T) {
	bins := compatBinDir(t)
	newRelay := buildThisRelay(t)
	darkRelay := buildRelay(t, "./testdata/darkrelay")
	keys := compatKeys(t)

	for _, old := range compatBaselines {
		oldRelay := filepath.Join(bins, old, "uptermd")
		require.FileExists(t, oldRelay, "make test-compat installs it")
		t.Run(old, func(t *testing.T) {
			for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
				t.Run(string(mode), func(t *testing.T) {
					consul := compatConsul(t, mode)
					// The old node as the fleet has it: an internal listener
					// where its build has one.
					oldNode := func(t *testing.T) *compatRelay {
						return startCompatRelay(t, old, oldRelay, keys, compatLayout{mode: mode, consul: consul, internal: old != "v0.40.0"})
					}

					t.Run("nothing composed", func(t *testing.T) {
						n := startCompatRelay(t, "new", newRelay, keys, compatLayout{mode: mode, consul: consul, internal: true})
						o := oldNode(t)
						for _, tc := range []struct {
							name        string
							home, entry *compatRelay
						}{
							{name: "old to new", home: n, entry: o},
							{name: "new to old", home: o, entry: n},
						} {
							t.Run(tc.name, func(t *testing.T) {
								s := shareOn(t, tc.home, keys)
								guest := requireCompatJoin(t, s, tc.entry, keys)
								// Today's format: the hop's user is the user the
								// guest typed, and its AuthRequest has none of the
								// gate's fields.
								require.Equal(t, s.user, guest.user)
								require.Zero(t, guest.auth.GateProtocol)
								require.Empty(t, guest.auth.TypedAddress)
								require.Empty(t, guest.auth.TargetRoutingId)
								require.Empty(t, guest.auth.IngressNodeId)
								require.Empty(t, guest.auth.ConnectionId)
							})
						}
					})

					t.Run("legacy hops refused on the new node", func(t *testing.T) {
						n := startCompatRelay(t, "new", newRelay, keys, compatLayout{mode: mode, consul: consul, internal: true, refuseLegacyHops: true})
						o := oldNode(t)
						// The old node hops to the new one, which refuses the
						// legacy hop.
						requireCompatRefused(t, shareOn(t, n, keys), o, n, upterm.UpstreamAuthFailed, keys)
						// The new node hops to the old one through the gate. In
						// Consul routing the old node authenticates the gate hop
						// and, as it does every hop, dials its host at once, so the
						// host sees the gate hop authenticate. The new node then
						// refuses to go on without the token, and no session
						// channel is ever opened at the host. In embedded routing
						// the old node can't decode the gate hop's user, the bare
						// routing ID, and refuses it first.
						if mode == routing.ModeConsul {
							requireCompatRefusedAfterHomeAuth(t, shareOn(t, o, keys), n, keys)
						} else {
							requireCompatRefused(t, shareOn(t, o, keys), n, nil, upterm.UpstreamAuthFailed, keys)
						}
						requireCompatJoin(t, shareOn(t, n, keys), n, keys)
						requireCompatJoin(t, shareOn(t, o, keys), o, keys)
					})

					// The new node with an authority composed, dark, and legacy
					// hops accepted, as a fleet's first node with one is: it
					// gates its own hops, and falls back to today's handling
					// toward the old node, which has no token. In Consul
					// routing the old node serves that hop, whose user is the
					// routing ID it expects; in embedded routing it can't
					// decode that user, and refuses it. With an authority
					// composed, a guest's hop is made as the guest
					// authenticates, so that refusal is the guest's own.
					t.Run("dark authority on the new node", func(t *testing.T) {
						n := startCompatRelay(t, "dark", darkRelay, keys, compatLayout{mode: mode, consul: consul, internal: true})
						o := oldNode(t)
						requireCompatJoin(t, shareOn(t, n, keys), o, keys)
						if mode == routing.ModeConsul {
							s := shareOn(t, o, keys)
							guest := requireCompatJoin(t, s, n, keys)
							require.Equal(t, s.user, guest.user, "the hop's user is the routing ID, which is the user here")
						} else {
							requireCompatRefusedAtEntry(t, shareOn(t, o, keys), n, keys)
						}
						requireCompatJoin(t, shareOn(t, n, keys), n, keys)
						requireCompatJoin(t, shareOn(t, o, keys), o, keys)
					})

					// Every node behind a PROXY-protocol listener shared with
					// hops: the server speaks second there.
					t.Run("shared PROXY listeners", func(t *testing.T) {
						shared := compatLayout{mode: mode, consul: consul, proxy: true}
						t.Run("legacy hops accepted", func(t *testing.T) {
							n1 := startCompatRelay(t, "new", newRelay, keys, shared)
							n2 := startCompatRelay(t, "new", newRelay, keys, shared)
							o := startCompatRelay(t, old, oldRelay, keys, shared)
							for _, pair := range [][2]*compatRelay{{n1, n2}, {n2, n1}, {n1, o}, {o, n1}} {
								requireCompatJoinWithin(t, shareOn(t, pair[0], keys), pair[1], keys)
							}
						})
						t.Run("legacy hops refused", func(t *testing.T) {
							gating := shared
							gating.refuseLegacyHops = true
							n1 := startCompatRelay(t, "new", newRelay, keys, gating)
							n2 := startCompatRelay(t, "new", newRelay, keys, gating)
							for _, pair := range [][2]*compatRelay{{n1, n2}, {n2, n1}} {
								guest := requireCompatJoinWithin(t, shareOn(t, pair[0], keys), pair[1], keys)
								require.NotEmpty(t, guest.auth.TargetRoutingId, "the join didn't go through the gate")
							}
						})
					})
				})
			}
		})
	}

	// A host on a release reads this build's relay version: it warns only
	// where a node that gates advertises the token on a listener hosts use.
	for _, release := range compatHostReleases {
		t.Run(release+" upterm host", func(t *testing.T) {
			cli := filepath.Join(bins, release, "upterm")
			require.FileExists(t, cli, "make test-compat installs it")
			shared := startCompatRelay(t, "new", newRelay, keys, compatLayout{mode: routing.ModeEmbedded, ws: true})
			split := startCompatRelay(t, "new", newRelay, keys, compatLayout{mode: routing.ModeEmbedded, internal: true, ws: true})
			for _, tc := range []struct{ name, server string }{
				{"shared SSH listener", "ssh://" + shared.ssh},
				{"public SSH listener", "ssh://" + split.ssh},
				{"WebSocket beside a shared listener", "ws://" + shared.ws},
				{"WebSocket beside an internal listener", "ws://" + split.ws},
			} {
				t.Run(tc.name, func(t *testing.T) {
					stderr, log := hostWithCLI(t, cli, tc.server, keys)
					require.NotContains(t, stderr, "didn't report a version")
					require.NotContains(t, log, "server version mismatch")
				})
			}
			// The control: a shared listener of a node that gates advertises
			// the token, and this release can't read that version.
			gating := startCompatRelay(t, "new", newRelay, keys, compatLayout{mode: routing.ModeEmbedded, refuseLegacyHops: true})
			stderr, log := hostWithCLI(t, cli, "ssh://"+gating.ssh, keys)
			require.Contains(t, stderr, "didn't report a version")
			require.Contains(t, log, "server version mismatch")
		})
	}
}

// compatBinDir is where make test-compat installed the released builds.
func compatBinDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("UPTERM_COMPAT_BIN")
	if dir == "" {
		dir = filepath.Join("..", "bin", "compat")
	}
	abs, err := filepath.Abs(dir)
	require.NoError(t, err)
	require.DirExists(t, abs, "run make test-compat, which installs the released builds")
	return abs
}

// buildThisRelay builds this checkout's uptermd.
func buildThisRelay(t *testing.T) string {
	t.Helper()
	return buildRelay(t, "github.com/owenthereal/upterm/cmd/uptermd")
}

// buildRelay builds the uptermd at pkg, this checkout's.
func buildRelay(t *testing.T, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "uptermd")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building this checkout's uptermd: %s", output)
	return out
}

// compatKeyFiles are the fleet's key files: one relay key every node holds, as
// a fleet's nodes do, and the host's and guest's.
type compatKeyFiles struct {
	relayFile, hostFile string
	relay, host, guest  ssh.Signer
}

func compatKeys(t *testing.T) compatKeyFiles {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) (string, ssh.Signer) {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		signer, err := ssh.ParsePrivateKey([]byte(content))
		require.NoError(t, err)
		return path, signer
	}
	relayFile, relay := write("relay_key", ServerPrivateKeyContent)
	hostFile, host := write("host_key", HostPrivateKeyContent)
	_, guest := write("guest_key", ClientPrivateKeyContent)
	return compatKeyFiles{relayFile: relayFile, hostFile: hostFile, relay: relay, host: host, guest: guest}
}

// compatConsul is the Consul URL a fleet in mode shares, under a key prefix of
// its own that the test removes; "" in embedded routing.
func compatConsul(t *testing.T, mode routing.Mode) string {
	t.Helper()
	if mode != routing.ModeConsul {
		return ""
	}
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	u, err := url.Parse(testhelpers.ConsulURL())
	require.NoError(t, err)
	prefix := fmt.Sprintf("uptermd-compat-%d", time.Now().UnixNano())
	u.Path = "/" + prefix
	t.Cleanup(func() {
		client, err := consulTestClient()
		require.NoError(t, err)
		defer client.transport.CloseIdleConnections()
		_, err = client.KV().DeleteTree(prefix+"/", nil)
		require.NoError(t, err)
		_, err = client.Catalog().Deregister(&api.CatalogDeregistration{Node: prefix + "/" + server.DefaultKeyPrefix}, nil)
		require.NoError(t, err)
	})
	return u.String()
}

// compatLayout is a node's listeners and settings.
type compatLayout struct {
	mode             routing.Mode
	consul           string
	internal         bool // a public listener and an internal one, which the node's records name
	proxy            bool // the SSH listener accepts a PROXY header
	ws               bool
	refuseLegacyHops bool
}

// compatRelay is a running uptermd.
type compatRelay struct {
	name              string
	ssh, internal, ws string
	output            *lockedBuffer
	relayHostKey      ssh.PublicKey
}

// hostKeyCallback accepts the relay's key, which it presents in a host
// certificate.
func (r *compatRelay) hostKeyCallback(_ string, _ net.Addr, key ssh.PublicKey) error {
	if !utils.KeysEqual(key, r.relayHostKey) {
		return fmt.Errorf("%s presented another key", r.name)
	}
	return nil
}

// lockedBuffer is an io.Writer a test can read while a process writes it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// reserveAddr holds a loopback port open, so that no other node of the test
// is given it, until release closes it for the relay that takes it.
func reserveAddr(t *testing.T) (addr string, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// compatStartAttempts bounds how often a relay is started again on fresh
// ports, when something else took one of its ports between their release and
// its bind.
const compatStartAttempts = 5

// startCompatRelay starts bin as layout says, and stops it when the test ends.
// A node's addresses are fixed before it starts, since its NodeAddr is one of
// them and a released build takes that from its flags, so each is held open
// until just before the relay binds it, and a start that finds one taken is
// tried again on new ones.
func startCompatRelay(t *testing.T, name, bin string, keys compatKeyFiles, layout compatLayout) *compatRelay {
	t.Helper()
	for attempt := 1; ; attempt++ {
		r, taken := tryStartCompatRelay(t, name, bin, keys, layout)
		if r != nil {
			return r
		}
		require.True(t, taken, "%s relay didn't start", name)
		require.Less(t, attempt, compatStartAttempts, "%s relay found its ports taken %d times", name, attempt)
	}
}

// tryStartCompatRelay is one start of startCompatRelay. It returns nil and
// true when the relay exited because one of its addresses was in use.
func tryStartCompatRelay(t *testing.T, name, bin string, keys compatKeyFiles, layout compatLayout) (*compatRelay, bool) {
	t.Helper()
	r := &compatRelay{name: name, output: &lockedBuffer{}, relayHostKey: keys.relay.PublicKey()}
	var releases []func()
	reserve := func() string {
		addr, release := reserveAddr(t)
		releases = append(releases, release)
		return addr
	}
	r.ssh = reserve()
	args := []string{"--ssh-addr", r.ssh, "--private-key", keys.relayFile, "--routing", string(layout.mode)}
	// Neighbours reach a node at its NodeAddr: its internal listener when it
	// has one.
	nodeAddr := r.ssh
	if layout.internal {
		r.internal = reserve()
		nodeAddr = r.internal
		args = append(args, "--internal-addr", r.internal)
	}
	args = append(args, "--node-addr", nodeAddr)
	if layout.ws {
		r.ws = reserve()
		args = append(args, "--ws-addr", r.ws)
	}
	if layout.consul != "" {
		args = append(args, "--consul-url", layout.consul)
	}
	if layout.proxy {
		args = append(args, "--ssh-proxy-protocol")
	}
	if layout.refuseLegacyHops {
		// Its debug log says why it refuses each hop.
		args = append(args, "--legacy-hops=false", "--debug")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = r.output, r.output
	// Only what the node is told on its command line configures it.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	for _, release := range releases {
		release()
	}
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop := func() {
		cancel()
		<-exited
	}
	// Every build logs this once its listeners are bound.
	deadline := time.After(15 * time.Second)
	for !strings.Contains(r.output.String(), "starting server") {
		select {
		case <-exited:
			cancel()
			if strings.Contains(r.output.String(), "address already in use") {
				return nil, true
			}
			t.Fatalf("%s relay (%s) exited:\n%s", name, strings.Join(args, " "), r.output.String())
		case <-deadline:
			stop()
			t.Fatalf("%s relay (%s) never started:\n%s", name, strings.Join(args, " "), r.output.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("%s relay (%s) output:\n%s", name, strings.Join(args, " "), r.output.String())
		}
	})
	for _, addr := range []string{r.ssh, r.internal, r.ws} {
		if addr == "" {
			continue
		}
		require.Eventually(t, func() bool {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		}, 15*time.Second, 50*time.Millisecond, "%s relay never listened on %s:\n%s", name, addr, r.output.String())
	}
	return r, false
}

// compatSession is a session shared on a relay as a host shares one, its host
// an endpoint that echoes and reports what reaches it: each guest a relay
// authenticates for, each channel a relay opens, and the end of each
// authenticated connection, which is reported after every channel the
// connection carried.
type compatSession struct {
	id, user string
	guests   <-chan compatGuest
	channels <-chan struct{}
	ended    <-chan struct{}
}

// compatGuest is what the endpoint saw of a guest: the user and the
// certified AuthRequest the home presented.
type compatGuest struct {
	user string
	auth *server.AuthRequest
}

// shareOn registers a session on relay, admitting only the guest's key.
func shareOn(t *testing.T, relay *compatRelay, keys compatKeyFiles) *compatSession {
	t.Helper()
	hostClient, err := ssh.Dial("tcp", relay.ssh, &ssh.ClientConfig{User: "compat-host", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(keys.host)}, HostKeyCallback: relay.hostKeyCallback, Timeout: 5 * time.Second})
	require.NoError(t, err)
	body, err := proto.Marshal(&server.CreateSessionRequest{HostUser: "host", HostPublicKeys: [][]byte{ssh.MarshalAuthorizedKey(keys.host.PublicKey())}, ClientAuthorizedKeys: [][]byte{ssh.MarshalAuthorizedKey(keys.guest.PublicKey())}})
	require.NoError(t, err)
	ok, reply, err := hostClient.SendRequest(upterm.ServerCreateSessionRequestType, true, body)
	require.NoError(t, err)
	require.True(t, ok, "%s refused the registration: %s", relay.name, reply)
	var registered server.CreateSessionResponse
	require.NoError(t, proto.Unmarshal(reply, &registered))
	socket, err := hostClient.Listen("unix", registered.SessionID)
	require.NoError(t, err)

	guests := make(chan compatGuest, 8)
	checker := server.UserCertChecker{IsUserAuthority: func(key ssh.PublicKey) bool { return utils.KeysEqual(key, keys.relay.PublicKey()) }}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auth, guest, err := checker.Authenticate(meta.User(), key)
		if err != nil {
			return nil, err
		}
		if !utils.KeysEqual(guest, keys.guest.PublicKey()) {
			return nil, fmt.Errorf("unexpected guest key")
		}
		select {
		case guests <- compatGuest{user: meta.User(), auth: auth}:
		default:
		}
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(keys.host)
	channels, ended := make(chan struct{}, 8), make(chan struct{}, 8)
	var served sync.WaitGroup
	served.Go(func() {
		for {
			conn, err := socket.Accept()
			if err != nil {
				return
			}
			served.Go(func() { serveEcho(conn, cfg, channels, ended) })
		}
	})
	t.Cleanup(func() {
		_ = socket.Close()
		_ = hostClient.Close()
		served.Wait()
	})
	return &compatSession{id: registered.SessionID, user: registered.SshUser, guests: guests, channels: channels, ended: ended}
}

// serveEcho serves one relay connection to the session: every channel echoes.
// It reports each channel a relay opens on opened and, once an authenticated
// connection has ended and its echoes are done, the end on ended. Neither
// report blocks it.
func serveEcho(raw net.Conn, cfg *ssh.ServerConfig, opened, ended chan<- struct{}) {
	defer func() { _ = raw.Close() }()
	conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() {
		select {
		case ended <- struct{}{}:
		default:
		}
	}()
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(requests)
	var echoes sync.WaitGroup
	defer echoes.Wait()
	for incoming := range channels {
		select {
		case opened <- struct{}{}:
		default:
		}
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		echoes.Go(func() { defer func() { _ = channel.Close() }(); _, _ = io.Copy(channel, channel) })
	}
}

// requireCompatJoin joins s through entry as a guest does, requires the
// guest's bytes to come back from its host, and returns what the host saw.
func requireCompatJoin(t *testing.T, s *compatSession, entry *compatRelay, keys compatKeyFiles) compatGuest {
	t.Helper()
	c, err := ssh.Dial("tcp", entry.ssh, &ssh.ClientConfig{User: s.user, Auth: []ssh.AuthMethod{ssh.PublicKeys(keys.guest)}, HostKeyCallback: entry.hostKeyCallback, Timeout: 10 * time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	channel, requests, err := c.OpenChannel("session", nil)
	require.NoError(t, err, "the guest didn't reach its host through %s", entry.name)
	go ssh.DiscardRequests(requests)
	defer func() { _ = channel.Close() }()
	payload := []byte("a guest of a mixed fleet")
	_, err = channel.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(channel, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	select {
	case guest := <-s.guests:
		return guest
	case <-time.After(5 * time.Second):
		t.Fatal("the host never saw the guest")
		return compatGuest{}
	}
}

// requireCompatJoinWithin is requireCompatJoin, which must complete within
// compatJoinBound.
func requireCompatJoinWithin(t *testing.T, s *compatSession, entry *compatRelay, keys compatKeyFiles) compatGuest {
	t.Helper()
	start := time.Now()
	guest := requireCompatJoin(t, s, entry, keys)
	require.Less(t, time.Since(start), compatJoinBound, "a join through %s waited on a banner", entry.name)
	return guest
}

// requireCompatRefused requires a guest of s entering at entry to reach no
// host, refused for the gate's reason, before any node dialed the host: the
// host sees no authentication at all, watched for compatQuietBound, since a
// refusal that comes first leaves no later path to it. See refuseCompatGuest
// for entry, refuser and reason.
func requireCompatRefused(t *testing.T, s *compatSession, entry, refuser *compatRelay, reason string, keys compatKeyFiles) {
	t.Helper()
	c := refuseCompatGuest(t, s, entry, refuser, reason, keys)
	defer func() { _ = c.Close() }()
	select {
	case <-s.guests:
		t.Fatalf("a guest entering at %s reached its host", entry.name)
	case <-time.After(compatQuietBound):
	}
}

// requireCompatRefusedAfterHomeAuth requires a guest of s entering at entry, a
// node that gates, to reach no session at its host, where s's home is a node
// from before the gate. That home authenticates entry's hop, and dials its
// host at once, as it does for every hop, so the host sees the hop
// authenticate: it must be a gate hop, for s. entry then refuses to go on,
// since the home's version lacks the token, and the guest's channel is refused
// with UpstreamUnavailable. The home's connection to the host must end
// without a channel ever opened on it.
func requireCompatRefusedAfterHomeAuth(t *testing.T, s *compatSession, entry *compatRelay, keys compatKeyFiles) {
	t.Helper()
	c := refuseCompatGuest(t, s, entry, entry, upterm.UpstreamUnavailable, keys)
	defer func() { _ = c.Close() }()
	select {
	case guest := <-s.guests:
		require.EqualValues(t, 1, guest.auth.GateProtocol, "%s hopped to the home without the gate", entry.name)
		require.Equal(t, s.id, guest.auth.TargetRoutingId, "%s's hop named another registration", entry.name)
	case <-time.After(5 * time.Second):
		t.Fatalf("the home never authenticated %s's hop at its host", entry.name)
	}
	select {
	case <-s.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the home's connection to its host never ended")
	}
	select {
	case <-s.channels:
		t.Fatalf("a guest entering at %s opened a channel at its host", entry.name)
	default:
	}
}

// refuseCompatGuest lets a guest of s in at entry, requires its channel to be
// refused, and returns its connection. The guest is let in once entry has
// resolved its session, so the refusal is never a route that entry hadn't seen
// yet: the guest's channel is refused with reason, which entry reports its
// upstream's failure with, and refuser, the node that gates, logs the gate's
// refusal for it. A nil refuser is a refusal by a node from before the gate,
// which logs no reason.
func refuseCompatGuest(t *testing.T, s *compatSession, entry, refuser *compatRelay, reason string, keys compatKeyFiles) *ssh.Client {
	t.Helper()
	gateRefusals := func() int {
		if refuser == nil {
			return 0
		}
		return strings.Count(refuser.output.String(), errGateRefusedText)
	}
	before := gateRefusals()
	var c *ssh.Client
	require.Eventually(t, func() bool {
		var err error
		c, err = ssh.Dial("tcp", entry.ssh, &ssh.ClientConfig{User: s.user, ClientVersion: upterm.JoinSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(keys.guest)}, HostKeyCallback: entry.hostKeyCallback, Timeout: 5 * time.Second})
		return err == nil
	}, 10*time.Second, 100*time.Millisecond, "%s never let the guest in", entry.name)
	t.Cleanup(func() { _ = c.Close() })
	channel, _, err := c.OpenChannel("session", nil)
	if channel != nil {
		_ = channel.Close()
	}
	var rejected *ssh.OpenChannelError
	require.ErrorAs(t, err, &rejected, "a guest entering at %s reached its host", entry.name)
	require.Equal(t, reason, rejected.Message)
	if refuser != nil {
		require.Eventually(t, func() bool { return gateRefusals() > before }, 5*time.Second, 50*time.Millisecond,
			"%s didn't log the gate's refusal:\n%s", refuser.name, refuser.output.String())
	}
	return c
}

// requireCompatRefusedAtEntry requires a guest of s entering at entry, a
// node with an authority composed, to be refused as it authenticates, as any
// unknown key is: such a node hops to the guest's home then, and a home that
// refuses the hop refuses the guest. It is sent no banner, and reaches no
// host, watched for compatQuietBound.
func requireCompatRefusedAtEntry(t *testing.T, s *compatSession, entry *compatRelay, keys compatKeyFiles) {
	t.Helper()
	var banners []string
	c, err := ssh.Dial("tcp", entry.ssh, &ssh.ClientConfig{User: s.user, ClientVersion: upterm.JoinSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(keys.guest)}, HostKeyCallback: entry.hostKeyCallback,
		BannerCallback: func(m string) error { banners = append(banners, m); return nil }, Timeout: 5 * time.Second})
	if c != nil {
		_ = c.Close()
	}
	require.ErrorContains(t, err, "unable to authenticate", "a guest entering at %s was let in", entry.name)
	require.Empty(t, banners, "a guest entering at %s was sent a banner", entry.name)
	select {
	case <-s.guests:
		t.Fatalf("a guest entering at %s reached its host", entry.name)
	case <-time.After(compatQuietBound):
	}
}

// errGateRefusedText is the error a node logs when the gate refuses a hop.
const errGateRefusedText = "authenticated home gate refused"

// hostWithCLI hosts a session on server with the upterm at cli, in a home of
// its own, and returns what it wrote on stderr and to its log once the
// session is ready. The session is stopped when the test ends.
func hostWithCLI(t *testing.T, cli, server string, keys compatKeyFiles) (string, string) {
	t.Helper()
	// Short, so the session's sockets fit the platform's path limit.
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	home, err := os.MkdirTemp(base, "uc")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	runtimeDir := filepath.Join(home, "r")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SHELL=/bin/sh",
		"XDG_STATE_HOME=" + filepath.Join(home, "s"), "XDG_CONFIG_HOME=" + filepath.Join(home, "c"),
		"XDG_DATA_HOME=" + filepath.Join(home, "d"), "XDG_CACHE_HOME=" + filepath.Join(home, "k"),
		"XDG_RUNTIME_DIR=" + runtimeDir,
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(cli, "host", "--detach", "--accept", "--server", server,
		"--skip-host-key-check", "--known-hosts", filepath.Join(home, "known_hosts"),
		"--private-key", keys.hostFile, "-o", "json", "--", "/bin/sh", "-c", "sleep 600")
	cmd.Env, cmd.Stdout, cmd.Stderr = env, &stdout, &stderr
	require.NoError(t, cmd.Run(), "upterm host on %s: %s", server, stderr.String())
	var started struct {
		Name    string `json:"name"`
		LogPath string `json:"logPath"`
		PID     int    `json:"pid"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &started), stdout.String())
	t.Cleanup(func() {
		stop := exec.Command(cli, "session", "stop", started.Name)
		stop.Env = env
		_ = stop.Run()
		if p, err := os.FindProcess(started.PID); err == nil {
			_ = p.Kill()
		}
	})
	// The host logs its version check, and any mismatch it finds, before it
	// logs that its tunnel is established; only once that is in the log may a
	// line's absence be read.
	var log []byte
	require.Eventually(t, func() bool {
		log, err = os.ReadFile(started.LogPath)
		return err == nil && bytes.Contains(log, []byte("Established reverse tunnel"))
	}, 10*time.Second, 50*time.Millisecond, "upterm host on %s never logged its tunnel", server)
	return stderr.String(), string(log)
}
