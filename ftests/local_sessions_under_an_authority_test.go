package ftests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// localAuthorities are the ways a relay can be composed for a local session:
// with no authority, with one dark, and with one enabled. Each topology has an
// internal listener; legacy hops are accepted with none and dark, as they
// must be off with an enabled authority.
var localAuthorities = []string{"none", "dark", "enabled"}

// localTopology is the relay options for composition, with authority as the
// test authority, if any.
func localTopology(composition string, authority *testauthority.Authority) func(*Server) {
	switch composition {
	case "dark":
		return func(s *Server) {
			withInternalListener(false)(s)
			withAuthority(authority, false)(s)
		}
	case "enabled":
		return withAuthority(authority, true)
	}
	return withInternalListener(false)
}

// localOutcome is what became of one guest of a local session.
type localOutcome struct {
	// user is the SSH user the guest joined as.
	user     string
	admitted bool
	// refusal is the guest's error, when it was refused, and banners every
	// banner the relay sent it.
	refusal string
	banners []string
	// took is how long joining took, from dialling to the shell starting,
	// whichever way it went.
	took time.Duration
}

// joinOutcome joins session at joinURL as a guest, with the client key or,
// when key is set, with key, and reports what became of it. An admitted
// guest must reach the host's shell.
func joinOutcome(t *testing.T, session *api.GetSessionResponse, joinURL string, key ssh.Signer) localOutcome {
	t.Helper()
	outcome := localOutcome{user: session.SshUser}
	c := &Client{PrivateKeys: []string{ClientPrivateKey}, BannerCallback: func(m string) error {
		outcome.banners = append(outcome.banners, m)
		return nil
	}}
	if key != nil {
		c.Signers = []ssh.Signer{key}
	}
	t.Cleanup(c.Close)
	start := time.Now()
	err := c.Join(session, joinURL)
	outcome.took = time.Since(start)
	if err != nil {
		outcome.refusal = err.Error()
		return outcome
	}
	requireReachesHost(t, c)
	outcome.admitted = true
	return outcome
}

// requireLocalRefusal requires got, a refused guest, to have been refused as it
// authenticated, with exactly the banners want.
func requireLocalRefusal(t *testing.T, scenario, composition string, got localOutcome, want ...string) {
	t.Helper()
	require.Contains(t, got.refusal, "unable to authenticate", "%s, with %s, wasn't refused as it authenticated", scenario, composition)
	require.Equal(t, want, got.banners, "%s, with %s: the banners", scenario, composition)
}

// withUser is session with its SSH user replaced by user.
func withUser(session *api.GetSessionResponse, user string) *api.GetSessionResponse {
	copied := proto.Clone(session).(*api.GetSessionResponse)
	copied.SshUser = user
	return copied
}

// embedded is id's user in embedded routing, on the node at nodeAddr.
func embedded(id, nodeAddr string) string {
	return id + ":" + base64.URLEncoding.EncodeToString([]byte(nodeAddr))
}

// localScenarios runs every local-session scenario on a fleet of two relays
// in mode, each composed with opts, and reports each one's outcome by name.
func localScenarios(t *testing.T, mode routing.Mode, opts func(*Server)) map[string]localOutcome {
	t.Helper()
	n1, n2 := newRedialRelay(t, mode, opts), newRedialRelay(t, mode, opts)
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(t, h.Share(n1.joinURL("ssh")))
	t.Cleanup(h.Close)
	session := getAndVerifySession(t, adminSocketFile, n1.joinURL("ssh"), n1.NodeAddr())
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	stranger, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	unknown := utils.GenerateSessionID()
	if mode == routing.ModeEmbedded {
		unknown = embedded(unknown, n1.NodeAddr())
	}

	outcomes := map[string]localOutcome{
		"bare-ID join":               joinOutcome(t, withUser(session, session.SessionId), n1.joinURL("ssh"), nil),
		"embedded-ID join":           joinOutcome(t, withUser(session, embedded(session.SessionId, n1.NodeAddr())), n1.joinURL("ssh"), nil),
		"a refused key":              joinOutcome(t, session, n1.joinURL("ssh"), stranger),
		"an unknown ID":              joinOutcome(t, withUser(session, unknown), n1.joinURL("ssh"), nil),
		"WebSocket direct":           joinOutcome(t, session, n1.joinURL("ws"), nil),
		"WebSocket bridged":          joinOutcome(t, session, n2.joinURL("ws"), nil),
		"a cross-node join":          joinOutcome(t, session, n2.joinURL("ssh"), nil),
		"a refused key across nodes": joinOutcome(t, session, n2.joinURL("ssh"), stranger),
	}

	// A host whose tunnel is cut redials, registers again, and is joined.
	redial := shareRedialling(t, "ssh", n1, redialTiming)
	first := redial.awaitRegistered(t, n1)
	redial.fwd.Redirect(closedAddr(t))
	redial.fwd.Cut()
	redial.awaitStatus(t, sessiondir.StatusReconnecting)
	redial.fwd.Redirect(n1.addr("ssh"))
	redial.awaitStatus(t, sessiondir.StatusReady)
	again := redial.awaitRegistered(t, n1)
	require.Greater(t, again.Generation, first.Generation, "registered again, under a later generation")
	outcomes["a host redial with the guest rejoining"] = joinOutcome(t, redial.first, n1.joinURL("ssh"), nil)

	// Reported by name, so that a scenario left out shows.
	require.Len(t, outcomes, 9)
	return outcomes
}

// requireNoLocalRegistration fails if any call the authority was asked names
// a registration, a guest or a user of the local session id.
func requireNoLocalRegistration(t *testing.T, authority *testauthority.Authority, ids ...string) {
	t.Helper()
	for _, c := range authority.Calls() {
		for _, id := range ids {
			require.NotEqual(t, id, c.Registration.RoutingID, "the authority was asked about a local registration: %s", c.Method)
			require.False(t, strings.HasPrefix(c.User, id), "the authority was asked about a local session's guest: %s %q", c.Method, c.User)
			if c.Home != nil {
				require.NotEqual(t, id, c.Home.Ref().RoutingID, "the authority was asked about a local home: %s", c.Method)
			}
			require.NotEqual(t, id, c.Target.RoutingID, "the authority was asked about a local target: %s", c.Method)
		}
	}
}

// A local session's guest is admitted or refused the same way whether the
// relay has no authority, a dark one or an enabled one, in both routing
// modes, though with an authority composed a guest takes the composed path,
// which dials the home as the guest authenticates. The refusals' forms
// differ, and both are pinned: with nothing composed, a user that names no
// session gets a banner saying so, and a key refused across nodes the home's
// banner, which the ingress words for plain ssh; with an authority composed,
// the former get no banner, and the latter is the home's channel rejection,
// passed on as it is. The authority is never asked about a local session.
func TestLocalSessionsUnderEachAuthority(t *testing.T) {
	useTestKeyPairs(t)
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
				t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
			}
			outcomes := map[string]map[string]localOutcome{}
			authorities := map[string]*testauthority.Authority{}
			for _, composition := range localAuthorities {
				t.Run(composition, func(t *testing.T) {
					authority := testauthority.New()
					authority.ClaimPrefix(claimPrefix)
					authorities[composition] = authority
					outcomes[composition] = localScenarios(t, mode, localTopology(composition, authority))
				})
			}
			require.Len(t, outcomes, len(localAuthorities))
			want := map[string]bool{
				"bare-ID join":                           mode == routing.ModeConsul,
				"embedded-ID join":                       true,
				"a refused key":                          false,
				"an unknown ID":                          false,
				"WebSocket direct":                       true,
				"WebSocket bridged":                      true,
				"a cross-node join":                      true,
				"a refused key across nodes":             false,
				"a host redial with the guest rejoining": true,
			}
			for scenario, admitted := range want {
				for _, composition := range localAuthorities {
					got := outcomes[composition][scenario]
					require.Equal(t, admitted, got.admitted, "%s, with %s: %s", scenario, composition, got.refusal)
				}
			}
			// The forms of the refusals. With nothing composed, a guest whose
			// user names no session is told so by a banner, and one whose
			// key the session doesn't admit is told nothing.
			none := outcomes["none"]
			requireLocalRefusal(t, "a refused key", "none", none["a refused key"])
			unknownID, _, _ := strings.Cut(none["an unknown ID"].user, ":")
			requireLocalRefusal(t, "an unknown ID", "none", none["an unknown ID"], fmt.Sprintf(upterm.BannerNoHostFormat, unknownID))
			if mode == routing.ModeEmbedded {
				bare := none["bare-ID join"]
				requireLocalRefusal(t, "bare-ID join", "none", bare, fmt.Sprintf("upterm: %q isn't a session on this relay; use the whole ssh command the host shared.\n", bare.user))
			}
			require.Contains(t, none["a refused key across nodes"].refusal, "refused your key", "without the gate, the ingress words the home's verdict")
			// With an authority composed, each is refused as any unknown key
			// is, with no banner, and a key refused across nodes is the
			// home's rejection, passed on as it is.
			for _, composition := range []string{"dark", "enabled"} {
				got := outcomes[composition]
				requireLocalRefusal(t, "a refused key", composition, got["a refused key"])
				requireLocalRefusal(t, "an unknown ID", composition, got["an unknown ID"])
				if mode == routing.ModeEmbedded {
					requireLocalRefusal(t, "bare-ID join", composition, got["bare-ID join"])
				}
				require.Contains(t, got["a refused key across nodes"].refusal, upterm.UpstreamKeyRefused, "through the gate, the home's rejection is passed on")
				requireNoLocalRegistration(t, authorities[composition])
				for _, c := range authorities[composition].Calls() {
					require.NotEqual(t, "Admit", c.Method, "a local session's guest reached Admit")
				}
			}
		})
	}
}

// A composed authority whose every call blocks forever holds up no local
// session's guest, dark or enabled: every scenario has the outcome it has
// with no authority, each guest is decided well within the 5 seconds a
// hanging Admit would cost it, and the authority is never asked.
func TestHangingAuthorityNeverDelaysLocalGuests(t *testing.T) {
	useTestKeyPairs(t)
	// A guest that waited on Admit would take at least admitCap.
	const admitCap = 5 * time.Second
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
				t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
			}
			var baseline map[string]localOutcome
			t.Run("none", func(t *testing.T) {
				baseline = localScenarios(t, mode, localTopology("none", nil))
			})
			require.NotNil(t, baseline)
			for _, composition := range []string{"dark", "enabled"} {
				t.Run(composition, func(t *testing.T) {
					authority := testauthority.New()
					authority.ClaimPrefix(claimPrefix)
					authority.Hang()
					hung := localScenarios(t, mode, localTopology(composition, authority))
					for scenario, want := range baseline {
						got := hung[scenario]
						require.Equal(t, want.admitted, got.admitted, "%s: %s", scenario, got.refusal)
						require.Less(t, got.took, admitCap, "%s took %s, as long as a wait on the authority", scenario, got.took)
					}
					require.Empty(t, authority.Calls(), "a local session's guest reached the hanging authority")
				})
			}
		})
	}
}
