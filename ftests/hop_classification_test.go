package ftests

import (
	"testing"

	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
)

// Successful routes prove both the original guest identity at the host and
// the channel-error behavior that distinguishes a local route from a hop, on
// a fleet that accepts legacy hops and on one that refuses them.
func TestOriginsAndHopClassificationByIngress(t *testing.T) {
	useTestKeyPairs(t)
	for _, refuse := range []bool{false, true} {
		name := "legacy hops accepted"
		opts := []func(*Server){withInternalListener(true)}
		if refuse {
			name = "legacy hops refused"
			opts = append(opts, withLegacyHopsRefused())
		}
		t.Run(name, func(t *testing.T) {
			for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
				t.Run(string(mode), func(t *testing.T) {
					if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
						t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
					}
					home := newRedialRelay(t, mode, opts...)
					ingress := newRedialRelay(t, mode, opts...)
					for _, tc := range []struct {
						name, url string
						hop       bool
					}{
						{"SSH_local", home.joinURL("ssh"), false},
						{"SSH_hop", ingress.joinURL("ssh"), true},
						{"WS_direct", home.joinURL("ws"), false},
						{"WS_bridged", ingress.joinURL("ws"), mode == routing.ModeEmbedded},
					} {
						t.Run(tc.name, func(t *testing.T) {
							requireJoinsAsItsOwnKey(t, home.joinURL("ssh"), home, tc.url)
							requireSuccessfulRouteClassification(t, home, tc.url, tc.hop)
						})
					}
				})
			}
		})
	}
}
