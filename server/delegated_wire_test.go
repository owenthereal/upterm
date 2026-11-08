package server

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// testdata/gate-v1.json is a delegated registration as the gate carries it:
// it is a valid one, and it comes back from the wire as it went.
func TestGateRegistrationGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/gate-v1.json")
	require.NoError(t, err)
	var golden struct {
		AccountID      string `json:"account_id"`
		SessionID      string `json:"session_id"`
		Generation     uint64 `json:"generation"`
		RoutingID      string `json:"routing_id"`
		RunPublicKey   []byte `json:"run_public_key"`
		RegistrationID []byte `json:"registration_id"`
		HomeNode       string `json:"home_node"`
		HomeNodeID     string `json:"home_relay_id"`
		HomeBootID     string `json:"home_boot_id"`
	}
	require.NoError(t, json.Unmarshal(data, &golden))
	ref := RegistrationRef{Authority: AuthorityDelegated, AccountID: golden.AccountID, SessionID: golden.SessionID, Generation: golden.Generation, RoutingID: golden.RoutingID, RunPublicKeys: [][]byte{golden.RunPublicKey}, RegistrationID: golden.RegistrationID, HomeNode: golden.HomeNode, HomeNodeID: golden.HomeNodeID, HomeBootID: golden.HomeBootID}
	wire := gateRegistration(ref)
	require.NoError(t, validGateRegistration(wire))
	data, err = proto.Marshal(wire)
	require.NoError(t, err)
	var decoded GateRegistration
	require.NoError(t, proto.Unmarshal(data, &decoded))
	require.Equal(t, ref, registrationRef(&decoded), "the delegated identity changed on the wire")
}

// Every value of every enum the delegated registration and the gate carry
// has its name and number, and there are no others.
func TestRelayEnumValues(t *testing.T) {
	for _, tc := range []struct {
		enum protoreflect.EnumDescriptor
		want []string
	}{
		{DelegatedDisposition(0).Descriptor(), []string{"DELEGATED_UNSPECIFIED", "DELEGATED_CURRENT", "DELEGATED_STOPPED", "DELEGATED_WITHDRAWN"}},
		{DelegatedErrorCode(0).Descriptor(), []string{"DELEGATED_ERROR_UNSPECIFIED", "DELEGATED_UNAVAILABLE", "DELEGATED_INVALID_REQUEST", "DELEGATED_STALE_GENERATION", "DELEGATED_UNSUPPORTED"}},
		{GateMode(0).Descriptor(), []string{"GATE_MODE_UNSPECIFIED", "GATE_MODE_LOCAL", "GATE_MODE_DELEGATED"}},
	} {
		values := tc.enum.Values()
		require.Equal(t, len(tc.want), values.Len(), "%s's values", tc.enum.FullName())
		for number, name := range tc.want {
			v := values.ByName(protoreflect.Name(name))
			require.NotNil(t, v, "%s has no %s", tc.enum.FullName(), name)
			require.Equal(t, protoreflect.EnumNumber(number), v.Number(), "%s.%s", tc.enum.FullName(), name)
		}
	}
	require.Equal(t, DelegatedDisposition(2), DelegatedDisposition_DELEGATED_STOPPED)
	require.Equal(t, DelegatedErrorCode(1), DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	require.Equal(t, DelegatedErrorCode(2), DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	require.Equal(t, DelegatedErrorCode(4), DelegatedErrorCode_DELEGATED_UNSUPPORTED)
}

// The source filter refuses a delegated registration's host as it refuses a
// local one's: before the banner on the SSH listener, and at registration by
// the source its certificate records, with nothing stored and nothing asked.
func TestSourceFilterAppliesToDelegatedToo(t *testing.T) {
	_, addr, _, _ := stockTestProxy(t, 4*time.Second, nil, func(p *sshProxy) {
		p.AuthorityComposed = true
		p.authorities = &gateFixtureRegistry{}
		p.deny = sourceDeny{filter: newDenyAddrs("127.0.0.1")}
	})
	raw, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(5*time.Second)))
	requireClosedSilently(t, raw)

	authority := &fakeAuthority{}
	srv := delegatedSSHD(t, authority, func(s *sshd) {
		s.deny = sourceDeny{prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.8/32")}}
	})
	p := newProven(t)
	host := originHost(t, srv, "denied-original", Ingress_INGRESS_SSH)
	ok, body := sendCreate(t, host, originRequest(t, p, "denied-original", 1))
	require.False(t, ok)
	require.Empty(t, body, "a denied host was told something")
	require.Zero(t, authority.calls())
	_, err = srv.sshd.SessionManager.GetSession(p.id())
	require.Error(t, err)
	_, found := srv.sshd.Lookup(p.id())
	require.False(t, found)
}
