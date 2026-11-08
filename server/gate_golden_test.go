package server

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// The fixed values TestRelayWireGolden builds its messages from: the
// registration in testdata/gate-v1.json, and the AuthRequest in
// testdata/authrequest.golden with the gate's fields added.
const (
	goldenTypedAddress  = "guest-typed-user"
	goldenIngressNodeID = "ingress-B"
	goldenConnectionID  = "44444444-4444-4444-8444-444444444444"
)

// goldenRegistration is testdata/gate-v1.json as a GateRegistration. The
// fixture's home_relay_id is the registration's home_node_id.
func goldenRegistration(t *testing.T) *GateRegistration {
	t.Helper()
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
	return &GateRegistration{
		Mode:           GateMode_GATE_MODE_DELEGATED,
		AccountId:      golden.AccountID,
		SessionId:      golden.SessionID,
		Generation:     golden.Generation,
		RoutingId:      golden.RoutingID,
		RunPublicKeys:  [][]byte{golden.RunPublicKey},
		RegistrationId: golden.RegistrationID,
		HomeNode:       golden.HomeNode,
		HomeNodeId:     golden.HomeNodeID,
		HomeBootId:     golden.HomeBootID,
	}
}

// goldenNonce is the 32 bytes 0x00 to 0x1f.
func goldenNonce() []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

// Every relay message the gate added has a fixed encoding: each is built from
// fixed values and must encode to its line of testdata/relay-wire.golden, so
// no field number, wire type or enum value can change unseen.
func TestRelayWireGolden(t *testing.T) {
	registration := goldenRegistration(t)
	old, err := os.ReadFile("testdata/authrequest.golden")
	require.NoError(t, err)
	auth := &AuthRequest{}
	require.NoError(t, proto.Unmarshal(old, auth))
	auth.TypedAddress = goldenTypedAddress
	auth.TargetRoutingId = registration.RoutingId
	auth.IngressNodeId = goldenIngressNodeID
	auth.ConnectionId = goldenConnectionID
	auth.GateProtocol = 1

	built := map[string]proto.Message{
		"AuthRequest":      auth,
		"GateRegistration": registration,
		"GateModeRequest":  &GateModeRequest{Protocol: 1, Nonce: goldenNonce(), RoutingId: registration.RoutingId},
		"GateModeReply":    &GateModeReply{Protocol: 1, Nonce: goldenNonce(), Registration: registration},
	}

	f, err := os.Open("testdata/relay-wire.golden")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		name, want, ok := strings.Cut(scanner.Text(), "\t")
		require.True(t, ok, "a golden line is NAME<TAB>HEX: %q", scanner.Text())
		msg, known := built[name]
		require.True(t, known, "the golden has %s, which this test doesn't build", name)
		require.False(t, seen[name], "the golden has %s twice", name)
		seen[name] = true
		got, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
		require.NoError(t, err)
		require.Equal(t, want, hex.EncodeToString(got), "%s's encoding changed", name)
	}
	require.NoError(t, scanner.Err())
	for name := range built {
		require.True(t, seen[name], "the golden has no line for %s", name)
	}
}
