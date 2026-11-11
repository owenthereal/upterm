package server

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// The fixed values TestRelayWireGolden builds its messages from: the
// registration in testdata/gate-v1.json, the AuthRequest in
// testdata/authrequest.golden with the gate's fields added, and these. The
// delegated messages take gate-v1.json's session ID as their external
// session ID, and its generation; a host's request takes its run key as the
// host key, and the response its routing ID and home node. A gate admission
// names that run key's fingerprint as the guest's key, and the gate's
// admission and held check take the golden sequence.
const (
	goldenTypedAddress  = "guest-typed-user"
	goldenIngressNodeID = "ingress-B"
	goldenConnectionID  = "44444444-4444-4444-8444-444444444444"

	goldenProtocol         = "test_v1"
	goldenSequence         = 3
	goldenDecisionRevision = 5
	goldenExitStatus       = -2
	goldenHostUser         = "host"
	goldenAuthorizedKey    = "k"
	goldenSessionSecret    = "session-secret"
	goldenHostKeyProof     = "host-key-proof"
	goldenSSHUser          = "guest-ssh-user"

	goldenIngressSSHSessionID = "ingress-ssh-session"
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

	session := registration.SessionId
	delegatedResponse := func() *DelegatedSession {
		return &DelegatedSession{Protocol: goldenProtocol, ExternalSessionId: session, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: goldenDecisionRevision}
	}
	exit := func() *DelegatedExit { return &DelegatedExit{ExitStatus: goldenExitStatus, StatusKnown: true} }
	runKey, err := ssh.ParsePublicKey(registration.RunPublicKeys[0])
	require.NoError(t, err)
	held := func() *GateHeldRequest {
		return &GateHeldRequest{Protocol: 1, ModeNonce: goldenNonce(), Registration: registration, Sequence: goldenSequence}
	}

	built := map[string]proto.Message{
		"AuthRequest":      auth,
		"GateRegistration": registration,
		"GateModeRequest":  &GateModeRequest{Protocol: 1, Nonce: goldenNonce(), RoutingId: registration.RoutingId},
		"GateModeReply":    &GateModeReply{Protocol: 1, Nonce: goldenNonce(), Registration: registration},
		"CreateSessionRequest": &CreateSessionRequest{
			HostUser:             goldenHostUser,
			HostPublicKeys:       registration.RunPublicKeys,
			ClientAuthorizedKeys: [][]byte{[]byte(goldenAuthorizedKey)},
			SessionSecret:        []byte(goldenSessionSecret),
			Generation:           registration.Generation,
			HostKeyProof:         []byte(goldenHostKeyProof),
			DelegatedSession:     &DelegatedSession{Protocol: goldenProtocol, ExternalSessionId: session},
		},
		"CreateSessionResponse": &CreateSessionResponse{
			SessionID:        registration.RoutingId,
			NodeAddr:         registration.HomeNode,
			SshUser:          goldenSSHUser,
			SessionKeyRedial: true,
			DelegatedSession: delegatedResponse(),
		},
		"DelegatedSession": delegatedResponse(),
		"DelegatedReady":   &DelegatedReady{},
		"DelegatedExit":    exit(),
		"DelegatedControlRequest": &DelegatedControlRequest{
			ExternalSessionId: session, Generation: registration.Generation, Sequence: goldenSequence,
			Event: &DelegatedControlRequest_Exit{Exit: exit()},
		},
		"DelegatedControlRequest/ready": &DelegatedControlRequest{
			ExternalSessionId: session, Generation: registration.Generation, Sequence: goldenSequence,
			Event: &DelegatedControlRequest_Ready{Ready: &DelegatedReady{}},
		},
		"DelegatedControlReply": &DelegatedControlReply{
			ExternalSessionId: session, Generation: registration.Generation, AcknowledgedSequence: goldenSequence,
			Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: goldenDecisionRevision,
		},
		"DelegatedDecision": &DelegatedDecision{
			ExternalSessionId: session, Generation: registration.Generation,
			Disposition: DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: goldenDecisionRevision,
		},
		"DelegatedDecisionAck": &DelegatedDecisionAck{ExternalSessionId: session, Generation: registration.Generation, DecisionRevision: goldenDecisionRevision},
		"DelegatedError":       &DelegatedError{Code: DelegatedErrorCode_DELEGATED_STALE_GENERATION},
		"GateAdmission": &GateAdmission{
			Protocol: 1, ModeNonce: goldenNonce(), Registration: registration, IngressNodeId: goldenIngressNodeID, ConnectionId: goldenConnectionID,
			IngressSshSessionId: []byte(goldenIngressSSHSessionID), KeyFingerprint: publicKeyFingerprint(runKey), Sequence: goldenSequence,
			Capabilities: []string{"shell", "exec"},
		},
		"GateHeldRequest": held(),
		"GateHeldReply":   &GateHeldReply{Request: held(), Held: true},
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
