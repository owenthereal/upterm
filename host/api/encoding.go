package api

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/owenthereal/upterm/upterm"
)

// SessionRoutingMode defines how session routing information is stored
type SessionRoutingMode string

const (
	// SessionRoutingEmbedded embeds node address in the session identifier (default)
	SessionRoutingEmbedded SessionRoutingMode = "embedded"
	// SessionRoutingConsul looks up node address from Consul
	SessionRoutingConsul SessionRoutingMode = "consul"
)

func EncodeIdentifierSession(session *GetSessionResponse) (string, error) {
	id := &Identifier{
		Id:       session.SessionId,
		Type:     Identifier_CLIENT,
		NodeAddr: session.NodeAddr,
	}

	return EncodeIdentifier(id)
}

func EncodeIdentifierSessionWithMode(session *GetSessionResponse, mode SessionRoutingMode) (string, error) {
	id := &Identifier{
		Id:       session.SessionId,
		Type:     Identifier_CLIENT,
		NodeAddr: session.NodeAddr,
	}

	return EncodeIdentifierWithMode(id, mode)
}

func EncodeIdentifier(id *Identifier) (string, error) {
	// Default to embedded routing mode for backward compatibility
	return EncodeIdentifierEmbedded(id)
}

func EncodeIdentifierWithMode(id *Identifier, mode SessionRoutingMode) (string, error) {
	switch mode {
	case SessionRoutingEmbedded:
		return EncodeIdentifierEmbedded(id)
	case SessionRoutingConsul:
		return EncodeIdentifierConsul(id)
	default:
		return EncodeIdentifierEmbedded(id) // Default to embedded
	}
}

// EncodeIdentifierEmbedded encodes with node address embedded in the identifier (default mode)
func EncodeIdentifierEmbedded(id *Identifier) (string, error) {
	result := id.Id
	if id.Type == Identifier_CLIENT {
		result += ":" + base64.URLEncoding.EncodeToString([]byte(id.NodeAddr))
	}

	return result, nil
}

// EncodeIdentifierConsul encodes for Consul-based routing (node address looked up from Consul)
func EncodeIdentifierConsul(id *Identifier) (string, error) {
	// In Consul mode, we don't embed the node address in the identifier
	// The node address will be looked up from Consul instead
	return id.Id, nil
}

func DecodeIdentifier(id, clientVersion string) (*Identifier, error) {
	// host
	if clientVersion == upterm.HostSSHClientVersion {
		return &Identifier{
			Id:   id,
			Type: Identifier_HOST,
		}, nil
	}

	// client - check if it's embedded routing format (contains encoded node address)
	if strings.Contains(id, ":") {
		return decodeEmbeddedIdentifier(id)
	}

	// Consul routing format: just the session ID
	return &Identifier{
		Id:   id,
		Type: Identifier_CLIENT,
		// NodeAddr will be looked up from Consul by the caller
	}, nil
}

// decodeEmbeddedIdentifier handles the embedded routing format
func decodeEmbeddedIdentifier(id string) (*Identifier, error) {
	split := strings.SplitN(id, ":", 2)
	if len(split) != 2 {
		return nil, fmt.Errorf("invalid embedded routing session id: %s", id)
	}

	nodeAddr, err := base64.URLEncoding.DecodeString(split[1])
	if err != nil {
		return nil, err
	}

	return &Identifier{
		Id:       split[0],
		Type:     Identifier_CLIENT,
		NodeAddr: string(nodeAddr),
	}, nil
}
