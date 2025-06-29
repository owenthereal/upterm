package api

import (
	"fmt"

	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
)

func DecodeIdentifier(id, clientVersion string, decoder routing.Decoder) (*Identifier, error) {
	// Check connection type based on client version
	if clientVersion == upterm.HostSSHClientVersion {
		// HOST connection
		return &Identifier{
			Id:   id,
			Type: Identifier_HOST,
		}, nil
	}

	// CLIENT connection: decode the SSH user to get session ID and node address
	sessionID, nodeAddr, err := decoder.Decode(id)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SSH user: %w", err)
	}
	return &Identifier{
		Id:       sessionID,
		Type:     Identifier_CLIENT,
		NodeAddr: nodeAddr,
	}, nil
}
