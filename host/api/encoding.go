package api

import (
	"fmt"

	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
)

func EncodeIdentifierSession(session *GetSessionResponse) (string, error) {
	id := &Identifier{
		Id:       session.SessionId,
		Type:     Identifier_CLIENT,
		NodeAddr: session.NodeAddr,
	}

	return EncodeIdentifier(id)
}

func EncodeIdentifier(id *Identifier) (string, error) {
	if id.Type == Identifier_CLIENT {
		return routing.EncodeSSHUser(id.Id, id.NodeAddr, routing.ModeEmbedded), nil
	}
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

	// client
	sessionID, nodeAddr, _, err := routing.DecodeSSHUser(id)
	if err != nil {
		return nil, fmt.Errorf("failed to decode identifier: %w", err)
	}

	return &Identifier{
		Id:       sessionID,
		Type:     Identifier_CLIENT,
		NodeAddr: nodeAddr,
	}, nil
}
