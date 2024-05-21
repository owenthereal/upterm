package api

import (
	"encoding/base64"
	"fmt"
	"strings"

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
	result := id.Id
	if id.Type == Identifier_CLIENT {
		result += ":" + base64.URLEncoding.EncodeToString([]byte(id.NodeAddr))
	}

	return result, nil
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
	split := strings.SplitN(id, ":", 2)
	if len(split) != 2 {
		return nil, fmt.Errorf("invalid client session id: %s", id)
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
