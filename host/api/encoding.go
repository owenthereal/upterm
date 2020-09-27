package api

import (
	"encoding/base64"
	"strings"

	"github.com/jingweno/upterm/upterm"
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
	t := Identifier_HOST
	if clientVersion != upterm.HostSSHClientVersion {
		t = Identifier_CLIENT
	}

	split := strings.SplitN(id, ":", 2)
	var (
		nodeAddr []byte
		err      error
	)

	if len(split) == 2 {
		nodeAddr, err = base64.URLEncoding.DecodeString(split[1])
		if err != nil {
			return nil, err
		}
	}

	return &Identifier{
		Id:       split[0],
		Type:     t,
		NodeAddr: string(nodeAddr),
	}, nil
}
