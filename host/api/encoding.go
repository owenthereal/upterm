package api

import (
	"encoding/base64"
	"strings"

	"github.com/jingweno/upterm/host/api/swagger/models"
)

func EncodeIdentifierSession(session *models.APIGetSessionResponse) (string, error) {
	id := &Identifier{
		Id:       session.SessionID,
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

func DecodeIdentifier(str string) (*Identifier, error) {
	split := strings.SplitN(str, ":", 2)
	var (
		t        = Identifier_HOST
		nodeAddr []byte
		err      error
	)

	if len(split) == 2 {
		t = Identifier_CLIENT
		nodeAddr, err = base64.URLEncoding.DecodeString(split[1])
		if err != nil {
			return nil, err
		}
	}

	id := &Identifier{
		Id:       split[0],
		Type:     t,
		NodeAddr: string(nodeAddr),
	}

	return id, nil
}
