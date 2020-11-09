package api

import (
	"testing"

	"github.com/owenthereal/upterm/upterm"
	"google.golang.org/protobuf/proto"
)

func Test_EncodeDecodeIdentifier(t *testing.T) {
	cases := []struct {
		name          string
		id            *Identifier
		clientVersion string
	}{
		{
			name: "client type",
			id: &Identifier{
				Id:       "client",
				Type:     Identifier_CLIENT,
				NodeAddr: "127.0.0.1:22",
			},
			clientVersion: "SSH-2.0-Go",
		},
		{
			name: "host type",
			id: &Identifier{
				Id:   "host",
				Type: Identifier_HOST,
			},
			clientVersion: upterm.HostSSHClientVersion,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			want := c.id
			str, err := EncodeIdentifier(want)
			if err != nil {
				t.Fatal(err)
			}

			got, err := DecodeIdentifier(str, c.clientVersion)
			if err != nil {
				t.Fatal(err)
			}

			if !proto.Equal(want, got) {
				t.Errorf("Encode/decode failed, want=%s got=%s", want, got)
			}
		})
	}
}
