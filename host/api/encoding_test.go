package api

import (
	"testing"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/assert"
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

			assert := assert.New(t)

			want := c.id
			str, err := EncodeIdentifier(want)
			assert.NoError(err)

			got, err := DecodeIdentifier(str, c.clientVersion)
			assert.NoError(err)

			assert.True(proto.Equal(want, got))
		})
	}
}

func TestDecodeIdentifier(t *testing.T) {
	assert := assert.New(t)

	_, err := DecodeIdentifier("10OLFAKZu4cxx2roOboaY:MTI3LjAuMC4xOjIyMjIIII=", "")
	assert.Error(err)
	assert.ErrorContains(err, "illegal base64 data")

	_, err = DecodeIdentifier("10OLFAKZu4cxx2roOboaY", "")
	assert.Error(err)
	assert.ErrorContains(err, "invalid client session id")
}
