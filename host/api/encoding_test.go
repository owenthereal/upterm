package api

import (
	"testing"

	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/assert"
)

func TestDecodeIdentifier(t *testing.T) {
	assert := assert.New(t)

	// Test invalid base64 in embedded mode should fail
	embeddedDecoder := routing.NewDecoder(routing.ModeEmbedded)
	_, err := DecodeIdentifier("10OLFAKZu4cxx2roOboaY:MTI3LjAuMC4xOjIyMjIIII=", "", embeddedDecoder)
	assert.Error(err)
	assert.ErrorContains(err, "failed to decode SSH user")

	// Test plain session ID (Consul mode) should succeed
	consulDecoder := routing.NewDecoder(routing.ModeConsul)
	id, err := DecodeIdentifier("10OLFAKZu4cxx2roOboaY", "", consulDecoder)
	assert.NoError(err)
	assert.Equal("10OLFAKZu4cxx2roOboaY", id.Id)
	assert.Equal(Identifier_CLIENT, id.Type)
	assert.Equal("", id.NodeAddr) // Empty for Consul mode
}
