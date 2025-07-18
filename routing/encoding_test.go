package routing

import (
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/suite"
)

// EncodeDecoderTestSuite tests the EncodeDecoder implementations
type EncodeDecoderTestSuite struct {
	suite.Suite
}

func (suite *EncodeDecoderTestSuite) TestEmbeddedEncodeDecoder() {
	sessionID := "test-session-123"
	nodeAddr := "node1.example.com:22"

	encoder := NewEncodeDecoder(ModeEmbedded)

	// Test encoding
	encoded := encoder.Encode(sessionID, nodeAddr)
	suite.Contains(encoded, ":")
	suite.Contains(encoded, sessionID)

	// Test decoding
	decodedSessionID, decodedNodeAddr, err := encoder.Decode(encoded)
	suite.NoError(err)
	suite.Equal(sessionID, decodedSessionID)
	suite.Equal(nodeAddr, decodedNodeAddr)
	suite.Equal(ModeEmbedded, encoder.Mode())
}

func (suite *EncodeDecoderTestSuite) TestConsulEncodeDecoder() {
	sessionID := "test-session-456"

	encoder := NewEncodeDecoder(ModeConsul)

	// Test encoding (should just return session ID)
	encoded := encoder.Encode(sessionID, "any-node")
	suite.Equal(sessionID, encoded)

	// Test decoding
	decodedSessionID, decodedNodeAddr, err := encoder.Decode(encoded)
	suite.NoError(err)
	suite.Equal(sessionID, decodedSessionID)
	suite.Empty(decodedNodeAddr)
	suite.Equal(ModeConsul, encoder.Mode())
}

func (suite *EncodeDecoderTestSuite) TestEmbeddedDecodeInvalidFormats() {
	decoder := NewEncodeDecoder(ModeEmbedded)

	testCases := []struct {
		input       string
		description string
	}{
		{"no-colon-here", "no colon separator"},
		{"", "empty string"},
		{"session:invalid-base64===!@#$", "invalid base64 characters"},
	}

	for _, tc := range testCases {
		suite.Run(tc.description, func() {
			_, _, err := decoder.Decode(tc.input)
			suite.Error(err)
		})
	}
}

func (suite *EncodeDecoderTestSuite) TestConsulDecodeInvalidFormats() {
	decoder := NewEncodeDecoder(ModeConsul)

	// Test empty session ID
	_, _, err := decoder.Decode("")
	suite.Error(err)
}

// DecodeIdentifierTestSuite tests the DecodeIdentifier function
type DecodeIdentifierTestSuite struct {
	suite.Suite
}

func (suite *DecodeIdentifierTestSuite) TestHostConnection() {
	// Host connections should ignore decoder and return HOST type
	decoder := NewDecoder(ModeConsul) // Mode doesn't matter for host connections

	id, err := DecodeIdentifier("session123", upterm.HostSSHClientVersion, decoder)
	suite.NoError(err)
	suite.Equal("session123", id.Id)
	suite.Equal(api.Identifier_HOST, id.Type)
	suite.Empty(id.NodeAddr)
}

func (suite *DecodeIdentifierTestSuite) TestClientConnectionConsulMode() {
	consulDecoder := NewDecoder(ModeConsul)

	id, err := DecodeIdentifier("test-session-456", "", consulDecoder)
	suite.NoError(err)
	suite.Equal("test-session-456", id.Id)
	suite.Equal(api.Identifier_CLIENT, id.Type)
	suite.Empty(id.NodeAddr)
}

func (suite *DecodeIdentifierTestSuite) TestClientConnectionEmbeddedMode() {
	sessionID := "test-session-123"
	nodeAddr := "127.0.0.1:2222"

	// Create properly encoded SSH user for embedded mode
	encoder := NewEncodeDecoder(ModeEmbedded)
	encodedSSHUser := encoder.Encode(sessionID, nodeAddr)

	decoder := NewDecoder(ModeEmbedded)

	id, err := DecodeIdentifier(encodedSSHUser, "SSH-2.0-client", decoder)
	suite.NoError(err)
	suite.Equal(sessionID, id.Id)
	suite.Equal(api.Identifier_CLIENT, id.Type)
	suite.Equal(nodeAddr, id.NodeAddr)
}

func (suite *DecodeIdentifierTestSuite) TestInvalidBase64EmbeddedMode() {
	embeddedDecoder := NewDecoder(ModeEmbedded)

	_, err := DecodeIdentifier("session:invalid-base64===!@#$", "", embeddedDecoder)
	suite.Error(err, "expected error for invalid base64")
}

// Test suite runners
func TestEncodeDecoderSuite(t *testing.T) {
	suite.Run(t, new(EncodeDecoderTestSuite))
}

func TestDecodeIdentifierSuite(t *testing.T) {
	suite.Run(t, new(DecodeIdentifierTestSuite))
}
