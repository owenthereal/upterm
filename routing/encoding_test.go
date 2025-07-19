package routing

import (
	"testing"

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

func (suite *EncodeDecoderTestSuite) TestConsulDecodeBackwardCompatibility() {
	sessionID := "test-session-123"
	nodeAddr := "127.0.0.1:2222"

	// Create an embedded format SSH user (what old clients send)
	embeddedEncoder := NewEncodeDecoder(ModeEmbedded)
	embeddedSSHUser := embeddedEncoder.Encode(sessionID, nodeAddr)

	// Test that Consul decoder can handle embedded format
	consulDecoder := NewEncodeDecoder(ModeConsul)
	decodedSessionID, decodedNodeAddr, err := consulDecoder.Decode(embeddedSSHUser)
	
	suite.NoError(err)
	suite.Equal(sessionID, decodedSessionID, "should extract session ID from embedded format")
	suite.Empty(decodedNodeAddr, "consul decoder should return empty node address")

	// Test that it still works with pure consul format
	decodedSessionID2, decodedNodeAddr2, err2 := consulDecoder.Decode(sessionID)
	suite.NoError(err2)
	suite.Equal(sessionID, decodedSessionID2, "should handle pure consul format")
	suite.Empty(decodedNodeAddr2, "consul decoder should return empty node address")
}

// Test suite runners
func TestEncodeDecoderSuite(t *testing.T) {
	suite.Run(t, new(EncodeDecoderTestSuite))
}
