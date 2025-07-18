package routing

import (
	"testing"
)

func TestEmbeddedEncodeDecoder(t *testing.T) {
	sessionID := "test-session-123"
	nodeAddr := "node1.example.com:22"

	encoder := NewEncodeDecoder(ModeEmbedded)

	// Test encoding
	encoded := encoder.Encode(sessionID, nodeAddr)

	// Test decoding
	decodedSessionID, decodedNodeAddr, err := encoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Errorf("Expected session ID %q, got %q", sessionID, decodedSessionID)
	}

	if decodedNodeAddr != nodeAddr {
		t.Errorf("Expected node addr %q, got %q", nodeAddr, decodedNodeAddr)
	}

	if encoder.Mode() != ModeEmbedded {
		t.Errorf("Expected mode %q, got %q", ModeEmbedded, encoder.Mode())
	}
}

func TestConsulEncodeDecoder(t *testing.T) {
	sessionID := "test-session-456"

	encoder := NewEncodeDecoder(ModeConsul)

	// Test encoding (should just return session ID)
	encoded := encoder.Encode(sessionID, "any-node")
	if encoded != sessionID {
		t.Errorf("Expected encoded value %q, got %q", sessionID, encoded)
	}

	// Test decoding
	decodedSessionID, decodedNodeAddr, err := encoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Errorf("Expected session ID %q, got %q", sessionID, decodedSessionID)
	}

	if decodedNodeAddr != "" {
		t.Errorf("Expected empty node addr for consul mode, got %q", decodedNodeAddr)
	}

	if encoder.Mode() != ModeConsul {
		t.Errorf("Expected mode %q, got %q", ModeConsul, encoder.Mode())
	}
}

func TestLegacyFunctions(t *testing.T) {
	sessionID := "test-session-789"
	nodeAddr := "node2.example.com:22"

	// Test legacy EncodeSSHUser function
	encoded := EncodeSSHUser(sessionID, nodeAddr, ModeEmbedded)

	// Test legacy DecodeSSHUser function
	decodedSessionID, decodedNodeAddr, mode, err := DecodeSSHUser(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Errorf("Expected session ID %q, got %q", sessionID, decodedSessionID)
	}

	if decodedNodeAddr != nodeAddr {
		t.Errorf("Expected node addr %q, got %q", nodeAddr, decodedNodeAddr)
	}

	if mode != ModeEmbedded {
		t.Errorf("Expected mode %q, got %q", ModeEmbedded, mode)
	}
}
