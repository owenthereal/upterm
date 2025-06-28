package routing

import (
	"testing"
)

func TestEncodeDecodeEmbedded(t *testing.T) {
	sessionID := "test-session-123"
	nodeAddr := "node1.example.com:22"

	// Test embedded encoding
	encoded := EncodeSSHUser(sessionID, nodeAddr, ModeEmbedded)

	// Test decoding
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

func TestEncodeDecodeConsul(t *testing.T) {
	sessionID := "test-session-456"

	// Test consul encoding
	encoded := EncodeSSHUser(sessionID, "any-node", ModeConsul)

	// Should just return the session ID
	if encoded != sessionID {
		t.Errorf("Expected encoded value %q, got %q", sessionID, encoded)
	}

	// Test decoding
	decodedSessionID, decodedNodeAddr, mode, err := DecodeSSHUser(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Errorf("Expected session ID %q, got %q", sessionID, decodedSessionID)
	}

	if decodedNodeAddr != "" {
		t.Errorf("Expected empty node addr for consul mode, got %q", decodedNodeAddr)
	}

	if mode != ModeConsul {
		t.Errorf("Expected mode %q, got %q", ModeConsul, mode)
	}
}
