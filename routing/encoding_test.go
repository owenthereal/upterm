package routing

import (
	"testing"

	"github.com/owenthereal/upterm/host/api"
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

func TestDecodeIdentifier(t *testing.T) {
	// Test invalid base64 in embedded mode should fail
	embeddedDecoder := NewDecoder(ModeEmbedded)
	_, err := DecodeIdentifier("10OLFAKZu4cxx2roOboaY:MTI3LjAuMC4xOjIyMjIIII=", "", embeddedDecoder)
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Test plain session ID (Consul mode) should succeed
	consulDecoder := NewDecoder(ModeConsul)
	id, err := DecodeIdentifier("10OLFAKZu4cxx2roOboaY", "", consulDecoder)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id.Id != "10OLFAKZu4cxx2roOboaY" {
		t.Errorf("expected session ID %s, got %s", "10OLFAKZu4cxx2roOboaY", id.Id)
	}
	if id.Type != api.Identifier_CLIENT {
		t.Errorf("expected CLIENT type, got %v", id.Type)
	}
	if id.NodeAddr != "" {
		t.Errorf("expected empty node addr for Consul mode, got %s", id.NodeAddr)
	}

	// Test HOST connection
	id, err = DecodeIdentifier("session123", "SSH-2.0-upterm-host-client", consulDecoder)
	if err != nil {
		t.Fatalf("expected no error for host connection, got: %v", err)
	}
	if id.Id != "session123" {
		t.Errorf("expected session ID %s, got %s", "session123", id.Id)
	}
	if id.Type != api.Identifier_HOST {
		t.Errorf("expected HOST type, got %v", id.Type)
	}
	if id.NodeAddr != "" {
		t.Errorf("expected empty node addr for host connection, got %s", id.NodeAddr)
	}
}
