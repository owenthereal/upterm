package routing

import (
	"testing"
)

func TestInterfaceSeparation(t *testing.T) {
	// Test that we can use individual interfaces
	var encoder Encoder = NewEncoder(ModeEmbedded)
	var decoder Decoder = NewDecoder(ModeEmbedded)
	var encodeDecoder EncodeDecoder = NewEncodeDecoder(ModeEmbedded)

	sessionID := "test-session"
	nodeAddr := "localhost:8080"

	// Test encoding with individual interface
	encoded := encoder.Encode(sessionID, nodeAddr)
	if encoded == "" {
		t.Error("encoded string should not be empty")
	}

	// Test decoding with individual interface
	decodedSessionID, decodedNodeAddr, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decodedSessionID != sessionID {
		t.Errorf("expected session ID %s, got %s", sessionID, decodedSessionID)
	}
	if decodedNodeAddr != nodeAddr {
		t.Errorf("expected node addr %s, got %s", nodeAddr, decodedNodeAddr)
	}

	// Test composite interface
	encoded2 := encodeDecoder.Encode(sessionID, nodeAddr)
	if encoded2 != encoded {
		t.Error("composite interface should produce same result")
	}

	decodedSessionID2, decodedNodeAddr2, err := encodeDecoder.Decode(encoded2)
	if err != nil {
		t.Fatalf("composite decode failed: %v", err)
	}
	if decodedSessionID2 != sessionID || decodedNodeAddr2 != nodeAddr {
		t.Error("composite interface should produce same result")
	}

	// Test mode provider
	if encodeDecoder.Mode() != ModeEmbedded {
		t.Error("mode should be embedded")
	}
}

func TestUtilityFunctions(t *testing.T) {
	encoder := NewEncoder(ModeConsul)
	decoder := NewDecoder(ModeConsul)

	sessionID := "test-session"
	nodeAddr := "localhost:8080"

	// Test utility functions
	encoded := EncodeWithEncoder(encoder, sessionID, nodeAddr)
	decodedSessionID, decodedNodeAddr, err := DecodeWithDecoder(decoder, encoded)
	if err != nil {
		t.Fatalf("utility decode failed: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Errorf("expected session ID %s, got %s", sessionID, decodedSessionID)
	}

	// In consul mode, nodeAddr should be empty
	if decodedNodeAddr != "" {
		t.Errorf("expected empty node addr in consul mode, got %s", decodedNodeAddr)
	}
}
