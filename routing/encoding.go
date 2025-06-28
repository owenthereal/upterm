package routing

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// EncodeSSHUser encodes a session ID and node address into an SSH username based on the routing mode
func EncodeSSHUser(sessionID, nodeAddr string, mode Mode) string {
	switch mode {
	case ModeEmbedded:
		return encodeEmbedded(sessionID, nodeAddr)
	case ModeConsul:
		return encodeConsul(sessionID)
	default:
		return encodeEmbedded(sessionID, nodeAddr) // Default to embedded
	}
}

// encodeEmbedded encodes with node address embedded in the identifier (embedded mode)
func encodeEmbedded(sessionID, nodeAddr string) string {
	return sessionID + ":" + base64.URLEncoding.EncodeToString([]byte(nodeAddr))
}

// encodeConsul encodes for Consul-based routing (just the session ID)
func encodeConsul(sessionID string) string {
	return sessionID
}

// DecodeSSHUser decodes an SSH username and determines the routing mode
func DecodeSSHUser(sshUser string) (sessionID, nodeAddr string, mode Mode, err error) {
	// Check if it's embedded routing format (contains encoded node address)
	if strings.Contains(sshUser, ":") {
		sessionID, nodeAddr, err = decodeEmbedded(sshUser)
		if err != nil {
			return "", "", "", err
		}
		return sessionID, nodeAddr, ModeEmbedded, nil
	}

	// Consul routing format: just the session ID
	return sshUser, "", ModeConsul, nil
}

// decodeEmbedded handles the embedded routing format
func decodeEmbedded(sshUser string) (sessionID, nodeAddr string, err error) {
	split := strings.SplitN(sshUser, ":", 2)
	if len(split) != 2 {
		return "", "", fmt.Errorf("invalid embedded routing ssh user: %s", sshUser)
	}

	nodeAddrBytes, err := base64.URLEncoding.DecodeString(split[1])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode node address: %w", err)
	}

	return split[0], string(nodeAddrBytes), nil
}
