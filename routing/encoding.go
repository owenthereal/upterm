package routing

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
)

var (
	ErrInvalidSSHUser = fmt.Errorf("invalid SSH user")
)

// Encoder defines the interface for encoding session information into SSH usernames
type Encoder interface {
	// Encode encodes a session ID and node address into an SSH username
	Encode(sessionID, nodeAddr string) string
}

// Decoder defines the interface for decoding SSH usernames into session information
type Decoder interface {
	// Decode decodes an SSH username into session ID and node address
	Decode(sshUser string) (sessionID, nodeAddr string, err error)
}

// ModeProvider defines the interface for getting the routing mode
type ModeProvider interface {
	// Mode returns the routing mode for this encoder/decoder
	Mode() Mode
}

// EncodeDecoder defines the composite interface for encoding and decoding SSH usernames
type EncodeDecoder interface {
	Encoder
	Decoder
	ModeProvider
}

// NewEncoder creates an Encoder for the specified routing mode
func NewEncoder(mode Mode) Encoder {
	return NewEncodeDecoder(mode)
}

// NewDecoder creates a Decoder for the specified routing mode
func NewDecoder(mode Mode) Decoder {
	return NewEncodeDecoder(mode)
}

// NewEncodeDecoder creates an EncodeDecoder for the specified routing mode
func NewEncodeDecoder(mode Mode) EncodeDecoder {
	switch mode {
	case ModeEmbedded:
		return &EmbeddedEncodeDecoder{}
	case ModeConsul:
		return &ConsulEncodeDecoder{}
	default:
		return &EmbeddedEncodeDecoder{} // Default to embedded
	}
}

// EmbeddedEncodeDecoder implements EncodeDecoder for embedded routing mode
type EmbeddedEncodeDecoder struct{}

func (e *EmbeddedEncodeDecoder) Encode(sessionID, nodeAddr string) string {
	return sessionID + ":" + base64.URLEncoding.EncodeToString([]byte(nodeAddr))
}

func (e *EmbeddedEncodeDecoder) Decode(sshUser string) (sessionID, nodeAddr string, err error) {
	split := strings.SplitN(sshUser, ":", 2)
	if len(split) != 2 {
		return "", "", ErrInvalidSSHUser
	}

	nodeAddrBytes, err := base64.URLEncoding.DecodeString(split[1])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode node address: %w", err)
	}

	return split[0], string(nodeAddrBytes), nil
}

func (e *EmbeddedEncodeDecoder) Mode() Mode {
	return ModeEmbedded
}

// ConsulEncodeDecoder implements EncodeDecoder for Consul routing mode
type ConsulEncodeDecoder struct{}

func (c *ConsulEncodeDecoder) Encode(sessionID, nodeAddr string) string {
	return sessionID
}

func (c *ConsulEncodeDecoder) Decode(sshUser string) (sessionID, nodeAddr string, err error) {
	if sshUser == "" {
		return "", "", ErrInvalidSSHUser
	}

	// In Consul mode, the SSH user is just the session ID
	return sshUser, "", nil
}

func (c *ConsulEncodeDecoder) Mode() Mode {
	return ModeConsul
}

// ConnectionType represents the type of SSH connection
type ConnectionType int

const (
	ConnectionTypeHost ConnectionType = iota
	ConnectionTypeClient
)

// DecodeIdentifier decodes an SSH user and client version into an API Identifier
func DecodeIdentifier(sshUser, clientVersion string, decoder Decoder) (*api.Identifier, error) {
	// Check connection type based on client version
	if clientVersion == upterm.HostSSHClientVersion {
		// HOST connection
		return &api.Identifier{
			Id:   sshUser,
			Type: api.Identifier_HOST,
		}, nil
	}

	// CLIENT connection: decode the SSH user to get session ID and node address
	sessionID, nodeAddr, err := decoder.Decode(sshUser)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SSH user: %w", err)
	}
	return &api.Identifier{
		Id:       sessionID,
		Type:     api.Identifier_CLIENT,
		NodeAddr: nodeAddr,
	}, nil
}
