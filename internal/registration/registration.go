// Package registration derives a session's ID from its host key and proves,
// over one connection, that a host holds that key (reconnect spec, section 3).
package registration

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

const (
	SecretLen  = 16
	IDLen      = 20 // the shape of uniuri.NewLen(uniuri.UUIDLen)
	idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	idDomain    = "upterm-session-id-v1"
	proofDomain = "upterm-session-v1"

	// What the relay refuses a registration with; the host classifies by these.
	RefusedProof = "upterm: session proof refused"
	Superseded   = "upterm: superseded by a newer registration"
)

var (
	errSecretLen  = fmt.Errorf("session secret must be %d bytes", SecretLen)
	errGeneration = errors.New("generation must be at least 1")
	errSessionID  = errors.New("no SSH session ID to bind the proof to")
)

// NewSecret generates a cryptographically random 16-byte session secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretLen)
	_, err := rand.Read(b)
	return b, err
}

// ID derives a 20-character session ID from the session key and secret.
// The ID is deterministic and stable across versions for a given key and secret.
func ID(sessionKey ssh.PublicKey, secret []byte) string {
	sum := sha256.Sum256(ssh.Marshal(struct {
		Domain      string
		Key, Secret []byte
	}{idDomain, sessionKey.Marshal(), secret}))
	n := new(big.Int).SetBytes(sum[:])
	base, digit := big.NewInt(int64(len(idAlphabet))), new(big.Int)
	out := make([]byte, IDLen)
	for i := range out {
		n.DivMod(n, base, digit)
		out[i] = idAlphabet[digit.Int64()]
	}
	return string(out)
}

func message(sshSessionID, secret []byte, generation uint64) []byte {
	return ssh.Marshal(struct {
		Domain            string
		SessionID, Secret []byte
		Generation        uint64
	}{proofDomain, sshSessionID, secret, generation})
}

func check(sshSessionID, secret []byte, generation uint64) error {
	switch {
	case len(secret) != SecretLen:
		return errSecretLen
	case generation < 1:
		return errGeneration
	case len(sshSessionID) == 0:
		return errSessionID
	}
	return nil
}

// Sign generates a proof that the holder of the key owns the session,
// binding it to a specific SSH connection ID and generation counter.
func Sign(key ssh.Signer, sshSessionID, secret []byte, generation uint64) ([]byte, error) {
	if err := check(sshSessionID, secret, generation); err != nil {
		return nil, err
	}
	sig, err := key.Sign(rand.Reader, message(sshSessionID, secret, generation))
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(sig), nil
}

// Verify checks that a proof is a valid signature of the session parameters
// by the holder of the session key, proving possession of that key.
func Verify(sessionKey ssh.PublicKey, sshSessionID, secret []byte, generation uint64, proof []byte) error {
	if err := check(sshSessionID, secret, generation); err != nil {
		return err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(proof, &sig); err != nil {
		return fmt.Errorf("malformed proof: %w", err)
	}
	return sessionKey.Verify(message(sshSessionID, secret, generation), &sig)
}
