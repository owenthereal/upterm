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
	// SecretLen is the length of a session secret. The secret keeps the ID
	// from being computable by anyone who learns the public key, and the relay
	// refuses any other length.
	SecretLen = 16
	// IDLen is the length of a derived session ID. It matches the shape of
	// random IDs the relay issues today, so connect strings and tooling don't
	// change.
	IDLen      = 20 // the shape of uniuri.NewLen(uniuri.UUIDLen)
	idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	idDomain    = "upterm-session-id-v1"
	proofDomain = "upterm-session-v1"

	// RefusedProof is what the relay sends when it refuses a registration.
	// The host classifies this refusal by this exact text, so it is part of
	// the wire contract.
	RefusedProof = "upterm: session proof refused"
	// Superseded is what the relay sends when a newer registration supersedes
	// an older one. The host classifies this refusal by this exact text, so it
	// is part of the wire contract.
	Superseded = "upterm: superseded by a newer registration"
)

var (
	errSecretLen  = fmt.Errorf("session secret must be %d bytes", SecretLen)
	errGeneration = errors.New("generation must be at least 1")
	errSessionID  = errors.New("no SSH session ID to bind the proof to")
)

// NewSecret generates a new session secret for a host process. The secret is
// kept in memory for the process's lifetime, and that stability keeps the
// session ID constant across redials.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretLen)
	_, err := rand.Read(b)
	return b, err
}

// ID derives a deterministic session ID from the session key and secret.
// Host and relay both compute it independently and may run different versions,
// so the output is pinned by a golden test. It is domain-separated from the
// proof so the two hashes can never be confused.
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

// Sign generates a proof of key possession. It binds the proof to one SSH
// connection (so a captured proof can't replay on another connection) and to
// one generation (so a delayed older registration can't claim a newer one's place).
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

// Verify is what the relay runs before accepting a derived ID. It checks the
// inputs itself because a hostile host can sign any message it likes, including
// generation 0, an empty session ID, or an invalid secret length.
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
