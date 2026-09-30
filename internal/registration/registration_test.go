package registration

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// goldenKey is the ed25519 key the server and ftests packages also use.
const goldenKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmAAAAIiRPFazkTxW
swAAAAtzc2gtZWQyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmA
AAAEDmpjZHP/SIyBTp6YBFPzUi18iDo2QHolxGRDpx+m7let0EWrjdcHcuMfI8bGAyHPcG
sAc/vd/gl5673pRkRBGYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`

func newKey(t *testing.T) ssh.Signer {
	t.Helper()
	keys, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	return keys[0]
}

// Host and relay run different versions and both derive the ID, so the
// output for one fixed input is part of the contract.
func TestIDIsPinned(t *testing.T) {
	key, err := ssh.ParsePrivateKey([]byte(goldenKey))
	require.NoError(t, err)
	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	require.Equal(t, "wtMmTSFPYXAIXO7cXhhP", ID(key.PublicKey(), secret))
}

func TestIDShapeAndInputs(t *testing.T) {
	key := newKey(t)
	secret := bytes.Repeat([]byte{7}, SecretLen)
	id := ID(key.PublicKey(), secret)
	require.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9]{20}$`), id)
	require.Equal(t, id, ID(key.PublicKey(), secret))
	require.NotEqual(t, id, ID(key.PublicKey(), bytes.Repeat([]byte{8}, SecretLen)))
	require.NotEqual(t, id, ID(newKey(t).PublicKey(), secret))
}

func TestProofRoundTripAndRefusals(t *testing.T) {
	key, other := newKey(t), newKey(t)
	secret := bytes.Repeat([]byte{7}, SecretLen)
	proof, err := Sign(key, []byte("conn-1"), secret, 3)
	require.NoError(t, err)
	require.NoError(t, Verify(key.PublicKey(), []byte("conn-1"), secret, 3, proof))

	for name, verify := range map[string]func() error{
		"another key":        func() error { return Verify(other.PublicKey(), []byte("conn-1"), secret, 3, proof) },
		"another connection": func() error { return Verify(key.PublicKey(), []byte("conn-2"), secret, 3, proof) },
		"another secret": func() error {
			return Verify(key.PublicKey(), []byte("conn-1"), bytes.Repeat([]byte{8}, SecretLen), 3, proof)
		},
		"another generation": func() error { return Verify(key.PublicKey(), []byte("conn-1"), secret, 4, proof) },
		"malformed":          func() error { return Verify(key.PublicKey(), []byte("conn-1"), secret, 3, []byte("junk")) },
		"short secret":       func() error { return Verify(key.PublicKey(), []byte("conn-1"), secret[:8], 3, proof) },
		"generation zero":    func() error { return Verify(key.PublicKey(), []byte("conn-1"), secret, 0, proof) },
		"no connection":      func() error { return Verify(key.PublicKey(), nil, secret, 3, proof) },
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, verify()) })
	}
	_, err = Sign(key, []byte("conn-1"), secret, 0)
	require.Error(t, err)
	_, err = Sign(key, []byte("conn-1"), secret[:8], 1)
	require.Error(t, err)
}

func TestVerifyRefusesAProofOverBadInputs(t *testing.T) {
	key := newKey(t)

	// A hostile host can sign any message it likes, including invalid inputs.
	// Verify must reject these even if they have a valid signature.
	for name, test := range map[string]struct {
		sshSessionID []byte
		secret       []byte
		generation   uint64
	}{
		"8-byte secret": {
			sshSessionID: []byte("conn-1"),
			secret:       bytes.Repeat([]byte{7}, 8),
			generation:   3,
		},
		"generation 0": {
			sshSessionID: []byte("conn-1"),
			secret:       bytes.Repeat([]byte{7}, SecretLen),
			generation:   0,
		},
		"empty session ID": {
			sshSessionID: nil,
			secret:       bytes.Repeat([]byte{7}, SecretLen),
			generation:   3,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Sign the (bad) message directly, bypassing Sign's check.
			msg := message(test.sshSessionID, test.secret, test.generation)
			sig, err := key.Sign(nil, msg)
			require.NoError(t, err)
			proof := ssh.Marshal(sig)

			// Verify must refuse this proof even though the signature is valid.
			require.Error(t, Verify(key.PublicKey(), test.sshSessionID, test.secret, test.generation, proof))
		})
	}
}
