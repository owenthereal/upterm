//go:build !windows

package host

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testAgent is a fake ssh-agent on a unix socket that counts the connections
// it accepts and the signatures it makes. The two counters are the point:
// "never dialled" and "never asked to sign" are the guarantees under test.
type testAgent struct {
	socket     string
	keyring    agent.ExtendedAgent
	accepts    atomic.Int32
	signatures atomic.Int32
}

// countingAgent wraps the keyring so both signing entry points are counted.
// agent.ServeAgent routes every sign request through SignWithFlags when the
// agent implements ExtendedAgent, including plain Sign calls from the client
// (flags 0), and the RSA-SHA2 algorithms arrive with a non-zero flag.
type countingAgent struct {
	agent.ExtendedAgent
	ta *testAgent
}

func (c *countingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	c.ta.signatures.Add(1)
	return c.ExtendedAgent.Sign(key, data)
}

func (c *countingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	c.ta.signatures.Add(1)
	return c.ExtendedAgent.SignWithFlags(key, data, flags)
}

// startTestAgent serves keys on a fresh socket for the test's lifetime.
func startTestAgent(t *testing.T, keys ...interface{}) *testAgent {
	t.Helper()

	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	require.True(t, ok, "x/crypto's keyring implements ExtendedAgent")
	for _, k := range keys {
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: k}))
	}

	// Keep the socket path below macOS's Unix socket path limit.
	dir, err := os.MkdirTemp("", "agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ta := &testAgent{socket: filepath.Join(dir, "sock"), keyring: keyring}

	ln, err := net.Listen("unix", ta.socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	counted := &countingAgent{ExtendedAgent: keyring, ta: ta}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			ta.accepts.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = agent.ServeAgent(counted, conn)
			}()
		}
	}()
	return ta
}

func newEd25519(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return sshPub, priv
}

func writeTestFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0600))
	return path
}

func TestSignersFromAgent(t *testing.T) {
	for _, populated := range []bool{false, true} {
		name := "empty"
		if populated {
			name = "populated"
		}
		t.Run(name, func(t *testing.T) {
			publicKey, privateKey := newEd25519(t)
			var ta *testAgent
			if populated {
				ta = startTestAgent(t, privateKey)
			} else {
				ta = startTestAgent(t)
			}
			t.Setenv("SSH_AUTH_SOCK", ta.socket)

			signers, cleanup, err := Signers(nil, false)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			require.NoError(t, err)
			require.Len(t, signers, 1)
			message := []byte("authenticate with an agent or temporary key")
			signature, err := signers[0].Sign(rand.Reader, message)
			require.NoError(t, err)
			require.NoError(t, signers[0].PublicKey().Verify(message, signature))
			if populated {
				require.Equal(t, publicKey.Marshal(), signers[0].PublicKey().Marshal())
				require.EqualValues(t, 1, ta.signatures.Load())
			}
		})
	}
}

func TestIdentitySigners_UnencryptedFileNeverDialsTheAgent(t *testing.T) {
	_, agentKey := newEd25519(t)
	ta := startTestAgent(t, agentKey)

	filePub, filePriv := newEd25519(t)
	block, err := ssh.MarshalPrivateKey(filePriv, "")
	require.NoError(t, err)
	keyFile := writeTestFile(t, t.TempDir(), "key", pem.EncodeToMemory(block))

	signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	require.Equal(t, filePub.Marshal(), signers[0].PublicKey().Marshal())
	_, err = signers[0].Sign(rand.Reader, []byte("m"))
	require.NoError(t, err)
	require.Zero(t, ta.accepts.Load(), "the agent socket was never opened")
}

func TestIdentitySigners_EncryptedOpenSSHFileHeldByAgentSignsThere(t *testing.T) {
	// The fixture's key, unlocked into the agent the way ssh-add would.
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(ed25519PriavteKey), []byte("1234"))
	require.NoError(t, err)
	ta := startTestAgent(t, raw)
	keyFile := writeTestFile(t, t.TempDir(), "key", []byte(ed25519PriavteKey))

	// No .pub beside it: the public half comes from the file itself.
	signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ed25519PublicKey))
	require.NoError(t, err)
	require.Equal(t, want.Marshal(), signers[0].PublicKey().Marshal())

	_, err = signers[0].Sign(rand.Reader, []byte("m"))
	require.NoError(t, err)
	require.EqualValues(t, 1, ta.signatures.Load(), "signed through the agent")
}

func TestIdentitySigners_EncryptedFileNotHeldByAgentPrompts(t *testing.T) {
	_, unrelated := newEd25519(t)
	ta := startTestAgent(t, unrelated)
	keyFile := writeTestFile(t, t.TempDir(), "key", []byte(ed25519PriavteKey))

	prompts := 0
	signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, func(string) ([]byte, error) {
		prompts++
		return []byte("1234"), nil
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	require.Equal(t, 1, prompts)
	_, err = signers[0].Sign(rand.Reader, []byte("m"))
	require.NoError(t, err)
	require.Zero(t, ta.signatures.Load(), "the file's own key signed")
}

// legacyPEM writes an encrypted "EC PRIVATE KEY" PEM, the pre-2018 OpenSSH
// format, which carries no public half.
func legacyPEM(t *testing.T, dir string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte("1234"), x509.PEMCipherAES256) //nolint:staticcheck // the legacy format is exactly what this case is about
	require.NoError(t, err)
	return writeTestFile(t, dir, "legacy", pem.EncodeToMemory(block)), priv
}

func TestIdentitySigners_LegacyPEMUsesThePubBeside(t *testing.T) {
	dir := t.TempDir()
	keyFile, priv := legacyPEM(t, dir)
	ta := startTestAgent(t, priv)
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	t.Run("with a .pub, the agent signs", func(t *testing.T) {
		writeTestFile(t, dir, "legacy.pub", ssh.MarshalAuthorizedKey(pub))
		t.Cleanup(func() { _ = os.Remove(keyFile + ".pub") })
		signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Equal(t, pub.Marshal(), signers[0].PublicKey().Marshal())
		_, err = signers[0].Sign(rand.Reader, []byte("m"))
		require.NoError(t, err)
		require.EqualValues(t, 1, ta.signatures.Load())
	})

	t.Run("without one, the passphrase is asked", func(t *testing.T) {
		prompts := 0
		signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, func(string) ([]byte, error) {
			prompts++
			return []byte("1234"), nil
		})
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Equal(t, pub.Marshal(), signers[0].PublicKey().Marshal())
		require.Equal(t, 1, prompts)
	})
}

// TestIdentitySigners_SecurityKeyStubResolvesThroughAgent is the regression
// this fix closes: `upterm host -i ~/.ssh/id_ed25519_sk` failed with
// "unhandled key type" because x/crypto cannot turn a FIDO/security-key
// private file into a signer at all. The fake agent cannot hold a genuine sk
// key either — x/crypto's agent keyring only accepts standard private key
// types, and a real sk key needs actual hardware behind it — so it holds an
// ordinary ed25519 key, and the .pub sibling names that key rather than a
// real, matching sk-ssh-ed25519 public key. What is under test is that an
// unparseable *private* file is resolved through the agent by its public
// half, exactly like an encrypted key already is; the stub's own embedded
// public key blob plays no further role once ssh.ParseRawPrivateKey has
// rejected it.
func TestIdentitySigners_SecurityKeyStubResolvesThroughAgent(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ta := startTestAgent(t, agentPriv)

	stubPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dir := t.TempDir()
	keyFile := writeTestFile(t, dir, "id_ed25519_sk", skEd25519PrivateStub(t, stubPub))
	writeTestFile(t, dir, "id_ed25519_sk.pub", ssh.MarshalAuthorizedKey(agentPub))

	signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	require.Equal(t, agentPub.Marshal(), signers[0].PublicKey().Marshal())

	_, err = signers[0].Sign(rand.Reader, []byte("m"))
	require.NoError(t, err)
	require.EqualValues(t, 1, ta.signatures.Load(), "signed through the agent")
}

// TestIdentitySigners_SecurityKeyStubNotHeldByAgentIsAnError covers the sk
// stub whose .pub sibling names a key the agent does not hold: the error
// must name both facts, that the file itself could not be parsed and that
// the agent could not supply it either.
func TestIdentitySigners_SecurityKeyStubNotHeldByAgentIsAnError(t *testing.T) {
	_, unrelatedPriv := newEd25519(t)
	ta := startTestAgent(t, unrelatedPriv)

	stubPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	notHeldPub, _ := newEd25519(t)
	dir := t.TempDir()
	keyFile := writeTestFile(t, dir, "id_ed25519_sk", skEd25519PrivateStub(t, stubPub))
	writeTestFile(t, dir, "id_ed25519_sk.pub", ssh.MarshalAuthorizedKey(notHeldPub))

	_, _, err = identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.ErrorContains(t, err, "cannot parse private key "+keyFile)
	require.ErrorContains(t, err, "unhandled key type")
	require.ErrorContains(t, err, "the SSH agent does not hold")
}

// skEd25519PrivateStubEmbedding builds the same sk-stub container as
// skEd25519PrivateStub (host/signer_test.go), except the caller supplies the
// container's embedded PubKey blob directly instead of it being computed
// from a public key via skEd25519PublicKeyBlob. It exists for the two tests
// below: a genuine sk key's container embeds an sk-wire blob
// (skEd25519PublicKeyBlob's shape), but x/crypto's agent.NewKeyring() cannot
// hold a real sk key — only standard private key types — so these tests
// stand in an ordinary ed25519 key for what the agent holds, and need the
// embedded PubKey to be that ordinary key's plain ssh-ed25519 blob for the
// two to match. The private block's key type stays
// sk-ssh-ed25519@openssh.com regardless, so the file still reaches
// x/crypto's "ssh: unhandled key type" failure the way a real FIDO stub
// would.
func skEd25519PrivateStubEmbedding(t *testing.T, pubKeyBlob []byte) []byte {
	t.Helper()

	privBlock := ssh.Marshal(skOpenSSHPrivateBlock{
		Check1:  0x2a2a2a2a,
		Check2:  0x2a2a2a2a,
		Keytype: "sk-ssh-ed25519@openssh.com",
	})
	container := ssh.Marshal(skOpenSSHContainer{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       pubKeyBlob,
		PrivKeyBlock: privBlock,
	})
	full := append([]byte(skPrivateKeyAuthMagic), container...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: full})
}

// TestIdentitySigners_SecurityKeyStubWithNoPubSiblingResolvesThroughAgent is
// the gap this fix closes: an sk stub with no .pub sibling used to be
// unresolvable even when the agent held the matching key, because nothing
// recovered a public key to look the agent up with. Now the public key
// embedded in the openssh-key-v1 container itself is tried, exactly as the
// .pub sibling already was. See skEd25519PrivateStubEmbedding for why the
// fixture substitutes an ordinary ed25519 key for what would be a real sk
// key on real hardware.
func TestIdentitySigners_SecurityKeyStubWithNoPubSiblingResolvesThroughAgent(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ta := startTestAgent(t, agentPriv)

	dir := t.TempDir()
	keyFile := writeTestFile(t, dir, "id_ed25519_sk", skEd25519PrivateStubEmbedding(t, agentPub.Marshal()))
	// Deliberately no id_ed25519_sk.pub beside it.

	signers, cleanup, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	require.Equal(t, agentPub.Marshal(), signers[0].PublicKey().Marshal())

	_, err = signers[0].Sign(rand.Reader, []byte("m"))
	require.NoError(t, err)
	require.EqualValues(t, 1, ta.signatures.Load(), "signed through the agent")
}

// TestIdentitySigners_SecurityKeyStubWithNoPubSiblingNotHeldByAgentIsAnError
// is the other half of the gap: with no .pub sibling and the agent not
// holding the embedded key either, resolution still fails, and the error
// must say so — the same two facts
// TestIdentitySigners_SecurityKeyStubNotHeldByAgentIsAnError asserts for the
// .pub-sibling case.
func TestIdentitySigners_SecurityKeyStubWithNoPubSiblingNotHeldByAgentIsAnError(t *testing.T) {
	_, unrelatedPriv := newEd25519(t)
	ta := startTestAgent(t, unrelatedPriv)

	notHeldPub, _ := newEd25519(t)
	dir := t.TempDir()
	keyFile := writeTestFile(t, dir, "id_ed25519_sk", skEd25519PrivateStubEmbedding(t, notHeldPub.Marshal()))

	_, _, err := identitySigners([]string{keyFile}, ta.socket, failingPrompt(t))
	require.ErrorContains(t, err, "cannot parse private key "+keyFile)
	require.ErrorContains(t, err, "unhandled key type")
	require.ErrorContains(t, err, "the SSH agent does not hold")
}

func TestIdentitySigners_PubSelectsAnAgentKey(t *testing.T) {
	pub, priv := newEd25519(t)
	ta := startTestAgent(t, priv)
	dir := t.TempDir()
	pubFile := writeTestFile(t, dir, "id.pub", ssh.MarshalAuthorizedKey(pub))

	t.Run("held", func(t *testing.T) {
		signers, cleanup, err := identitySigners([]string{pubFile}, ta.socket, failingPrompt(t))
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Len(t, signers, 1)
		require.Equal(t, pub.Marshal(), signers[0].PublicKey().Marshal())
		_, err = signers[0].Sign(rand.Reader, []byte("m"))
		require.NoError(t, err)
		require.EqualValues(t, 1, ta.signatures.Load())
	})

	t.Run("not held", func(t *testing.T) {
		other, _ := newEd25519(t)
		otherFile := writeTestFile(t, dir, "other.pub", ssh.MarshalAuthorizedKey(other))
		_, _, err := identitySigners([]string{otherFile}, ta.socket, failingPrompt(t))
		require.ErrorContains(t, err, otherFile+": the SSH agent does not hold")
	})
}

func TestIdentitySigners_SelectorsAgainstCertificateEntries(t *testing.T) {
	pub, priv := newEd25519(t)
	_, caPriv := newEd25519(t)
	ca, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	cert := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "alice", ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, ca))

	// The agent holds only the certificate entry, which is what ssh-add
	// leaves when a key is added with its -cert.pub beside it.
	ta := startTestAgent(t)
	require.NoError(t, ta.keyring.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert}))
	dir := t.TempDir()

	t.Run("a raw .pub matches by underlying key", func(t *testing.T) {
		rawFile := writeTestFile(t, dir, "id.pub", ssh.MarshalAuthorizedKey(pub))
		signers, cleanup, err := identitySigners([]string{rawFile}, ta.socket, failingPrompt(t))
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Equal(t, cert.Marshal(), signers[0].PublicKey().Marshal(), "the certificate entry signs")
	})

	t.Run("a certificate selector matches exactly", func(t *testing.T) {
		certFile := writeTestFile(t, dir, "id-cert.pub", ssh.MarshalAuthorizedKey(cert))
		signers, cleanup, err := identitySigners([]string{certFile}, ta.socket, failingPrompt(t))
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Equal(t, cert.Marshal(), signers[0].PublicKey().Marshal())

		other := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "bob", ValidBefore: ssh.CertTimeInfinity}
		require.NoError(t, other.SignCert(rand.Reader, ca))
		otherFile := writeTestFile(t, dir, "other-cert.pub", ssh.MarshalAuthorizedKey(other))
		_, _, err = identitySigners([]string{otherFile}, ta.socket, failingPrompt(t))
		require.ErrorContains(t, err, "does not hold", "another certificate for the same key is another identity")
	})
}

func TestIdentitySigners_RSAAgentKeySignsWithFlags(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ta := startTestAgent(t, priv)
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubFile := writeTestFile(t, t.TempDir(), "id_rsa.pub", ssh.MarshalAuthorizedKey(pub))

	signers, cleanup, err := identitySigners([]string{pubFile}, ta.socket, failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	as, ok := signers[0].(ssh.AlgorithmSigner)
	require.True(t, ok, "agent signers pick algorithms")
	sig, err := as.SignWithAlgorithm(rand.Reader, []byte("m"), ssh.KeyAlgoRSASHA256)
	require.NoError(t, err)
	require.Equal(t, ssh.KeyAlgoRSASHA256, sig.Format, "RSA-SHA2 went through SignWithFlags")
	require.NoError(t, pub.Verify([]byte("m"), sig))
	require.EqualValues(t, 1, ta.signatures.Load())
}
