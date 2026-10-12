package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/owenthereal/upterm/join"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// keyFile is a private key file a test wrote, and the signer it holds.
type keyFile struct {
	path   string
	signer ssh.Signer
}

// newKeyFile writes an unencrypted ed25519 key, in the openssh format, to a
// directory of its own, with no .pub beside it.
func newKeyFile(t *testing.T) keyFile {
	t.Helper()
	priv, signer := newEd25519Signer(t)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return keyFile{path: writeFile(t, "id_ed25519", string(pem.EncodeToMemory(block))), signer: signer}
}

// newEncryptedKeyFile writes an ed25519 key encrypted with passphrase, in the
// openssh format, which carries its public half in the clear, to a directory
// of its own, with no .pub beside it.
func newEncryptedKeyFile(t *testing.T, passphrase string) keyFile {
	t.Helper()
	priv, signer := newEd25519Signer(t)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	return keyFile{path: writeFile(t, "id_ed25519", string(pem.EncodeToMemory(block))), signer: signer}
}

func newEd25519Signer(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return priv, signer
}

// writeFile writes content to name in a directory of its own, so that no two
// files a test writes are siblings, and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// fingerprints is each signer's SHA256 fingerprint, in order.
func fingerprints(signers []ssh.Signer) []string {
	out := make([]string, 0, len(signers))
	for _, s := range signers {
		out = append(out, utils.FingerprintSHA256(s.PublicKey()))
	}
	return out
}

func fp(k keyFile) string { return utils.FingerprintSHA256(k.signer.PublicKey()) }

// noPrompt is a passphrase prompt that fails the test if it is asked.
func noPrompt(t *testing.T) func(context.Context, string) ([]byte, error) {
	return func(_ context.Context, file string) ([]byte, error) {
		t.Errorf("asked for the passphrase of %s", file)
		return nil, errors.New("no passphrase in this test")
	}
}

func TestAnEncryptedKeyNotInTheAgentAsksOnce(t *testing.T) {
	enc := newEncryptedKeyFile(t, "secret")
	asked := 0
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{Files: []string{enc.path},
		Passphrase: func(context.Context, string) ([]byte, error) { asked++; return []byte("secret"), nil }})
	require.NoError(t, err)
	for i := 0; i < 2; i++ { // two attempts
		_, release, err := g.Signers(context.Background())
		require.NoError(t, err)
		release()
	}
	require.Equal(t, 1, asked)
}

func TestAKeyIsGeneratedOnlyWhenThereIsNoKeyAtAll(t *testing.T) {
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{})
	require.NoError(t, err)
	s1, r1, err := g.Signers(context.Background())
	require.NoError(t, err)
	r1()
	s2, r2, err := g.Signers(context.Background())
	require.NoError(t, err)
	r2()
	require.Len(t, s1, 1)
	require.Equal(t, fingerprints(s1), fingerprints(s2)) // kept for the run
	require.True(t, g.Source().Generated)
}

func TestFilesThatAllFailToLoadAreAnErrorNotAGeneratedKey(t *testing.T) {
	bad := writeFile(t, "id_ed25519", "not a key")
	_, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{Files: []string{bad}})
	var ie *join.IdentityError
	require.ErrorAs(t, err, &ie)
	require.Len(t, ie.Load, 1)
	require.Contains(t, ie.Load[0], bad)
}

func TestAFileThatWontLoadIsSkippedNextToAGoodKey(t *testing.T) { // an _sk key file x/crypto can't load, say
	good, bad := newKeyFile(t), writeFile(t, "id_ed25519_sk", "not a key x/crypto can load")
	var skipped []string
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		Files: []string{bad, good.path}, OnSkip: func(f string, _ error) { skipped = append(skipped, f) }})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	release()
	require.Equal(t, []string{fp(good)}, fingerprints(signers))
	require.Equal(t, []string{bad}, skipped)
}

func TestAnExplicitEntryThatWontLoadIsAnError(t *testing.T) { // -i: every entry must resolve
	good := newKeyFile(t)
	selector := writeFile(t, "id.pub", string(ssh.MarshalAuthorizedKey(newKeyFile(t).signer.PublicKey())))
	for _, bad := range []string{
		filepath.Join(t.TempDir(), "missing"), // can't be read
		selector,                              // names an agent key, with no agent
	} {
		_, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
			IdentitiesOnly: true, Files: []string{good.path, bad},
			OnSkip: func(f string, err error) { t.Errorf("skipped %s: %v", f, err) }})
		var ie *join.IdentityError
		require.ErrorAs(t, err, &ie)
		require.Len(t, ie.Load, 1)
		require.True(t, strings.HasPrefix(ie.Load[0], bad+": "), ie.Load[0])
	}
}

// staleAgentSocket is a socket file nobody listens on: an agent that exited
// without removing it.
func staleAgentSocket(t *testing.T) string {
	t.Helper()
	// Keep the socket path below macOS's Unix socket path limit.
	dir, err := os.MkdirTemp("", "agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	require.NoError(t, err)
	ln.SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	_, err = net.Dial("unix", socket)
	require.True(t, errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeconnrefused),
		"the socket file outlives its listener, and refuses: %v", err)
	return socket
}

// A stale socket is no agent, on Windows too, where it refuses the dial with
// WSAECONNREFUSED.
func TestAStaleAgentSocketIsNoAgent(t *testing.T) { // as if SSH_AUTH_SOCK were unset
	good := newKeyFile(t)
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		AgentSocket: staleAgentSocket(t), Files: []string{good.path},
		OnAgentSkip: func(err error) { t.Errorf("the agent was skipped: %v", err) }})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	release()
	require.Equal(t, []string{fp(good)}, fingerprints(signers))
	require.Equal(t, join.KeySource{Files: 1}, g.Source())
}

// A dial that finds nobody listening on the agent's socket is no agent, on
// every platform: unix's ENOENT or ECONNREFUSED, and Windows' WSAECONNREFUSED,
// which isn't the ECONNREFUSED Go makes up there. Any other failure is an
// agent that failed.
func TestADialNobodyListensOnIsNoAgent(t *testing.T) {
	dialErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", errno)}
	}
	for _, errno := range []syscall.Errno{syscall.ENOENT, syscall.ECONNREFUSED, wsaeconnrefused} {
		require.True(t, nobodyListens(dialErr(errno)), "%v", errno)
	}
	require.False(t, nobodyListens(dialErr(syscall.EACCES)))
}
