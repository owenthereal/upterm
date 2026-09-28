package ftests

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// failAfterFirstSign is an identity that signs exactly once. It stands in for
// an agent that confirms each signature and is then declined: the tunnel
// handshake gets the one, and anything that asks again — a guest join, an
// attach, a rekey — fails loudly instead of silently working.
type failAfterFirstSign struct {
	ssh.Signer
	calls atomic.Int32
}

func (s *failAfterFirstSign) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if s.calls.Add(1) > 1 {
		return nil, errors.New("the identity was asked to sign a second time")
	}
	return s.Signer.Sign(rand, data)
}

func guestKeyFile(t *testing.T) string {
	t.Helper()
	path, err := writeTempFile("id_ed25519", ClientPrivateKeyContent)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func awaitSession(t *testing.T, sessions <-chan *api.GetSessionResponse) *api.GetSessionResponse {
	t.Helper()
	select {
	case s := <-sessions:
		return s
	case <-time.After(outcomeTimeout):
		t.Fatal("the session was never created")
		return nil
	}
}

// Test_Host_IdentitySignsOnceAndTheDoorsUseTheSessionKey is the assertion
// the session host key exists for: one identity signature for the tunnel,
// then guest joins and an attach on a key the identity never touches, with
// guests on a key of their own that is neither the identity nor the session
// key and no guest restriction in force.
func Test_Host_IdentitySignsOnceAndTheDoorsUseTheSessionKey(t *testing.T) {
	identity, err := utils.CreateSigners([][]byte{[]byte(HostPrivateKeyContent)})
	require.NoError(t, err)
	once := &failAfterFirstSign{Signer: identity[0]}

	sessions := make(chan *api.GetSessionResponse, 1)
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "echo READY; sleep 30"},
		[]string{"cmd", "/c", "echo READY & ping -n 30 127.0.0.1 > NUL"}),
		withSigners([]ssh.Signer{once}),
		withSessionCreatedCallback(func(_ context.Context, s *api.GetSessionResponse) error {
			sessions <- s
			return nil
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	// The attach door, pinned from the record the daemon published.
	sock := run.awaitAttachSocket(t)
	awaitMarker(t, run.attachViewer(t, ctx, sock), "READY")
	rec := run.record(t)
	require.Len(t, rec.HostKeys, 1)
	identityLine := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(once.PublicKey())), "\n")
	require.NotEqual(t, identityLine, rec.HostKeys[0], "the record carries the session key, not the identity")

	session := awaitSession(t, sessions)
	guestKey := guestKeyFile(t)
	for i := 0; i < 2; i++ {
		guest := &Client{PrivateKeys: []string{guestKey}}
		require.NoError(t, guest.Join(session, "ssh://"+run.relay.SSHAddr()), "guest %d joins", i+1)
		t.Cleanup(guest.Close)
	}

	require.EqualValues(t, 1, once.calls.Load(), "the identity signed for the tunnel and nothing else")
	cancel()
	<-done
}

// Test_Host_AllowlistedRelayChecksTheIdentityNotTheSessionKey: the relay's
// --authorized-keys is a list of identities. The session host key is never
// in it, and must never be what the relay looks at.
func Test_Host_AllowlistedRelayChecksTheIdentityNotTheSessionKey(t *testing.T) {
	identity, err := utils.CreateSigners([][]byte{[]byte(HostPrivateKeyContent)})
	require.NoError(t, err)
	allowed := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(allowed, ssh.MarshalAuthorizedKey(identity[0].PublicKey()), 0o600))

	command := shellCommand(t,
		[]string{"sh", "-c", "sleep 30"},
		[]string{"cmd", "/c", "ping -n 30 127.0.0.1 > NUL"})

	t.Run("a listed identity registers and serves a guest", func(t *testing.T) {
		sessions := make(chan *api.GetSessionResponse, 1)
		run := newOutcomeRun(t, command,
			withRelayAuthorizedKeys(allowed),
			withSigners(identity),
			withSessionCreatedCallback(func(_ context.Context, s *api.GetSessionResponse) error {
				sessions <- s
				return nil
			}),
		)
		ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- run.host.Run(ctx) }()

		session := awaitSession(t, sessions)
		guest := &Client{PrivateKeys: []string{guestKeyFile(t)}}
		require.NoError(t, guest.Join(session, "ssh://"+run.relay.SSHAddr()))
		t.Cleanup(guest.Close)
		cancel()
		<-done
	})

	t.Run("an unlisted identity is refused", func(t *testing.T) {
		other, err := utils.CreateSigners([][]byte{[]byte(ClientPrivateKeyContent)})
		require.NoError(t, err)
		run := newOutcomeRun(t, command, withRelayAuthorizedKeys(allowed), withSigners(other))
		ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
		defer cancel()
		err = run.host.Run(ctx)
		require.Error(t, err)
		// An allowlist that does not name this identity is the commonest way a
		// host is turned away, and until #562 it was the one the code did not
		// recognise: the match covered only the no-key-offered shape, so this
		// fell through to a raw "ssh dial error: ssh: handshake failed, ...
		// attempted methods [none publickey]" — the string the issue quotes.
		//
		// Asserted on the text rather than on PermissionDeniedError, which
		// host/internal is not allowed to export this far. The whole sentence
		// is what makes it equivalent: only that type produces it, and it says
		// the identity was offered and refused rather than never offered,
		// which a host that failed to reach the relay would also satisfy.
		require.ErrorContains(t, err, "Permission denied (publickey); the 1 identity offered was refused.")
		require.NotContains(t, err.Error(), "ssh dial error", "a denial is classified, not wrapped as a generic dial failure")
	})
}
