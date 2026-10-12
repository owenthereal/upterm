//go:build !windows

package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/join"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// listenAgent listens on a fresh unix socket for the test's lifetime, serves
// each connection it accepts with serve, and returns the socket's path.
func listenAgent(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	// Keep the socket path below macOS's Unix socket path limit.
	dir, err := os.MkdirTemp("", "agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ta := &testAgent{socket: filepath.Join(dir, "sock"), ending: make(chan struct{}, 1)}
	t.Cleanup(ta.stop)
	ta.listen(t, serve)
	return ta.socket
}

// signerAgent is an agent that holds signers, for agent.ServeAgent: x/crypto's
// keyring holds only private keys, and these tests have signers.
type signerAgent struct {
	agent.Agent // an empty keyring, for the calls these tests never make
	signers     []ssh.Signer
	hold        <-chan struct{} // nil, or what each signature waits on
}

func (a *signerAgent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, len(a.signers))
	for _, s := range a.signers {
		pub := s.PublicKey()
		keys = append(keys, &agent.Key{Format: pub.Type(), Blob: pub.Marshal()})
	}
	return keys, nil
}

func (a *signerAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if a.hold != nil {
		<-a.hold
	}
	for _, s := range a.signers {
		if bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			return s.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("no such key")
}

// serveAgent is an agent holding signers, on a unix socket.
func serveAgent(t *testing.T, signers ...ssh.Signer) string {
	t.Helper()
	a := &signerAgent{Agent: agent.NewKeyring(), signers: signers}
	return listenAgent(t, func(conn net.Conn) { _ = agent.ServeAgent(a, conn) })
}

// silentAgent accepts connections and never answers them.
func silentAgent(t *testing.T) string {
	t.Helper()
	socket, _ := silentAgentAccepting(t)
	return socket
}

// silentAgentAccepting is silentAgent, and a channel that receives as it
// accepts each connection.
func silentAgentAccepting(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	accepted := make(chan struct{}, 16)
	socket := listenAgent(t, func(conn net.Conn) {
		select {
		case accepted <- struct{}{}:
		default:
		}
		_, _ = io.Copy(io.Discard, conn)
	})
	return socket, accepted
}

// agentThatHangsOnSign lists s, and never answers a signature request: an
// agent waiting on an approval prompt.
func agentThatHangsOnSign(t *testing.T, s ssh.Signer) string {
	t.Helper()
	hold := make(chan struct{})
	a := &signerAgent{Agent: agent.NewKeyring(), signers: []ssh.Signer{s}, hold: hold}
	socket := listenAgent(t, func(conn net.Conn) { _ = agent.ServeAgent(a, conn) })
	t.Cleanup(func() { close(hold) }) // before the listener's stop, which waits on the handlers
	return socket
}

func TestAgentKeysComeBeforeFilesAndNoKeyIsOfferedTwice(t *testing.T) {
	a, b := newKeyFile(t), newKeyFile(t)
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		AgentSocket: serveAgent(t, a.signer), Files: []string{b.path, a.path}, Passphrase: noPrompt(t)})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	defer release()
	require.Equal(t, []string{fp(a), fp(b)}, fingerprints(signers))
	require.Equal(t, join.KeySource{Agent: 1, Files: 1}, g.Source())
}

func TestAnEncryptedKeyTheAgentHoldsNeedsNoPassphrase(t *testing.T) {
	enc := newEncryptedKeyFile(t, "secret")
	for _, only := range []bool{false, true} { // the defaults, and -i
		g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
			IdentitiesOnly: only, Files: []string{enc.path},
			AgentSocket: serveAgent(t, enc.signer), Passphrase: noPrompt(t)})
		require.NoError(t, err)
		signers, release, err := g.Signers(context.Background())
		require.NoError(t, err)
		release()
		require.Equal(t, []string{fp(enc)}, fingerprints(signers))
	}
}

func TestASelectorNamesOnlyThatAgentKey(t *testing.T) { // -i key.pub
	a, b := newKeyFile(t), newKeyFile(t)
	sel := writeFile(t, "a.pub", string(ssh.MarshalAuthorizedKey(a.signer.PublicKey())))
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		IdentitiesOnly: true, Files: []string{sel}, AgentSocket: serveAgent(t, a.signer, b.signer)})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	release()
	require.Equal(t, []string{fp(a)}, fingerprints(signers)) // b is never offered
}

func TestAnExplicitEmptyListIsAnError(t *testing.T) {
	_, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{IdentitiesOnly: true, AgentSocket: serveAgent(t, newKeyFile(t).signer)})
	require.ErrorContains(t, err, "private-key was supplied but names no files")
}

func TestAMissingAgentSocketIsNoAgent(t *testing.T) { // as if SSH_AUTH_SOCK were unset
	dir, err := os.MkdirTemp("", "agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		AgentSocket: filepath.Join(dir, "sock"),
		OnAgentSkip: func(err error) { t.Errorf("the agent was skipped: %v", err) }})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	release()
	require.Len(t, signers, 1)
	require.True(t, g.Source().Generated)
}

// launchd sets SSH_AUTH_SOCK on macOS whether or not the agent holds a key,
// so an empty agent is the default there. With no key file either, the
// guest has no key at all, and gets a generated one, as with no agent.
func TestAnEmptyAgentWithNoFilesGivesAGeneratedKey(t *testing.T) {
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		AgentSocket: serveAgent(t),
		OnAgentSkip: func(err error) { t.Errorf("the agent was skipped: %v", err) }})
	require.NoError(t, err)
	signers, release, err := g.Signers(context.Background())
	require.NoError(t, err)
	release()
	require.Len(t, signers, 1)
	require.Equal(t, join.KeySource{Generated: true}, g.Source())
}

func TestASilentAgentCostsOnlyItsOwnBudget(t *testing.T) { // an agent that accepts and never answers
	good := newKeyFile(t)
	var skippedAgent error
	start := time.Now()
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{
		AgentSocket: silentAgent(t), AgentTimeout: 100 * time.Millisecond, Files: []string{good.path},
		OnAgentSkip: func(err error) { skippedAgent = err }})
	require.NoError(t, err) // the agent is skipped; the file key is offered
	// Slack for -race on CI; without its budget, listing a silent agent never ends.
	require.Less(t, time.Since(start), 100*time.Millisecond+250*time.Millisecond)
	require.Error(t, skippedAgent)
	signers, release, err := g.Signers(context.Background()) // the attempt's budget is untouched
	require.NoError(t, err)
	release()
	require.Equal(t, []string{fp(good)}, fingerprints(signers))
}

func TestASilentAgentWithNoFilesIsAnIdentityError(t *testing.T) {
	_, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{AgentSocket: silentAgent(t), AgentTimeout: 100 * time.Millisecond})
	var ie *join.IdentityError
	require.ErrorAs(t, err, &ie)
	require.True(t, ie.List)
}

func TestListingTheAgentEndsWithItsContext(t *testing.T) { // Ctrl-C (SIGINT) during preparation
	socket, accepted := silentAgentAccepting(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := NewGuestIdentity(ctx, GuestIdentityOptions{AgentSocket: socket, AgentTimeout: time.Hour})
		done <- err
	}()
	// Cancel once the listing is under way. A ctx cancelled before the dial
	// ends it in the dial, and leaves the listing's own close untested.
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent was never dialled")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	// Slack for -race on CI; a listing that ignores cancellation never ends.
	case <-time.After(250 * time.Millisecond):
		t.Fatal("listing the agent ignored cancellation")
	}
}

func TestSigningOnARejoinIsReleasedWithTheAttempt(t *testing.T) {
	key := newKeyFile(t)
	g, err := NewGuestIdentity(context.Background(), GuestIdentityOptions{AgentSocket: agentThatHangsOnSign(t, key.signer)})
	require.NoError(t, err) // listing works
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	signers, release, err := g.Signers(ctx)
	require.NoError(t, err)
	stop := context.AfterFunc(ctx, release) // as join.Run arms it
	defer stop()
	start := time.Now()
	_, err = signers[0].Sign(rand.Reader, []byte("data"))
	require.Error(t, err)
	// Slack for -race on CI; a signature the release doesn't end never returns.
	require.Less(t, time.Since(start), 100*time.Millisecond+250*time.Millisecond)
}
