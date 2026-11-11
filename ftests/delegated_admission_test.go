package ftests

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// claimPrefix starts every user the runs' test authority claims.
const claimPrefix = "claim-"

// guestOutput is a bytes.Buffer a guest's session writes while a test reads
// it.
type guestOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *guestOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *guestOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// target is the run's registration, as its authority allows guests to it,
// with the capabilities the run was placed with.
func (r *delegatedRun) target(t *testing.T) server.Target {
	t.Helper()
	var reg *server.DelegatedRegistration
	for _, c := range r.authority.Calls() {
		if c.Method == "Register" {
			reg = &c.Registration
		}
	}
	require.NotNil(t, reg, "the run never registered")
	return server.Target{
		Registration: server.RegistrationRef{Authority: server.AuthorityDelegated, AccountID: testauthority.AccountID, SessionID: delegatedSessionID, Generation: reg.Generation, RoutingID: reg.RoutingID,
			RunPublicKeys: [][]byte{reg.RunPublicKey.Marshal()}, RegistrationID: reg.RegistrationID, HomeNode: reg.HomeNode, HomeNodeID: reg.HomeNodeID, HomeBootID: reg.HomeBootID},
		AccountID:    testauthority.AccountID,
		SessionID:    delegatedSessionID,
		RoutingID:    reg.RoutingID,
		RunPublicKey: reg.RunPublicKey,
		Capabilities: r.broker.Runs()[0].Capabilities,
	}
}

// printing is a command, in this platform's shell, that prints line every
// 100 ms until it is stopped.
func printing(line string) []string {
	if runtime.GOOS == "windows" {
		return append(getTestShell(), "-Command", "while ($true) { Write-Output '"+line+"'; Start-Sleep -Milliseconds 100 }")
	}
	return []string{"sh", "-c", "while :; do echo " + line + "; sleep 0.1; done"}
}

// allow is an allow of the run's guests to target, for the next while.
func allow(target server.Target) server.Admission {
	return server.Admission{Verdict: server.VerdictAllow, Sequence: 1, AllowUntil: time.Now().Add(45 * time.Second), Target: target}
}

// admitted is every guest the authority was asked about, in order.
func (r *delegatedRun) admitted() []testauthority.Call {
	var calls []testauthority.Call
	for _, c := range r.authority.Calls() {
		if c.Method == "Admit" {
			calls = append(calls, c)
		}
	}
	return calls
}

// dialGuestAs connects to the run's relay as user, with the client key.
func (r *delegatedRun) dialGuestAs(t *testing.T, user string) (*ssh.Client, error) {
	t.Helper()
	signers, err := utils.CreateSigners([][]byte{[]byte(ClientPrivateKeyContent)})
	require.NoError(t, err)
	client, err := ssh.Dial("tcp", r.relay.SSHAddr(), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// A delegated host's guests come only as the relay's authority decides.
// Refused, a guest gets nowhere. To be shown a message, it is shown that,
// exits 1 and never reaches the host. Allowed, it joins the host's session
// over the relay with the key it proved, until the authority closes it,
// which ends its session, its connection and its transport and leaves the
// host and its command running, taking guests.
func TestDelegatedGuestAdmission(t *testing.T) {
	r := newDelegatedRun(t, printing("DELEGATED-GUEST-OUTPUT"))
	r.authority.ClaimPrefix(claimPrefix)
	r.start(t)
	r.awaitReady(t)
	r.requireStarted(t)
	target := r.target(t)
	clientKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	user := claimPrefix + "work"

	t.Run("refused", func(t *testing.T) {
		_, err := r.dialGuestAs(t, user)
		require.Error(t, err)
		require.NotEmpty(t, r.admitted(), "the authority was not asked")
	})

	t.Run("shown a message", func(t *testing.T) {
		const message = "the session is not running (last seen unknown).\n"
		r.authority.ScriptAdmit(server.Admission{Verdict: server.VerdictMessage, Message: []byte(message)})
		guest, err := r.dialGuestAs(t, user)
		require.NoError(t, err)
		sess, err := guest.NewSession()
		require.NoError(t, err)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		require.NoError(t, sess.Shell())
		var exit *ssh.ExitError
		require.ErrorAs(t, sess.Wait(), &exit)
		require.Equal(t, 1, exit.ExitStatus())
		require.Equal(t, message, stdout.String())
		require.NotContains(t, stdout.String(), "DELEGATED-GUEST-OUTPUT")
	})

	t.Run("admitted, then closed", func(t *testing.T) {
		before := len(r.admitted())
		r.authority.ScriptAdmit(allow(target))
		guest, err := r.dialGuestAs(t, user)
		require.NoError(t, err)
		calls := r.admitted()
		require.Len(t, calls, before+1)
		call := calls[before]
		require.Equal(t, user, call.User, "the authority was not told the user the guest typed")
		require.Nil(t, call.Home, "a claimed user's request named a home")
		g := call.Guest
		require.Equal(t, clientKey.Marshal(), g.Key.Marshal(), "the authority was not given the key the guest proved")
		require.NotNil(t, g.Home(), "an allowed guest wasn't bound to its target's home")
		require.Equal(t, target.RoutingID, g.Home().Ref().RoutingID)

		sess, err := guest.NewSession()
		require.NoError(t, err)
		stdin, err := sess.StdinPipe()
		require.NoError(t, err)
		defer func() { _ = stdin.Close() }()
		out := &guestOutput{}
		sess.Stdout = out
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		require.NoError(t, sess.Shell())
		require.Eventually(t, func() bool { return strings.Contains(out.String(), "DELEGATED-GUEST-OUTPUT") }, outcomeTimeout, 10*time.Millisecond,
			"the admitted guest never saw the hosted command's output")

		rawEnded := make(chan error, 1)
		go func() { rawEnded <- guest.Wait() }()
		select {
		case err := <-rawEnded:
			t.Fatalf("the guest's transport ended before the authority closed it: %v", err)
		default:
		}
		g.Close()
		ended := make(chan error, 1)
		go func() { ended <- sess.Wait() }()
		select {
		case err := <-ended:
			t.Logf("the guest's session completed after the authority closed it: %v", err)
		case <-time.After(outcomeTimeout):
			t.Fatal("the guest's session outlived the authority closing it")
		}
		select {
		case <-g.Done():
		case <-time.After(outcomeTimeout):
			t.Fatal("the guest's connection outlived the authority closing it")
		}
		select {
		case err := <-rawEnded:
			t.Logf("the guest's transport completed after the authority closed it: %v", err)
		case <-time.After(outcomeTimeout):
			t.Fatal("the raw SSH transport outlived the authority closing it")
		}

		// The host and its command go on, taking guests.
		select {
		case err := <-r.done:
			t.Fatalf("closing a guest ended the host: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		require.Equal(t, sessiondir.StatusReady, r.record(t).Status)
		r.authority.ScriptAdmit(allow(target))
		_, err = r.dialGuestAs(t, user)
		require.NoError(t, err, "the host stopped taking guests")
	})
}
