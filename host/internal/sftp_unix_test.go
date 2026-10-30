//go:build !windows

package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/owenthereal/upterm/upterm"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// denyingChecker refuses every SFTP operation and remembers the client the
// last prompt would have named.
type denyingChecker struct {
	mu      sync.Mutex
	asked   bool
	lastFor consent.ClientInfo
}

func (c *denyingChecker) CheckPermission(_ context.Context, op consent.Operation, client consent.ClientInfo, paths ...string) (consent.Decision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked, c.lastFor = true, client
	return consent.Deny, nil
}

func (c *denyingChecker) ClearConnection(string) {}

// The prompt names the key the guest authenticated with: the fingerprint the
// host's client list shows. The relay reaches the host with a certificate it
// signs with its own key and carries the guest's key inside it, so the key
// the host's SSH server sees fingerprints as neither.
func TestSFTPConsentGuestKey(t *testing.T) {
	checker := &denyingChecker{}
	h := startHost(t, &Server{Command: readsALine("READY", 0), PermissionChecker: checker})

	guestPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	guestKey, err := ssh.NewPublicKey(guestPublic)
	require.NoError(t, err)
	cert := &server.UserCertSigner{
		User: "guest", SessionID: t.Name(),
		AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(guestKey)},
	}
	// Signed by the harness's relay, the authority this host trusts: a
	// certificate from anyone else is refused at the guest door, so the prompt
	// would never be reached.
	h.guestSigner, err = cert.SignCert(h.relaySigner)
	require.NoError(t, err)

	sftpClient, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sftpClient.Close() })

	// The host answers the open only once the checker has decided, so the
	// prompt has been recorded by the time Open returns.
	_, err = sftpClient.Open(filepath.Join(t.TempDir(), "notes.txt"))
	require.Error(t, err)

	checker.mu.Lock()
	defer checker.mu.Unlock()
	require.True(t, checker.asked, "the download was not put to the checker")
	require.Equal(t, utils.FingerprintSHA256(guestKey), checker.lastFor.Fingerprint)
}

func TestSFTPConsentSSH(t *testing.T) {
	t.Run("terminal connection grant survives sftp channel close", func(t *testing.T) {
		h := approvalHost(t)
		primary := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, primary.id)
		guest := h.guestClient(t)
		path := filepath.Join(t.TempDir(), "notes")
		require.NoError(t, os.WriteFile(path, []byte("content"), 0600))
		first, err := sftp.NewClient(guest)
		require.NoError(t, err)
		finished := make(chan error, 1)
		go func() {
			f, e := first.Open(path)
			if e == nil {
				e = f.Close()
			}
			finished <- e
		}()
		var requestID string
		select {
		case state := <-primary.states:
			require.NotNil(t, state.Current)
			require.Equal(t, "sftp", state.Current.Capability)
			require.Equal(t, [][]byte{[]byte(path)}, state.Current.Subjects)
			requestID = state.Current.ID
		case <-time.After(harnessTimeout):
			t.Fatal("no sftp approval")
		}
		require.True(t, approvalAnswer(t, primary, requestID, "connection"))
		require.NoError(t, <-finished)
		require.NoError(t, first.Close())
		approvalState(t, primary, "", 0)
		second, err := sftp.NewClient(guest)
		require.NoError(t, err)
		defer second.Close()
		f, err := second.Open(path)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		require.Empty(t, primary.states, "one prompt across two SFTP channels on one transport")
	})
	t.Run("no primary and disabled escapes deny without touching files", func(t *testing.T) {
		for _, attach := range []bool{false, true} {
			t.Run(fmt.Sprint(attach), func(t *testing.T) {
				h := approvalHost(t)
				if attach {
					p := approvalConnect(t, h, false, true, true, true)
					approvalPrimary(t, h, p.id)
				}
				guest := h.guestClient(t)
				c, err := sftp.NewClient(guest)
				require.NoError(t, err)
				defer c.Close()
				path := filepath.Join(t.TempDir(), "new")
				err = c.Mkdir(path)
				// pkg/sftp normalizes status 3 to os.ErrPermission, discarding its text.
				require.ErrorIs(t, err, os.ErrPermission)
				code, message := sftpMkdirStatus(t, guest, path)
				require.Equal(t, uint32(sftp.ErrSSHFxPermissionDenied), code)
				require.Contains(t, message, "primary host terminal")
				require.Contains(t, message, "--accept")
				_, err = os.Stat(path)
				require.True(t, os.IsNotExist(err))
			})
		}
	})
	t.Run("accept skips terminal prompts", func(t *testing.T) {
		h := startHost(t, &Server{Command: readsALine("READY", 0), TerminalConsent: true, SFTPAutoAccept: true})
		p := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, p.id)
		c, err := sftp.NewClient(h.guestClient(t))
		require.NoError(t, err)
		defer c.Close()
		require.NoError(t, c.Mkdir(filepath.Join(t.TempDir(), "new")))
		require.Empty(t, p.states)
	})
	t.Run("relative paths retain home directory base", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		require.NoError(t, os.WriteFile(filepath.Join(home, "notes"), []byte("from home"), 0600))
		h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPAutoAccept: true})
		c, err := sftp.NewClient(h.guestClient(t))
		require.NoError(t, err)
		defer c.Close()
		f, err := c.Open("notes")
		require.NoError(t, err)
		defer f.Close()
		content, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, "from home", string(content))
	})

	t.Run("disabled precedes accept and checker", func(t *testing.T) {
		var called atomic.Int32
		h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPDisabled: true, SFTPAutoAccept: true, PermissionChecker: sftpConsentChecker{check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			called.Add(1)
			return consent.AllowGuest, nil
		}}})
		_, err := sftp.NewClient(h.guestClient(t))
		require.Error(t, err)
		require.Zero(t, called.Load())
	})
	t.Run("connection cleared once including transports without sftp", func(t *testing.T) {
		cleared := make(chan string, 8)
		h := startHost(t, &Server{Command: readsALine("READY", 0), PermissionChecker: sftpConsentChecker{clear: func(id string) { cleared <- id }, check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			return consent.AllowConnection, nil
		}}})
		for _, sftpChannels := range []int{0, 2} {
			guest := h.guestClient(t)
			for i := 0; i < sftpChannels; i++ {
				c, err := sftp.NewClient(guest)
				require.NoError(t, err)
				require.NoError(t, c.Close())
			}
			require.Empty(t, cleared, "channel close must not clear connection")
			id := hex.EncodeToString(guest.SessionID())
			require.NoError(t, guest.Close())
			select {
			case got := <-cleared:
				require.Equal(t, id, got)
			case <-time.After(harnessTimeout):
				t.Fatal("connection not cleared")
			}
		}
		require.Empty(t, cleared, "each guest connection cleared exactly once")
	})
	t.Run("channel close cancels an sftp worker before library cleanup", func(t *testing.T) {
		entered := make(chan struct{}, 1)
		cancelled := make(chan struct{}, 1)
		h := startHost(t, &Server{Command: readsALine("READY", 0), PermissionChecker: sftpConsentChecker{check: func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
			entered <- struct{}{}
			<-ctx.Done()
			cancelled <- struct{}{}
			return consent.AllowGuest, nil
		}}})
		guest := h.guestClient(t)
		session, err := guest.NewSession()
		require.NoError(t, err)
		input, err := session.StdinPipe()
		require.NoError(t, err)
		output, err := session.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, session.RequestSubsystem("sftp"))
		c, err := sftp.NewClientPipe(output, input)
		require.NoError(t, err)
		defer c.Close()
		path := filepath.Join(t.TempDir(), "new")
		finished := make(chan error, 1)
		go func() { finished <- c.Mkdir(path) }()
		select {
		case <-entered:
		case <-time.After(harnessTimeout):
			t.Fatal("worker not pending")
		}
		require.NoError(t, session.Close())
		select {
		case <-cancelled:
		case <-time.After(harnessTimeout):
			t.Fatal("channel CLOSE did not cancel sftp worker")
		}
		select {
		case <-finished:
		case <-time.After(harnessTimeout):
			t.Fatal("sftp request stuck")
		}
		_, err = os.Stat(path)
		require.True(t, os.IsNotExist(err))
		probe, err := guest.NewSession()
		require.NoError(t, err)
		require.NoError(t, probe.Close())
	})
	t.Run("conflicting embedding configuration fails before startup", func(t *testing.T) {
		s := &Server{TerminalConsent: true, PermissionChecker: &denyingChecker{}}
		err := s.ServeWithContext(t.Context(), nil, nil)
		require.ErrorContains(t, err, "mutually exclusive")
	})
}

func TestSFTPConsentQueuedBehindReview(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clients := &hostClients{primary: &hostClient{id: "primary"}}
		b := newApprovalBroker(clients, discardLogger())
		owner := &approvalTransport{ctx: &approvalTestContext{baseContext: t.Context(), id: "primary"}, registered: true, session: true, eligible: true, wake: make(chan struct{}, 1), done: make(chan struct{})}
		b.transports[owner] = struct{}{}
		m := consent.NewManager(b, discardLogger())
		defer m.Close()
		first := make(chan error, 1)
		go func() {
			_, err := m.CheckPermission(t.Context(), consent.OpExec, consent.ClientInfo{Fingerprint: "other", ConnectionID: "other"}, "command")
			first <- err
		}()
		synctest.Wait()
		require.Len(t, b.pending, 1)
		time.Sleep(10 * time.Second)
		arrived := time.Now()
		s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: m, clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "sftp"}}
		second := make(chan error, 1)
		go func() { second <- s.checkPermission(t.Context(), arrived, consent.OpDownload, "file") }()
		synctest.Wait()
		require.Len(t, b.pending, 2)
		require.Equal(t, "command", string(b.pending[0].request.Subjects[0]))
		require.Equal(t, arrived.Add(consent.PermissionTimeout).UnixMilli(), b.pending[1].request.DeadlineUnixMilli)
		time.Sleep(50 * time.Second)
		synctest.Wait()
		require.Error(t, <-first)
		state, err := upterm.DecodeApprovalState(owner.snapshot)
		require.NoError(t, err)
		require.Equal(t, uint32(1), state.Pending)
		require.Equal(t, "file", string(state.Current.Subjects[0]))
		require.Equal(t, arrived.Add(consent.PermissionTimeout).UnixMilli(), state.Current.DeadlineUnixMilli)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		require.Error(t, <-second)
		require.Empty(t, b.pending)
	})
}

// sftpMkdirStatus checks the real protocol reply before pkg/sftp's client
// normalizes permission-denied text away. This session owns its only reader.
func sftpMkdirStatus(t *testing.T, client *ssh.Client, path string) (uint32, string) {
	t.Helper()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	input, err := session.StdinPipe()
	require.NoError(t, err)
	output, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.RequestSubsystem("sftp"))
	write := func(payload []byte) {
		t.Helper()
		_, err := input.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...))
		require.NoError(t, err)
	}
	read := func() []byte {
		t.Helper()
		header := make([]byte, 4)
		_, err := io.ReadFull(output, header)
		require.NoError(t, err)
		size := binary.BigEndian.Uint32(header)
		require.Greater(t, size, uint32(0))
		require.Less(t, size, uint32(4096))
		payload := make([]byte, size)
		_, err = io.ReadFull(output, payload)
		require.NoError(t, err)
		return payload
	}
	write([]byte{1, 0, 0, 0, 3}) // SSH_FXP_INIT version 3.
	require.Equal(t, byte(2), read()[0])
	write(append([]byte{14}, ssh.Marshal(struct {
		ID    uint32
		Path  string
		Flags uint32
	}{1, path, 0})...)) // SSH_FXP_MKDIR.
	packet := read()
	require.Equal(t, byte(101), packet[0])
	var status struct {
		ID, Code          uint32
		Message, Language string
	}
	require.NoError(t, ssh.Unmarshal(packet[1:], &status))
	require.Equal(t, uint32(1), status.ID)
	return status.Code, status.Message
}
