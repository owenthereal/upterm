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
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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

// An SFTP session its client finishes ends with an exit status, as OpenSSH's
// sftp-server's does. scp runs ssh -s sftp and takes ssh's exit status for its
// own, so a channel that closes without one ("Exit status -1") fails a
// transfer that has already succeeded.
func TestSFTPSessionEndsWithAnExitStatus(t *testing.T) {
	testSFTPExitStatus(t, false, 0)
}

// An open transfer when the client sends EOF is incomplete, even if no
// packet is truncated. Serve closes its handle and reports unexpected EOF;
// the guest must receive failure rather than a successful exit status.
func TestSFTPIncompleteSessionEndsWithFailure(t *testing.T) {
	testSFTPExitStatus(t, true, 1)
}

func testSFTPExitStatus(t *testing.T, leaveFileOpen bool, wantStatus uint32) {
	t.Helper()
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPAutoAccept: leaveFileOpen})
	// A raw channel rather than an ssh.Session, whose Wait refuses a session
	// started by a subsystem request: the test reads what the host sends.
	channel, requests, err := h.guestClient(t).OpenChannel("session", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = channel.Close() })
	ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	require.NoError(t, err)
	require.True(t, ok, "the host refused the sftp subsystem")
	client, err := sftp.NewClientPipe(channel, eofOnClose{channel})
	require.NoError(t, err, "the sftp handshake failed")
	if leaveFileOpen {
		path := filepath.Join(t.TempDir(), "incomplete.txt")
		require.NoError(t, os.WriteFile(path, []byte("unfinished transfer"), 0600))
		// Deliberately leave the protocol handle open. The server owns its
		// cleanup when EOF interrupts the exchange.
		_, err := client.Open(path)
		require.NoError(t, err)
	}
	// The client is done: it sends EOF, and the channel stays open for the
	// host to say how the session ended before it closes it.
	require.NoError(t, client.Close())

	statuses := make(chan []uint32, 1)
	go func() {
		var got []uint32
		for req := range requests { // until the host closes the channel
			if req.Type == "exit-status" {
				var status struct{ Status uint32 }
				if ssh.Unmarshal(req.Payload, &status) == nil {
					got = append(got, status.Status)
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
		statuses <- got
	}()
	select {
	case got := <-statuses:
		require.Equal(t, []uint32{wantStatus}, got, "the sftp session must send exactly one exit status before channel close")
	case <-time.After(harnessTimeout):
		t.Fatal("the host did not close the sftp session's channel after its client finished")
	}
}

// eofOnClose ends only the writing half of a channel when closed, as a client
// that has finished sending does.
type eofOnClose struct{ ssh.Channel }

func (c eofOnClose) Close() error { return c.CloseWrite() }

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
		defer func() { _ = second.Close() }()
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
				defer func() { _ = c.Close() }()
				path := filepath.Join(t.TempDir(), "new")
				err = c.Mkdir(path)
				// pkg/sftp normalizes status 3 to os.ErrPermission, discarding its text.
				require.ErrorIs(t, err, os.ErrPermission)
				code, message := sftpMkdirStatus(t, guest, path)
				require.Equal(t, uint32(sftp.ErrSSHFxPermissionDenied), code)
				require.Equal(t, "permission denied: SFTP needs approval in the primary host terminal; the host can attach with approval escapes enabled or use --allow-sftp", message)
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
		defer func() { _ = c.Close() }()
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
		defer func() { _ = c.Close() }()
		f, err := c.Open("notes")
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
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
		defer func() { _ = c.Close() }()
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
		case err := <-finished:
			require.Error(t, err, "channel close must fail the pending mkdir")
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
		b := newApprovalBroker(clients, nil, false, discardLogger())
		owner := &approvalTransport{ctx: &approvalTestContext{baseContext: t.Context(), id: "primary"}, registered: true, session: true, eligible: true, wake: make(chan struct{}, 1), done: make(chan struct{})}
		b.transports[owner] = struct{}{}
		type queuedRequest struct {
			subject  string
			deadline int64
		}
		pending := func() []queuedRequest {
			b.mu.Lock()
			defer b.mu.Unlock()
			requests := make([]queuedRequest, len(b.pending))
			for i, p := range b.pending {
				requests[i] = queuedRequest{string(p.request.Subjects[0]), p.request.DeadlineUnixMilli}
			}
			return requests
		}
		m := consent.NewManager(b, discardLogger())
		defer m.Close()
		first := make(chan error, 1)
		go func() {
			_, err := m.CheckPermission(t.Context(), consent.OpExec, consent.ClientInfo{Fingerprint: "other", ConnectionID: "other"}, "command")
			first <- err
		}()
		synctest.Wait()
		require.Len(t, pending(), 1)
		time.Sleep(10 * time.Second)
		arrived := time.Now()
		s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: m, clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "sftp"}}
		second := make(chan error, 1)
		go func() {
			second <- s.checkPermission(t.Context(), arrived, nextSFTPRequestID(), consent.OpDownload, "file")
		}()
		synctest.Wait()
		queued := pending()
		require.Len(t, queued, 2)
		require.Equal(t, "command", queued[0].subject)
		require.Equal(t, arrived.Add(consent.PermissionTimeout).UnixMilli(), queued[1].deadline)
		time.Sleep(50 * time.Second)
		synctest.Wait()
		require.Error(t, <-first)
		b.mu.Lock()
		snapshot := append([]byte(nil), owner.snapshot...)
		b.mu.Unlock()
		state, err := upterm.DecodeApprovalState(snapshot)
		require.NoError(t, err)
		require.Equal(t, uint32(1), state.Pending)
		require.Equal(t, "file", string(state.Current.Subjects[0]))
		require.Equal(t, arrived.Add(consent.PermissionTimeout).UnixMilli(), state.Current.DeadlineUnixMilli)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		require.Error(t, <-second)
		require.Empty(t, pending())
	})
}

// sftpPipeChannel carries an SFTP channel over pipes to a client in the test;
// fakeGuestSession is the rest of its session.
type sftpPipeChannel struct {
	fakeGuestSession
	in  *io.PipeReader
	out *io.PipeWriter
}

func (c *sftpPipeChannel) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *sftpPipeChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *sftpPipeChannel) Close() error                { _ = c.in.Close(); return c.out.Close() }

// A request still waiting for approval ends at once with the session it
// arrived in, however that ends: its channel closes, the host stops, or the
// hosted command exits on its own, which ends the session's context and never
// the stop's. Each is a cancellation, and audited as one.
func TestSFTPConsentEndedBySessionEnd(t *testing.T) {
	for _, end := range []string{"channel", "stop", "command exit"} {
		t.Run(end, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stop, cancelStop := context.WithCancelCause(t.Context())
				defer cancelStop(nil)
				// The session's context as the server makes it: one a stop
				// doesn't end, cancelled once its sessions are released.
				sessCtx, endSession := context.WithCancel(sessionContext(stop))
				defer endSession()
				asked, ended := make(chan struct{}), make(chan struct{})
				output := &recordingWriter{}
				h := &sessionHandler{kind: kindGuest, ctx: sessCtx, stopCtx: stop, logger: slog.New(slog.NewJSONHandler(output, nil)), permissionChecker: sftpConsentChecker{check: func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
					close(asked)
					<-ctx.Done()
					close(ended)
					return consent.Deny, consent.ErrCanceled
				}}}
				serverIn, clientOut := io.Pipe()
				clientIn, serverOut := io.Pipe()
				channel := &sftpPipeChannel{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "sftp"}}, in: serverIn, out: serverOut}
				closed := make(chan struct{})
				served := make(chan struct{})
				go func() {
					defer close(served)
					// This fixture calls the handler directly, so it owns the
					// channel close the SSH subsystem wrapper normally performs.
					defer func() { _ = channel.Close() }()
					h.HandleSFTP(&rawSession{Session: channel, channel: channel, closed: closed})
				}()
				client, err := sftp.NewClientPipe(clientIn, clientOut)
				require.NoError(t, err)
				path := filepath.Join(t.TempDir(), "new")
				result := make(chan error, 1)
				go func() { result <- client.Mkdir(path) }()
				<-asked
				switch end {
				case "channel":
					close(closed)
				case "stop":
					cancelStop(ErrSessionStopped)
				default:
					endSession()
				}
				synctest.Wait()
				select {
				case <-ended:
				default:
					// Not Fatal: the handler still has to be let finish.
					t.Error("SFTP request still waiting for approval after its session ended")
				}
				// A no-op unless the end above left the request waiting.
				cancelStop(nil)
				require.ErrorIs(t, <-result, os.ErrPermission)
				require.NoError(t, client.Close())
				<-served
				_, err = os.Stat(path)
				require.ErrorIs(t, err, os.ErrNotExist)
				records := sftpAuditRecords(t, output)
				require.Len(t, records, 1)
				requireSFTPAudit(t, records[0], "mkdir", "canceled", []string{path})
			})
		})
	}
}

// sftpMkdirStatus checks the real protocol reply before pkg/sftp's client
// normalizes permission-denied text away. This session owns its only reader.
func sftpMkdirStatus(t *testing.T, client *ssh.Client, path string) (uint32, string) {
	t.Helper()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
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

func TestSFTPAuditSSH(t *testing.T) {
	output := &recordingWriter{}
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPAutoAccept: true, Logger: slog.New(slog.NewJSONHandler(output, nil))})
	guest := h.guestClient(t)
	clients := make([]*sftp.Client, 2)
	for i := range clients {
		var err error
		clients[i], err = sftp.NewClient(guest)
		require.NoError(t, err)
		t.Cleanup(func() { _ = clients[i].Close() })
	}
	root := t.TempDir()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, c := range clients {
		go func() { <-start; results <- c.Mkdir(filepath.Join(root, fmt.Sprint(i))) }()
	}
	close(start)
	for range clients {
		require.NoError(t, <-results)
	}
	require.NoError(t, clients[0].Mkdir(filepath.Join(root, "again")))
	// Exercise read/upload handler identity wiring on these same channels too.
	downloaded, err := clients[0].Open(filepath.Join(root, "0"))
	require.NoError(t, err)
	require.NoError(t, downloaded.Close())
	uploaded, err := clients[1].Create(filepath.Join(root, "upload"))
	require.NoError(t, err)
	require.NoError(t, uploaded.Close())
	records := sftpAuditRecords(t, output)
	require.Len(t, records, 5)
	operations := map[string]int{}
	ids := make(map[string]bool)
	for _, record := range records {
		require.Equal(t, "sftp", record["capability"])
		operations[record["operation"].(string)]++
		require.Equal(t, "allowed", record["outcome"])
		require.Equal(t, strconv.QuoteToASCII(hex.EncodeToString(guest.SessionID())), record["connection_id"])
		require.Equal(t, strconv.QuoteToASCII(utils.FingerprintSHA256(h.relaySigner.PublicKey())), record["fingerprint"])
		id, ok := record["request_id"].(string)
		require.True(t, ok)
		require.NotEmpty(t, id)
		require.False(t, ids[id], "concurrent channels reused boundary ID")
		ids[id] = true
	}
	require.Equal(t, map[string]int{"mkdir": 3, "download": 1, "upload": 1}, operations)
}
