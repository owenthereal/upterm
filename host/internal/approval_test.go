//go:build !windows

package internal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type baseContext = context.Context
type approvalTestContext struct {
	gssh.Context
	baseContext
	id string
}

func (c *approvalTestContext) Value(key any) any           { return c.baseContext.Value(key) }
func (c *approvalTestContext) Deadline() (time.Time, bool) { return c.baseContext.Deadline() }
func (c *approvalTestContext) Done() <-chan struct{}       { return c.baseContext.Done() }
func (c *approvalTestContext) Err() error                  { return c.baseContext.Err() }
func (c *approvalTestContext) SessionID() string           { return c.id }

type approvalPeer struct {
	client *ssh.Client
	states chan upterm.ApprovalState
	ends   chan struct{}
	id     string
	gate   *gatedConn
}

func approvalConnect(t *testing.T, h *hostHarness, register, interactive, local, ack bool) *approvalPeer {
	p := approvalDial(t, h, local, ack)
	if register {
		approvalRegister(t, p, true)
	}
	approvalAttach(t, p, interactive)
	return p
}
func approvalRegister(t *testing.T, p *approvalPeer, want bool) {
	t.Helper()
	ok, _, err := p.client.SendRequest(upterm.ApprovalRegisterRequest, true, nil)
	require.NoError(t, err)
	require.Equal(t, want, ok)
}
func approvalDial(t *testing.T, h *hostHarness, local, ack bool) *approvalPeer {
	t.Helper()
	var raw net.Conn
	var err error
	if local {
		raw, err = net.Dial("unix", h.attachSocket)
	} else {
		raw, err = net.Dial("tcp", h.addr)
	}
	require.NoError(t, err)
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	gate := newGatedConn(raw)
	t.Cleanup(gate.resumeReads)
	cfg := &ssh.ClientConfig{User: "host", HostKeyCallback: ssh.FixedHostKey(h.hostKey), Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)}}
	if !local {
		cfg.User = "guest"
	}
	conn, chans, reqs, err := ssh.NewClientConn(gate, "approval-test", cfg)
	require.NoError(t, err)
	p := &approvalPeer{gate: gate, states: make(chan upterm.ApprovalState, 128), ends: make(chan struct{}, 1)}
	empty := make(chan *ssh.Request)
	close(empty)
	p.client = ssh.NewClient(conn, chans, empty)
	p.id = hex.EncodeToString(conn.SessionID())
	t.Cleanup(func() { _ = p.client.Close() })
	go func() {
		for req := range reqs {
			if req.Type == upterm.ApprovalStateRequest {
				state, e := upterm.DecodeApprovalState(req.Payload)
				if e == nil {
					p.states <- state
				}
				if ack {
					_ = req.Reply(e == nil, nil)
				}
			} else {
				if req.Type == upterm.SessionEndRequestType {
					p.ends <- struct{}{}
				}
				_ = req.Reply(true, nil)
			}
		}
	}()
	return p
}
func approvalAttach(t *testing.T, p *approvalPeer, interactive bool) {
	t.Helper()
	sess, e := p.client.NewSession()
	require.NoError(t, e)
	if interactive {
		require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
		require.NoError(t, sess.Setenv(upterm.AttachInteractiveEnvVar, "1"))
	}
	_, e = sess.StdinPipe()
	require.NoError(t, e)
	out, e := sess.StdoutPipe()
	require.NoError(t, e)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	require.NoError(t, sess.Shell())
}
func approvalHost(t *testing.T) *hostHarness {
	return startHost(t, &Server{TerminalConsent: true, Command: []string{"sh", "-c", "printf READY; exec sleep 60"}})
}
func approvalPrompt(id string) consent.Prompt {
	return consent.Prompt{ID: id, Operation: consent.OpExec, Client: consent.ClientInfo{Fingerprint: "SHA256:guest", ConnectionID: "guest"}, Subjects: []string{"echo hi"}, Deadline: time.Now().Add(time.Minute)}
}

type approvalResult struct {
	decision consent.Decision
	err      error
}

func approvalStart(b *approvalBroker, ctx context.Context, id string) <-chan approvalResult {
	ch := make(chan approvalResult, 1)
	go func() { d, e := b.Prompt(ctx, approvalPrompt(id)); ch <- approvalResult{d, e} }()
	return ch
}
func approvalState(t *testing.T, p *approvalPeer, id string, pending uint32) upterm.ApprovalState {
	t.Helper()
	for {
		select {
		case s := <-p.states:
			if s.Pending == pending && ((id == "" && s.Current == nil) || (s.Current != nil && s.Current.ID == id)) {
				return s
			}
		case <-time.After(harnessTimeout):
			t.Fatal("no matching approval snapshot")
			return upterm.ApprovalState{}
		}
	}
}
func approvalAnswer(t *testing.T, p *approvalPeer, id, decision string) bool {
	t.Helper()
	payload, e := json.Marshal(upterm.ApprovalAnswer{ID: id, Decision: decision})
	require.NoError(t, e)
	ok, _, e := p.client.SendRequest(upterm.ApprovalAnswerRequest, true, payload)
	require.NoError(t, e)
	return ok
}
func approvalResultRead(t *testing.T, ch <-chan approvalResult) approvalResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(harnessTimeout):
		t.Fatal("prompt stuck")
		return approvalResult{}
	}
}
func approvalPrimary(t *testing.T, h *hostHarness, id string) {
	t.Helper()
	require.Eventually(t, func() bool { return h.srv.hostClients.primaryID() == id }, harnessTimeout, time.Millisecond)
}

func TestApprovalPrimary(t *testing.T) {
	t.Run("primary only and duplicate registration", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, a.id)
		b := approvalConnect(t, h, true, true, true, true)
		ok, _, err := a.client.SendRequest(upterm.ApprovalRegisterRequest, true, nil)
		require.NoError(t, err)
		require.False(t, ok)
		extra, err := a.client.NewSession()
		require.NoError(t, err)
		require.Error(t, extra.Shell())
		_ = extra.Close()
		result := approvalStart(h.srv.approvals, context.Background(), "one")
		approvalState(t, a, "one", 1)
		require.False(t, approvalAnswer(t, b, "one", "guest"))
		require.True(t, approvalAnswer(t, a, "one", "connection"))
		require.Equal(t, consent.AllowConnection, approvalResultRead(t, result).decision)
		require.Empty(t, b.states)
	})
	t.Run("old primary does not skip to registered secondary", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, false, true, true, true)
		approvalPrimary(t, h, a.id)
		b := approvalConnect(t, h, true, true, true, true)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r := approvalResultRead(t, approvalStart(h.srv.approvals, ctx, "one"))
		require.ErrorIs(t, r.err, consent.ErrUnavailable)
		require.Empty(t, b.states)
	})
	t.Run("secondary negotiates first and promotion precedes a new prompt", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalDial(t, h, true, true)
		b := approvalDial(t, h, true, true)
		approvalRegister(t, b, true)
		approvalRegister(t, b, false)
		approvalRegister(t, a, true)
		approvalAttach(t, a, true)
		approvalPrimary(t, h, a.id)
		approvalAttach(t, b, true)
		result := approvalStart(h.srv.approvals, context.Background(), "first")
		approvalState(t, a, "first", 1)
		require.Empty(t, b.states)
		require.True(t, approvalAnswer(t, a, "first", "deny"))
		require.Equal(t, consent.Deny, approvalResultRead(t, result).decision)
		require.NoError(t, a.client.Close())
		approvalPrimary(t, h, b.id)
		result = approvalStart(h.srv.approvals, context.Background(), "after-promotion")
		approvalState(t, b, "after-promotion", 1)
		require.True(t, approvalAnswer(t, b, "after-promotion", "guest"))
		require.Equal(t, consent.AllowGuest, approvalResultRead(t, result).decision)
	})
	t.Run("old client cannot negotiate after shell", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, false, true, true, true)
		approvalPrimary(t, h, a.id)
		approvalRegister(t, a, false)
	})
	t.Run("viewer unavailable", func(t *testing.T) {
		h := approvalHost(t)
		p := approvalConnect(t, h, true, false, true, true)
		r := approvalResultRead(t, approvalStart(h.srv.approvals, context.Background(), "one"))
		require.ErrorIs(t, r.err, consent.ErrUnavailable)
		require.Empty(t, p.states)
	})
}
func TestApprovalProtocol(t *testing.T) {
	h := approvalHost(t)
	a := approvalConnect(t, h, true, true, true, true)
	approvalPrimary(t, h, a.id)
	for _, req := range []struct {
		kind    string
		payload []byte
	}{{upterm.ApprovalRegisterRequest, []byte("x")}, {upterm.ApprovalAnswerRequest, []byte(`{"ID":"a","Decision":"yes"}`)}, {"approval-register-v2@upterm", nil}} {
		ok, _, err := a.client.SendRequest(req.kind, true, req.payload)
		require.NoError(t, err)
		require.False(t, ok)
	}
	guest := approvalDial(t, h, false, true).client
	for _, kind := range []string{upterm.ApprovalRegisterRequest, upterm.ApprovalAnswerRequest} {
		ok, _, err := guest.SendRequest(kind, true, nil)
		require.NoError(t, err)
		require.False(t, ok)
	}
}
func TestApprovalQueue(t *testing.T) {
	t.Run("expiry keeps IDs dead", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// A pure broker state machine: transport I/O is deliberately absent.
			clients := &hostClients{primary: &hostClient{id: "primary"}}
			broker := newApprovalBroker(clients, nil)
			owner := &approvalTransport{ctx: &approvalTestContext{baseContext: context.Background(), id: "primary"}, registered: true, session: true, eligible: true, wake: make(chan struct{}, 1), done: make(chan struct{})}
			owner.ctx.(*approvalTestContext).baseContext = context.WithValue(context.Background(), approvalLocalKey{}, owner)
			broker.transports[owner] = struct{}{}
			prompt := approvalPrompt("expired")
			prompt.Deadline = time.Now().Add(time.Second)
			result := make(chan approvalResult, 1)
			go func() { d, e := broker.Prompt(context.Background(), prompt); result <- approvalResult{d, e} }()
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			require.ErrorIs(t, approvalResultRead(t, result).err, consent.ErrTimeout)
			ok, _ := broker.handleRequest(owner.ctx, &ssh.Request{Type: upterm.ApprovalAnswerRequest, Payload: []byte(`{"ID":"expired","Decision":"guest"}`)})
			require.False(t, ok)
			require.Empty(t, broker.pending)
		})
	})
	t.Run("bounded queue coalesces snapshots", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			clients := &hostClients{primary: &hostClient{id: "primary"}}
			broker := newApprovalBroker(clients, nil)
			owner := &approvalTransport{ctx: &approvalTestContext{baseContext: context.Background(), id: "primary"}, registered: true, session: true, eligible: true, wake: make(chan struct{}, 1), done: make(chan struct{})}
			broker.transports[owner] = struct{}{}
			ctx, cancel := context.WithCancel(context.Background())
			var results []<-chan approvalResult
			for i := 0; i < consent.MaxPending; i++ {
				results = append(results, approvalStart(broker, ctx, strconv.Itoa(i)))
				synctest.Wait()
			}
			require.ErrorIs(t, approvalResultRead(t, approvalStart(broker, ctx, "overflow")).err, consent.ErrOverloaded)
			snapshot, err := upterm.DecodeApprovalState(owner.snapshot)
			require.NoError(t, err)
			require.Equal(t, uint32(consent.MaxPending), snapshot.Pending)
			require.Equal(t, "0", snapshot.Current.ID)
			require.Len(t, owner.wake, 1)
			cancel()
			synctest.Wait()
			for _, result := range results {
				require.ErrorIs(t, approvalResultRead(t, result).err, consent.ErrCanceled)
			}
			snapshot, err = upterm.DecodeApprovalState(owner.snapshot)
			require.NoError(t, err)
			require.Zero(t, snapshot.Pending)
			require.Nil(t, snapshot.Current)
			require.Len(t, owner.wake, 1)
		})
	})
	t.Run("FIFO cancellation", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, a.id)
		ctx, cancel := context.WithCancel(context.Background())
		one := approvalStart(h.srv.approvals, ctx, "one")
		approvalState(t, a, "one", 1)
		two := approvalStart(h.srv.approvals, context.Background(), "two")
		approvalState(t, a, "one", 2)
		cancel()
		require.ErrorIs(t, approvalResultRead(t, one).err, consent.ErrCanceled)
		approvalState(t, a, "two", 1)
		require.False(t, approvalAnswer(t, a, "one", "guest"))
		require.True(t, approvalAnswer(t, a, "two", "deny"))
		require.Equal(t, consent.Deny, approvalResultRead(t, two).decision)
		approvalState(t, a, "", 0)
	})
}
func TestApprovalLoss(t *testing.T) {
	h := approvalHost(t)
	a := approvalConnect(t, h, true, true, true, true)
	approvalPrimary(t, h, a.id)
	b := approvalConnect(t, h, true, true, true, true)
	result := approvalStart(h.srv.approvals, context.Background(), "old")
	approvalState(t, a, "old", 1)
	require.NoError(t, a.client.Close())
	approvalPrimary(t, h, b.id)
	require.Equal(t, consent.Deny, approvalResultRead(t, result).decision)
	require.False(t, approvalAnswer(t, b, "old", "guest"))
	result = approvalStart(h.srv.approvals, context.Background(), "new")
	approvalState(t, b, "new", 1)
	require.True(t, approvalAnswer(t, b, "new", "guest"))
	require.Equal(t, consent.AllowGuest, approvalResultRead(t, result).decision)
}
func TestApprovalControlDoesNotBlockShutdown(t *testing.T) {
	t.Run("pending prompt permits SessionEnd", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, a.id)
		result := approvalStart(h.srv.approvals, context.Background(), "one")
		approvalState(t, a, "one", 1)
		h.stop(t)
		select {
		case <-a.ends:
		case <-time.After(harnessTimeout):
			t.Fatal("SessionEnd blocked")
		}
		require.Equal(t, consent.Deny, approvalResultRead(t, result).decision)
	})
	t.Run("stopped reader is closed", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, true, true, true, true)
		approvalPrimary(t, h, a.id)
		a.gate.pauseReads()
		result := approvalStart(h.srv.approvals, context.Background(), "unread")
		require.Equal(t, consent.Deny, approvalResultRead(t, result).decision)
		a.gate.resumeReads()
		select {
		case <-a.gate.transportClosed():
		case <-time.After(harnessTimeout):
			t.Fatal("stalled transport not closed")
		}
	})
	t.Run("missing control ACK closes owned transport", func(t *testing.T) {
		h := approvalHost(t)
		a := approvalConnect(t, h, true, true, true, false)
		approvalPrimary(t, h, a.id)
		result := approvalStart(h.srv.approvals, context.Background(), "one")
		approvalState(t, a, "one", 1)
		require.Equal(t, consent.Deny, approvalResultRead(t, result).decision)
		approvalPrimary(t, h, "")
	})
}
