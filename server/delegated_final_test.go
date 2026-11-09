package server

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// freezableOriginHost is originHost over a connection that freeze silences,
// as a host is that has gone while something between it and the relay keeps
// the connection open. The test's cleanup thaws it, so the client's read loop
// can end. decisions, when set, receives the relay's decision requests.
func freezableOriginHost(t *testing.T, srv *testSSHD, original string, decisions func(*ssh.Request)) (*ssh.Client, func()) {
	t.Helper()
	auth := &AuthRequest{
		ClientVersion: upterm.HostSSHClientVersion, AuthorizedKey: ssh.MarshalAuthorizedKey(srv.signer.PublicKey()),
		RemoteAddr: "203.0.113.8:41234", Ingress: Ingress_INGRESS_SSH, IngressNode: srv.sshd.NodeAddr, IngressConnection: []byte(original),
	}
	cert, err := (&UserCertSigner{SessionID: original, User: "host", AuthRequest: auth}).SignCert(srv.signer)
	require.NoError(t, err)
	conn := &freezableConn{Conn: srv.rawConn(t), frozen: make(chan struct{}), thawed: make(chan struct{})}
	thaw := sync.OnceFunc(func() { close(conn.thawed) })
	t.Cleanup(thaw)
	c, ch, requests, err := ssh.NewClientConn(conn, srv.addr, &ssh.ClientConfig{User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	rest := make(chan *ssh.Request)
	go func() {
		defer close(rest)
		for r := range requests {
			if decisions != nil && r.Type == upterm.HostDelegatedDecisionRequestType {
				decisions(r)
				continue
			}
			rest <- r
		}
	}()
	client := ssh.NewClient(c, ch, rest)
	t.Cleanup(func() { thaw(); _ = client.Close(); _ = client.Wait() })
	return client, sync.OnceFunc(func() { close(conn.frozen) })
}

// A registration the authority accepts with a final decision keeps its
// connection only for the host's final reports, and that connection is
// pinged as a current registration's is: a host that falls silent while the
// connection stays open is closed at its silence deadline, and is then no
// longer counted, nor reported connected.
func TestFinalRegistrationIsPinged(t *testing.T) {
	for _, disposition := range []DelegatedDisposition{DelegatedDisposition_DELEGATED_STOPPED, DelegatedDisposition_DELEGATED_WITHDRAWN} {
		t.Run(disposition.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				timing := liveness.Timing{Interval: 50 * time.Millisecond, Bound: 50 * time.Millisecond}
				authority := &fakeAuthority{register: decided(disposition, 4)}
				srv := newBubbleSSHD(t, withAuthority(authority), func(d *sshd) { d.liveness = timing })
				p := newProven(t)
				host, freeze := freezableOriginHost(t, srv, "final-original", nil)
				ok, body := sendCreate(t, host, originRequest(t, p, "final-original", 1))
				require.True(t, ok, "%q", body)
				registrations, _ := authority.seen()
				require.Len(t, registrations, 1)
				contact := registrations[0].Contact
				connected := func() bool {
					counted, _ := srv.sshd.delegated.Counts()
					return counted == 1 && contact().Connected
				}
				synctest.Wait()
				require.True(t, connected())
				// The host's last byte arrived now: it is silent from here.
				deadline := time.Now().Add(timing.Interval + timing.Bound)
				freeze()
				synctest.Wait()
				time.Sleep(time.Until(deadline) - time.Nanosecond)
				synctest.Wait()
				require.True(t, connected(), "closed before the host's silence deadline")
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				counted, _ := srv.sshd.delegated.Counts()
				require.Zero(t, counted, "a silent host is still counted")
				require.False(t, contact().Connected, "a silent host is still reported connected")
			})
		})
	}
}

// A final decision pushed to a current registration retires its home before
// the push, so no guest reaches it, but the push still returns within its
// own deadline however long the store takes to release the route. The
// release completes once the store answers.
func TestPushedFinalDecisionIsBoundedByItsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newReleaseWitnessStore(1)
		store.SessionStore = newMemorySessionStore(slog.New(slog.DiscardHandler))
		t.Cleanup(store.releaseHolds)
		srv := newBubbleSSHD(t, withAuthority(&fakeAuthority{}), func(s *sshd) {
			s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
		})
		p := newProven(t)
		// The host never answers the decision: the push waits for it until
		// its deadline. It records whether the relay still served the home
		// when the decision arrived.
		servedAtPush := make(chan bool, 1)
		host, _ := freezableOriginHost(t, srv, "original", func(*ssh.Request) {
			_, found := srv.sshd.Lookup(p.id())
			servedAtPush <- found
		})
		ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
		require.True(t, ok, "%q", body)
		home, found := srv.sshd.Lookup(p.id())
		require.True(t, found)

		const deadline = 100 * time.Millisecond
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		defer cancel()
		start := time.Now()
		returned := make(chan time.Duration, 1)
		go func() {
			_, _ = srv.sshd.delegated.PushDecision(ctx, &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2})
			returned <- time.Since(start)
		}()
		// The store's release of the route is held, and the home is already
		// retired: no guest reaches it.
		release := store.call(t, 1)
		require.True(t, homeRetired(home), "the home was still held while the store released its route")
		_, found = srv.sshd.Lookup(p.id())
		require.False(t, found)

		time.Sleep(deadline)
		synctest.Wait()
		select {
		case took := <-returned:
			require.LessOrEqual(t, took, deadline)
		default:
			t.Fatal("the push outlived its deadline while the store released the route")
		}
		select {
		case served := <-servedAtPush:
			require.False(t, served, "the decision reached the host before its home was retired")
		default:
			t.Fatal("the decision never reached the host")
		}

		store.releaseHolds()
		<-release.returned
		synctest.Wait()
		_, err := srv.sshd.SessionManager.GetSession(p.id())
		require.Error(t, err, "the route stayed once the store released it")
		require.Nil(t, slotOf(srv, p.id()))
	})
}

// A final decision pushed while the relay is stopping retires the home before
// the push returns, though the stopping sshd takes no release work: the home
// would otherwise stay held, and joinable, until its host's connection ended.
func TestPushedFinalDecisionRetiresTheHomeOnAStoppingRelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newBubbleSSHD(t, withAuthority(&fakeAuthority{}))
		p := newProven(t)
		host, _ := freezableOriginHost(t, srv, "original", nil)
		ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
		require.True(t, ok, "%q", body)
		home, found := srv.sshd.Lookup(p.id())
		require.True(t, found)

		// The sshd stops taking work, as it does when the relay stops; its
		// connections stay open.
		srv.sshd.work.seal()

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, _ = srv.sshd.delegated.PushDecision(ctx, &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2})
		require.True(t, homeRetired(home), "the home stayed held after a final decision on a stopping relay")
		_, found = srv.sshd.Lookup(p.id())
		require.False(t, found, "the home stayed joinable after a final decision on a stopping relay")
	})
}
