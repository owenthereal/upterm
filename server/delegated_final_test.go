package server

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// freezableOriginHost is originHost over a connection that freeze silences,
// as a host is that has gone while something between it and the relay keeps
// the connection open. The test's cleanup thaws it, so the client's read loop
// can end.
func freezableOriginHost(t *testing.T, srv *testSSHD, original string) (*ssh.Client, func()) {
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
	client := ssh.NewClient(c, ch, requests)
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
				host, freeze := freezableOriginHost(t, srv, "final-original")
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
