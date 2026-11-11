package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// A PROXY header sent to the internal listener, which reads none, can't make
// a raw guest an SSH ingress guest of a delegated registration: it reaches
// neither the authority nor the host.
func TestGateAttacksAndOutages(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(fmt.Sprintf("internal_PROXY_v%d_cannot_create_ssh_origin", version), func(t *testing.T) {
			authority := &fakeAuthority{}
			f := delegatedGateHome(t, func(p *sshProxy) {
				p.authority, p.AuthorityEnabled, p.AuthorityComposed = authority, true, true
				p.NodeID = "home-machine"
			})
			raw, err := net.DialTimeout("tcp", f.addr, time.Second)
			require.NoError(t, err)
			defer func() { _ = raw.Close() }()
			require.NoError(t, raw.SetDeadline(time.Now().Add(2*time.Second)))
			_, err = (&proxyproto.Header{Version: version, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4, SourceAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, DestinationAddr: raw.RemoteAddr()}).WriteTo(raw)
			require.NoError(t, err)
			conn, _, _, err := ssh.NewClientConn(raw, f.addr, &ssh.ClientConfig{User: f.route, Auth: []ssh.AuthMethod{ssh.PublicKeys(f.guest)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err, "a PROXY header made a raw guest an SSH ingress guest")
			admissions, _ := authority.guests()
			require.Empty(t, admissions, "untrusted source metadata reached the authority")
			require.Zero(t, f.dialer.calls.Load(), "untrusted source metadata reached the host")
		})
	}
}
