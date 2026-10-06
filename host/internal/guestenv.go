package internal

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/owenthereal/upterm/server"
)

// sshSessionVars are the variables sshd sets to describe a session: where its
// client is, and which terminal it has. A guest's forced command is told its
// guest's, never the ones the host inherited -- from its own ssh login, say,
// which describe another connection and a terminal the command is not on.
var sshSessionVars = []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"}

// withoutSSHSessionVars returns a copy of env with sshSessionVars taken out.
func withoutSSHSessionVars(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(sshSessionVars, name)
	})
}

// guestConnectionEnv is SSH_CONNECTION and SSH_CLIENT for a guest, written as
// sshd writes them, from the two ends of the guest's connection to the relay
// that the relay names in the guest's certificate.
//
// Nil under --hide-client-ip, and nil when either end is missing or is not an
// IP address -- a relay older than local_addr names only the guest's -- because
// a variable that is absent misleads nobody, and one that is half made up does.
func guestConnectionEnv(auth *server.AuthRequest, hideClientIP bool) []string {
	if hideClientIP {
		return nil
	}
	client, err := netip.ParseAddrPort(auth.GetRemoteAddr())
	if err != nil {
		return nil
	}
	relay, err := netip.ParseAddrPort(auth.GetLocalAddr())
	if err != nil {
		return nil
	}
	// Unmapped because sshd writes an IPv4 peer on a dual-stack socket as the
	// IPv4 address it is, and bare because it writes IPv6 without brackets.
	clientIP, relayIP := client.Addr().Unmap(), relay.Addr().Unmap()
	return []string{
		fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", clientIP, client.Port(), relayIP, relay.Port()),
		fmt.Sprintf("SSH_CLIENT=%s %d %d", clientIP, client.Port(), relay.Port()),
	}
}
