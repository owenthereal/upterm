package host

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// relayKeyChecks are upterm host's two checks of its relay's key, the
// prompting one and --skip-host-key-check's, with the trust each reports for
// a key it takes on first use.
var relayKeyChecks = []struct {
	name     string
	firstUse string
	new      func(stdin io.Reader, stdout io.Writer, file string) (*RelayKeyCheck, error)
}{
	{"prompting", RelayKeyPrompted, func(stdin io.Reader, stdout io.Writer, file string) (*RelayKeyCheck, error) {
		return NewPromptingRelayKeyCheck(stdin, stdout, file, false)
	}},
	{"auto-accepting", RelayKeyAutoAccepted, func(_ io.Reader, stdout io.Writer, file string) (*RelayKeyCheck, error) {
		return NewAutoAcceptingRelayKeyCheck(stdout, file)
	}},
}

// authorityLine is the @cert-authority line for host and key, as a check
// writes it.
func authorityLine(host string, key ssh.PublicKey) string {
	return "@cert-authority " + knownhosts.Line([]string{host}, key)
}

// A check says which known_hosts line a guest pins the key it accepted with,
// for the host and port it was checked for, and how it came to trust it:
// known when a line was there already, and otherwise the way it took the key
// on first use, recording it.
func TestRelayKeyCheckSaysWhatItTrustedAndHow(t *testing.T) {
	ca, hostKey := newSigner(t), newSigner(t)
	cert := signHostCert(t, ca, hostKey.PublicKey(), "relay.test")
	// Signed by its own key, as every uptermd's certificate is.
	selfSigned := signHostCert(t, hostKey, hostKey.PublicKey(), "relay.test")
	// Certificates another authority signs, which ssh accepts by it only for
	// a host they list: none, other hosts, the host in capitals, the host
	// among others, and an address.
	noPrincipals := signHostCert(t, ca, hostKey.PublicKey())
	otherHosts := signHostCert(t, ca, hostKey.PublicKey(), "other.test", "relay.test.example")
	inCapitals := signHostCert(t, ca, hostKey.PublicKey(), "Relay.Test")
	amongOthers := signHostCert(t, ca, hostKey.PublicKey(), "other.test", "relay.test")
	ipv6 := signHostCert(t, ca, hostKey.PublicKey(), "::1")
	plain := knownhosts.Line([]string{"relay.test"}, hostKey.PublicKey())
	authority := authorityLine("relay.test", ca.PublicKey())
	ownAuthority := authorityLine("relay.test", hostKey.PublicKey())

	for _, tc := range []struct {
		name       string
		knownHosts string
		addr       string
		key        ssh.PublicKey
		wantLine   string
		known      bool
		recorded   string // what a first use writes to the file; wantLine when empty
	}{
		{"a plain key its line names", plain + "\n", "relay.test:22", hostKey.PublicKey(), plain, true, ""},
		{"a certificate its authority's line trusts", authority + "\n", "relay.test:22", cert, authority, true, ""},
		// The certificate is trusted by its own key, which is all the line
		// vouches for: its authority was never checked.
		{"a certificate a line for its own key trusts", plain + "\n", "relay.test:22", cert, plain, true, ""},
		// Its authority is the key the relay proved it holds, so a guest pins
		// that key itself, the form ssh accepts whatever names the certificate
		// lists.
		{"a self-signed certificate its key's authority line trusts", ownAuthority + "\n", "relay.test:22", selfSigned, plain, true, ""},
		{"a plain key no line names", "", "relay.test:22", hostKey.PublicKey(), plain, false, ""},
		{"a certificate no line names", "", "relay.test:22", cert, authority, false, ""},
		{"a self-signed certificate no line names", "", "relay.test:22", selfSigned, plain, false, ownAuthority},
		{"a key on another port", "", "relay.test:2222", hostKey.PublicKey(),
			knownhosts.Line([]string{"[relay.test]:2222"}, hostKey.PublicKey()), false, ""},
		// ssh refuses a certificate that lists no names, or not the host it
		// dialled, and then checks its key as a plain one: a guest pins that
		// key, as for a self-signed certificate, while the host's own file
		// keeps the authority. ssh lowercases the host it dials and compares
		// the names letter for letter, so a name in capitals isn't the host.
		{"a certificate that lists no names, its authority's line trusts", authority + "\n", "relay.test:22", noPrincipals, plain, true, ""},
		{"a certificate that lists no names, no line names", "", "relay.test:22", noPrincipals, plain, false, authority},
		{"a certificate for other hosts no line names", "", "relay.test:22", otherHosts, plain, false, authority},
		{"a certificate for its host in capitals no line names", "", "relay.test:22", inCapitals, plain, false, authority},
		// One that lists the host is pinned by its authority, for the host and
		// port the check was asked about.
		{"a certificate for its host among others no line names", "", "relay.test:22", amongOthers, authority, false, ""},
		{"a certificate for a host dialled in capitals", "", "Relay.Test:22", cert,
			authorityLine("Relay.Test", ca.PublicKey()), false, ""},
		{"a certificate for an address on another port", "", "[::1]:2222", ipv6,
			authorityLine("[::1]:2222", ca.PublicKey()), false, ""},
	} {
		for _, c := range relayKeyChecks {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				file := writeKnownHosts(t, tc.knownHosts)
				check, err := c.new(strings.NewReader("yes\n"), io.Discard, file)
				require.NoError(t, err)
				_, ok := check.Trusted()
				require.False(t, ok, "nothing is trusted before a key is checked")

				require.NoError(t, check.HostKeyCallback(tc.addr, fakeAddr, tc.key))

				want := TrustedRelayKey{KnownHostsLine: tc.wantLine, Trust: RelayKeyKnown}
				wantFile := tc.knownHosts
				if !tc.known {
					want.Trust = c.firstUse
					wantFile = tc.wantLine + "\n"
					if tc.recorded != "" {
						wantFile = tc.recorded + "\n"
					}
				}
				got, ok := check.Trusted()
				require.True(t, ok)
				require.Equal(t, want, got)
				content, err := os.ReadFile(file)
				require.NoError(t, err)
				require.Equal(t, wantFile, string(content), "what the file has afterwards")
			})
		}
	}
}

// A key taken on first use stays reported as that when the check sees it
// again, as for a re-key of the same connection: the line it finds then is
// the one it recorded itself.
func TestRelayKeyCheckKeepsHowItFirstTrustedAKey(t *testing.T) {
	key := newSigner(t).PublicKey()
	for _, c := range relayKeyChecks {
		t.Run(c.name, func(t *testing.T) {
			check, err := c.new(strings.NewReader("yes\n"), io.Discard, writeKnownHosts(t, ""))
			require.NoError(t, err)
			require.NoError(t, check.HostKeyCallback("relay.test:22", fakeAddr, key))
			require.NoError(t, check.HostKeyCallback("relay.test:22", fakeAddr, key))
			got, ok := check.Trusted()
			require.True(t, ok)
			require.Equal(t, c.firstUse, got.Trust)
		})
	}
}

// A key the check refuses is trusted by nobody: it reports nothing.
func TestRelayKeyCheckReportsNothingItRefused(t *testing.T) {
	pinned, presented := newSigner(t).PublicKey(), newSigner(t).PublicKey()
	pin := knownhosts.Line([]string{"relay.test"}, pinned) + "\n"
	for _, c := range relayKeyChecks {
		t.Run(c.name+"/a changed key", func(t *testing.T) {
			check, err := c.new(strings.NewReader("yes\n"), io.Discard, writeKnownHosts(t, pin))
			require.NoError(t, err)
			require.ErrorIs(t, check.HostKeyCallback("relay.test:22", fakeAddr, presented), ErrHostKeyChanged)
			_, ok := check.Trusted()
			require.False(t, ok)
		})
	}
	t.Run("prompting/declined at the prompt", func(t *testing.T) {
		check, err := NewPromptingRelayKeyCheck(strings.NewReader("no\n"), io.Discard, writeKnownHosts(t, ""), false)
		require.NoError(t, err)
		require.Error(t, check.HostKeyCallback("relay.test:22", fakeAddr, presented))
		_, ok := check.Trusted()
		require.False(t, ok)
	})
}

// With the published file, the public relay's certificate is trusted by its
// @cert-authority line, on each of the ports a host dials it on. Its
// authority is its own key, so a guest pins that key, for the same host and
// port.
func TestRelayKeyCheckReportsThePublishedPin(t *testing.T) {
	published, err := os.ReadFile(publishedKnownHosts)
	require.NoError(t, err)
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4"
	for addr, want := range map[string]string{
		"uptermd.upterm.dev:22":  "uptermd.upterm.dev " + key,
		"uptermd.upterm.dev:443": "[uptermd.upterm.dev]:443 " + key,
	} {
		t.Run(addr, func(t *testing.T) {
			check, err := NewPromptingRelayKeyCheck(strings.NewReader(""), io.Discard, writeKnownHosts(t, string(published)), false)
			require.NoError(t, err)
			require.NoError(t, check.HostKeyCallback(addr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, relayHostCert(t)))
			got, ok := check.Trusted()
			require.True(t, ok)
			require.Equal(t, TrustedRelayKey{KnownHostsLine: want, Trust: RelayKeyKnown}, got)
		})
	}
}

// The callbacks the older constructors return are a check's: they ask and
// record as they always did.
func TestTheHostKeyCallbacksAreTheChecks(t *testing.T) {
	key := newSigner(t).PublicKey()
	stdout := &bytes.Buffer{}
	file := writeKnownHosts(t, "")
	cb, err := NewAutoAcceptingHostKeyCallback(stdout, file)
	require.NoError(t, err)
	require.NoError(t, cb("relay.test:22", fakeAddr, key))
	require.Contains(t, stdout.String(), "Warning: Permanently added 'relay.test'")
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, knownhosts.Line([]string{"relay.test"}, key)+"\n", string(content))
}
