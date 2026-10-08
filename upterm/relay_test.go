package upterm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// upterm join matches these texts on the wire, so changing one breaks every
// join that is already installed. This pins them byte for byte.
func TestRelayTextsAreTheWireContract(t *testing.T) {
	for _, tc := range []struct {
		name, got, want string
	}{
		{"BannerNoHostFormat", BannerNoHostFormat, "upterm: no host is connected for session %s right now. " +
			"If it is reconnecting, this same ssh command will work again once it's back. " +
			"Try again in a few seconds.\n"},
		{"BannerNoHostPrefix", BannerNoHostPrefix, "upterm: no host is connected for session "},
		{"BannerLookupFailed", BannerLookupFailed, "upterm: the relay can't look up sessions right now. Try again shortly.\n"},
		{"UpstreamUnavailable", UpstreamUnavailable, "upstream unavailable"},
		{"UpstreamAuthFailed", UpstreamAuthFailed, "ssh: unable to authenticate with the upstream"},
		{"UpstreamHostKeyMismatch", UpstreamHostKeyMismatch, "ssh: host key mismatch"},
		{"UpstreamNoHost", UpstreamNoHost, "upstream has no session"},
		{"UpstreamLookupFailed", UpstreamLookupFailed, "upstream can't look up sessions"},
		{"UpstreamKeyRefused", UpstreamKeyRefused, "upstream refused the key"},
		{"HopBannerKeyRefused", HopBannerKeyRefused, "upterm-hop: key refused\n"},
		{"JoinSSHClientVersion", JoinSSHClientVersion, "SSH-2.0-upterm-join"},
	} {
		require.Equal(t, tc.want, tc.got, tc.name)
	}
	// join recognizes the no-host banner by its prefix, whatever the session.
	require.True(t, strings.HasPrefix(BannerNoHostFormat, BannerNoHostPrefix))
}

// The relay treats any client version but the exact HostSSHClientVersion as a
// guest. join's must be neither that nor a prefix of it, nor have it as one.
func TestJoinVersionIsNeverTheHosts(t *testing.T) {
	require.NotEqual(t, HostSSHClientVersion, JoinSSHClientVersion)
	require.False(t, strings.HasPrefix(JoinSSHClientVersion, HostSSHClientVersion))
	require.False(t, strings.HasPrefix(HostSSHClientVersion, JoinSSHClientVersion))
}
