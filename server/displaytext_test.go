package server

import (
	"testing"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
)

// Each wire text a guest can be rejected with has a sentence a person using
// plain ssh reads in its place, naming the session as a banner does.
func TestDisplayRejectionWordsEveryWireText(t *testing.T) {
	for wire, want := range map[string]string{
		upterm.UpstreamNoHost:          "upterm: no host is connected for session Ab3 right now; it may have ended, or the ID may be wrong.",
		upterm.UpstreamLookupFailed:    "upterm: the relay can't look up sessions right now; try again shortly.",
		upterm.UpstreamKeyRefused:      "upterm: session Ab3 refused your key; if another key is authorized, pass it with ssh -i, or ask the host to add yours.",
		upterm.UpstreamAuthFailed:      "upterm: session Ab3 refused your key, or the relay has no such session.",
		upterm.UpstreamUnavailable:     "upterm: the relay can't reach the host of session Ab3 right now; try again shortly.",
		upterm.UpstreamHostKeyMismatch: "upterm: the relay couldn't verify the host of session Ab3.",
	} {
		got, ok := displayRejection(wire, "Ab3")
		require.True(t, ok, "%q", wire)
		require.Equal(t, want, got)
	}
	// The ID is whatever the guest's user carries, and lands on its terminal.
	got, _ := displayRejection(upterm.UpstreamHostKeyMismatch, "a\x1b[2Jb")
	require.Equal(t, `upterm: the relay couldn't verify the host of session "a\x1b[2Jb".`, got)
}

func TestDisplayRejectionPassesOtherTextsThrough(t *testing.T) {
	for _, msg := range []string{"host policy explanation", "", upterm.UpstreamNoHost + "\n", "SSH peer disconnected"} {
		_, ok := displayRejection(msg, "s")
		require.False(t, ok, "%q", msg)
	}
	rewrite := rejectionRewriteFor("SSH-2.0-OpenSSH_9.6", false, "s")
	require.Equal(t, "host policy explanation", rewrite.apply("host policy explanation"))
}

// Only a plain ssh client is shown the sentences: upterm join and a relay node
// match the wire texts, and a host reads them. A host opens no channel, so no
// end-to-end test sees its branch; this one does.
func TestRejectionRewriteForWordsOnlyForPlainClients(t *testing.T) {
	for _, tc := range []struct {
		name          string
		clientVersion string
		hop           bool
		words         bool
	}{
		{"join", upterm.JoinSSHClientVersion, false, false},
		{"host", upterm.HostSSHClientVersion, false, false},
		{"hop", "SSH-2.0-Go", true, false},
		{"plain", "SSH-2.0-OpenSSH_9.6", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rewrite := rejectionRewriteFor(tc.clientVersion, tc.hop, "s")
			if tc.words {
				require.NotNil(t, rewrite)
			} else {
				require.Nil(t, rewrite)
			}
		})
	}
}
