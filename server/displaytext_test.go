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
