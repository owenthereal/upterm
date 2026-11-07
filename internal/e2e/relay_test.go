package e2e

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelayArgsPutTheHarnessLast(t *testing.T) {
	got, err := relayArgs("127.0.0.1:1", "/k", []string{"--node-id", "e2e"})
	require.NoError(t, err)
	require.Equal(t, []string{"--node-id", "e2e", "--ssh-addr", "127.0.0.1:1", "--private-key", "/k"}, got)
}

// The harness owns the relay's address and host key. --private-key is a slice
// flag, so a second one would add a key rather than replace the harness's.
func TestRelayArgsRefuseTheHarnessFlags(t *testing.T) {
	for _, tc := range []struct {
		extra []string
		flag  string
	}{
		{extra: []string{"--ssh-addr=x"}, flag: "--ssh-addr"},
		{extra: []string{"--ssh-addr", "x"}, flag: "--ssh-addr"},
		{extra: []string{"--private-key", "x"}, flag: "--private-key"},
		{extra: []string{"--node-id", "e2e", "--private-key=x"}, flag: "--private-key"},
	} {
		got, err := relayArgs("127.0.0.1:1", "/k", tc.extra)
		require.Error(t, err, "extra %q", tc.extra)
		require.ErrorContains(t, err, tc.flag, "extra %q", tc.extra)
		require.Nil(t, got, "extra %q", tc.extra)
	}
}

func TestRelayBinaryFromEnvMustExist(t *testing.T) {
	t.Setenv(relayBinaryEnv, "no-such-binary")
	dir := t.TempDir()

	bin, err := relayBinary(t.Context(), dir)
	require.ErrorIs(t, err, exec.ErrNotFound)
	require.Empty(t, bin)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "a relay binary named in the environment must not be built")
}
