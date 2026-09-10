package command

import (
	"os"
	"testing"
	"time"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
)

// uptermdEnv lists every variable that can influence a decode, so tests can
// start from a known-empty environment. root.go:100-105 binds UPTERMD_*
// through viper's AutomaticEnv and additionally binds bare SENTRY_DSN.
var uptermdEnv = []string{
	"UPTERMD_SSH_ADDR", "UPTERMD_WS_ADDR", "UPTERMD_NODE_ADDR",
	"UPTERMD_AUTHORIZED_KEYS", "UPTERMD_PRIVATE_KEY", "UPTERMD_HOSTNAME",
	"UPTERMD_SSH_PROXY_PROTOCOL", "UPTERMD_NETWORK", "UPTERMD_NETWORK_OPT",
	"UPTERMD_METRIC_ADDR", "UPTERMD_DEBUG", "UPTERMD_ROUTING",
	"UPTERMD_CONSUL_URL", "UPTERMD_CONSUL_SESSION_TTL", "UPTERMD_SENTRY_DSN",
	"SENTRY_DSN", "UPTERMD_HANDSHAKE_TIMEOUT",
}

// ambientEnv lists variables that reach the decoded struct through flag
// DEFAULTS rather than viper's UPTERMD_ prefix, and so are invisible to
// uptermdEnv. PORT feeds the ssh-addr default via utils.DefaultLocalhost
// (utils/utils.go:163); DEBUG feeds the debug default (root.go:41). Both are
// read when Root() is constructed, which is why resetUptermdEnv must clear
// them before unmarshalForTest builds the command.
var ambientEnv = []string{"PORT", "DEBUG"}

// unsetEnv removes keys for the duration of the test and restores their prior
// state afterwards. Go has t.Setenv but no t.Unsetenv.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if old, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		require.NoError(t, os.Unsetenv(k))
	}
}

// resetUptermdEnv clears every variable that can influence a decode.
//
// Call it as the FIRST line of a test, before setting the values under test —
// it unsets, so calling it afterwards would discard them. Environment values
// outrank config-file values in viper, so an ambient UPTERMD_* would otherwise
// silently mask what a test asserts.
func resetUptermdEnv(t *testing.T) {
	t.Helper()
	unsetEnv(t, uptermdEnv...)
	unsetEnv(t, ambientEnv...)
}

// unmarshalForTest parses args against a fresh root command and decodes the
// result, exercising the same path RunE uses.
func unmarshalForTest(t *testing.T, args ...string) (server.Opt, error) {
	t.Helper()
	cmd := Root()
	require.NoError(t, cmd.ParseFlags(args))

	var opt server.Opt
	err := unmarshalFlags(cmd, &opt)
	return opt, err
}

func TestUnmarshalFlagsExpandsFlagValues(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("FLY_MACHINE_ID", "d891")
	t.Setenv("FLY_APP_NAME", "upterm")

	opt, err := unmarshalForTest(t, "--node-addr", "${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:2222")

	require.NoError(t, err)
	require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
}

func TestUnmarshalFlagsExpandsEnvValues(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("FLY_MACHINE_ID", "d891")
	t.Setenv("FLY_APP_NAME", "upterm")
	t.Setenv("UPTERMD_NODE_ADDR", "${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:2222")

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
}

func TestUnmarshalFlagsExpandsConfigFileValues(t *testing.T) {
	// Especially important here: an ambient UPTERMD_NODE_ADDR would outrank
	// the config file and the test would assert nothing.
	resetUptermdEnv(t)
	t.Setenv("FLY_MACHINE_ID", "d891")
	t.Setenv("FLY_APP_NAME", "upterm")

	dir := t.TempDir()
	path := dir + "/uptermd.yaml"
	require.NoError(t, os.WriteFile(path,
		[]byte("node-addr: ${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:2222\n"), 0o600))

	opt, err := unmarshalForTest(t, "--config", path)

	require.NoError(t, err)
	require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
}

// Regression test: expansion must not disturb viper's default decode hooks,
// which split comma-separated values into []string.
func TestUnmarshalFlagsSplitsListsThenExpandsElements(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("KEYS_DIR", "/etc/keys")
	t.Setenv("UPTERMD_AUTHORIZED_KEYS", "${KEYS_DIR}/a,${KEYS_DIR}/b")

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, []string{"/etc/keys/a", "/etc/keys/b"}, opt.AuthorizedKeysFiles)
}

// Expansion must run exactly once. A hook-based implementation would expand
// the whole string and then each element, turning "$${NAME}" into a
// substitution or an error on the second pass.
func TestUnmarshalFlagsExpandsListElementsExactlyOnce(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("KEYS_DIR", "/etc/keys")
	t.Setenv("UPTERMD_AUTHORIZED_KEYS", "$${KEYS_DIR}/a")

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, []string{"${KEYS_DIR}/a"}, opt.AuthorizedKeysFiles)
}

// Splitting happens before expansion, so a comma inside a substituted value
// does not create a new element.
func TestUnmarshalFlagsDoesNotSplitOnSubstitutedComma(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("HOSTS", "a.example.com,b.example.com")
	t.Setenv("UPTERMD_HOSTNAME", "${HOSTS}")

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com,b.example.com"}, opt.Hostnames)
}

// A credential whose value contains a reference must survive verbatim.
func TestUnmarshalFlagsDoesNotRescanSubstitutedValues(t *testing.T) {
	// root.go:105 binds bare SENTRY_DSN ahead of UPTERMD_SENTRY_DSN;
	// resetUptermdEnv clears both.
	resetUptermdEnv(t)
	t.Setenv("SECRET_DSN", "https://user:p${TOKEN}w@sentry.example.com/1")
	t.Setenv("TOKEN", "should-not-appear")
	t.Setenv("UPTERMD_SENTRY_DSN", "${SECRET_DSN}")

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, "https://user:p${TOKEN}w@sentry.example.com/1", opt.SentryDSN)
}

func TestUnmarshalFlagsFailsOnUnsetRequiredVariable(t *testing.T) {
	resetUptermdEnv(t)
	unsetEnv(t, "FLY_MACHINE_ID")
	t.Setenv("UPTERMD_NODE_ADDR", "${FLY_MACHINE_ID}.vm.internal:2222")

	_, err := unmarshalForTest(t)

	require.Error(t, err)
	require.Contains(t, err.Error(), `required variable "FLY_MACHINE_ID" is not set`)
}

// PORT and DEBUG reach the decoded struct through flag defaults rather than
// viper's UPTERMD_ prefix. Setting them before the reset is deliberate: the
// reset clearing them is exactly what this test asserts.
func TestResetUptermdEnvClearsAmbientPortAndDebug(t *testing.T) {
	t.Setenv("PORT", "9999")
	t.Setenv("DEBUG", "1")

	resetUptermdEnv(t)

	opt, err := unmarshalForTest(t)

	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:2222", opt.SSHAddr)
	require.False(t, opt.Debug)
}

func TestFrontDoorFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		env     bool
		timeout time.Duration
	}{
		{name: "defaults", timeout: 60 * time.Second},
		{name: "flags", args: []string{"--handshake-timeout=8s"}, timeout: 8 * time.Second},
		{name: "environment", env: true, timeout: 12 * time.Second},
		{name: "flag overrides environment", env: true, args: []string{"--handshake-timeout=4s"}, timeout: 4 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetUptermdEnv(t)
			if tc.env {
				t.Setenv("UPTERMD_HANDSHAKE_TIMEOUT", "12s")
			}
			cmd := Root()
			require.NoError(t, cmd.ParseFlags(tc.args))
			var opt server.Opt
			require.NoError(t, unmarshalFlags(cmd, &opt))
			require.Equal(t, tc.timeout, opt.HandshakeTimeout)
		})
	}
}

func TestNegativeHandshakeTimeout(t *testing.T) {
	resetUptermdEnv(t)
	cmd := Root()
	require.NoError(t, cmd.ParseFlags([]string{"--handshake-timeout=-1s"}))
	var opt server.Opt
	require.NoError(t, unmarshalFlags(cmd, &opt))
	require.ErrorContains(t, opt.Validate(), "handshake-timeout")
}

func TestRemovedFrontDoorFlag(t *testing.T) {
	for _, arg := range []string{"--stock-ssh", "--stock-ssh=false"} {
		t.Run(arg, func(t *testing.T) {
			require.ErrorContains(t, Root().ParseFlags([]string{arg}), "unknown flag: --stock-ssh")
		})
	}
}
