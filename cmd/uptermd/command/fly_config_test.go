package command

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/routing"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// flyEnv is the intended [env] block, transcribed here so this test can run
// before Task 7 edits the TOML files. It pins behavior against the wrapper; it
// does NOT prove the shipped TOML files contain these values. Task 7 adds
// TestShippedFlyConfigsDecode, which reads the real files.
var flyEnv = map[string]string{
	"UPTERMD_SSH_ADDR":           "[::]:2222",
	"UPTERMD_WS_ADDR":            "[::]:8080",
	"UPTERMD_METRIC_ADDR":        "[::]:9091",
	"UPTERMD_SSH_PROXY_PROTOCOL": "true",
	"UPTERMD_NODE_ADDR":          "${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:2222",
	"UPTERMD_ROUTING":            "auto",
	"UPTERMD_CONSUL_URL":         "${FLY_CONSUL_URL:-}",
	"UPTERMD_CONSUL_SESSION_TTL": "1h",
}

// TestFlyConfigMatchesDeletedWrapper pins the fly.toml [env] block to the
// behavior of cmd/uptermd-fly/main.go:25-40, which it replaces.
func TestFlyConfigMatchesDeletedWrapper(t *testing.T) {
	t.Run("single machine, no consul attached", func(t *testing.T) {
		setFlyEnv(t, "")

		opt, err := unmarshalForTest(t)
		require.NoError(t, err)

		// Identical to the wrapper.
		require.Equal(t, "[::]:2222", opt.SSHAddr)
		require.Equal(t, "[::]:8080", opt.WSAddr)
		require.Equal(t, "[::]:9091", opt.MetricAddr)
		require.True(t, opt.SSHProxyProtocol)
		require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
		require.Empty(t, opt.ConsulURL)

		// Divergence 1: the wrapper set Routing to a concrete mode; the config
		// sets "auto". Equivalence is asserted on the resolved value.
		require.Equal(t, routing.ModeAuto, opt.Routing)
		require.Equal(t, routing.ModeEmbedded, opt.ResolvedRouting())

		// Divergence 2: the wrapper left ConsulSessionTTL at the flag default
		// in embedded mode. Setting it unconditionally is inert, because it is
		// read only under case routing.ModeConsul in Start (server/server.go)
		// and validated only in validateConsulConfig (server/server.go).
		require.Equal(t, "1h", opt.ConsulSessionTTL)
		require.NoError(t, opt.Validate())
	})

	t.Run("multi machine, consul attached", func(t *testing.T) {
		setFlyEnv(t, "https://consul.internal:8500/upterm/")

		opt, err := unmarshalForTest(t)
		require.NoError(t, err)

		require.Equal(t, "[::]:2222", opt.SSHAddr)
		require.Equal(t, "[::]:8080", opt.WSAddr)
		require.Equal(t, "[::]:9091", opt.MetricAddr)
		require.True(t, opt.SSHProxyProtocol)
		require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)

		// Identical to the wrapper's consul branch.
		require.Equal(t, "https://consul.internal:8500/upterm/", opt.ConsulURL)
		require.Equal(t, "1h", opt.ConsulSessionTTL)
		require.Equal(t, routing.ModeConsul, opt.ResolvedRouting())
		require.NoError(t, opt.Validate())
	})
}

// TestFlyConfigFailsWithoutFlyRuntimeVars pins both halves of the guard that
// cmd/uptermd-fly/main.go:12-22 provided: it exited if either FLY_APP_NAME or
// FLY_MACHINE_ID was missing. Both are covered because expansion scans left to
// right — an absent FLY_MACHINE_ID short-circuits before the FLY_APP_NAME
// token is reached, so one case cannot stand in for the other.
func TestFlyConfigFailsWithoutFlyRuntimeVars(t *testing.T) {
	t.Run("FLY_MACHINE_ID missing", func(t *testing.T) {
		resetUptermdEnv(t)
		for k, v := range flyEnv {
			t.Setenv(k, v)
		}
		t.Setenv("FLY_APP_NAME", "upterm")
		// FLY_MACHINE_ID must be absent, not merely unmentioned.
		unsetEnv(t, "FLY_MACHINE_ID")

		_, err := unmarshalForTest(t)

		require.Error(t, err)
		require.Contains(t, err.Error(), `required variable "FLY_MACHINE_ID" is not set`)
	})

	t.Run("FLY_APP_NAME missing", func(t *testing.T) {
		resetUptermdEnv(t)
		for k, v := range flyEnv {
			t.Setenv(k, v)
		}
		t.Setenv("FLY_MACHINE_ID", "d891")
		// FLY_APP_NAME must be absent, not merely unmentioned.
		unsetEnv(t, "FLY_APP_NAME")

		_, err := unmarshalForTest(t)

		require.Error(t, err)
		require.Contains(t, err.Error(), `required variable "FLY_APP_NAME" is not set`)
	})
}

func setFlyEnv(t *testing.T, consulURL string) {
	t.Helper()
	resetUptermdEnv(t)
	for k, v := range flyEnv {
		t.Setenv(k, v)
	}
	// Injected by the Fly platform at runtime.
	t.Setenv("FLY_MACHINE_ID", "d891")
	t.Setenv("FLY_APP_NAME", "upterm")
	t.Setenv("FLY_CONSUL_URL", consulURL)
}

// loadShippedFlyEnv reads the [env] block out of a committed TOML file and
// applies it to the process environment, mimicking what Fly does at runtime.
func loadShippedFlyEnv(t *testing.T, file string) {
	t.Helper()
	resetUptermdEnv(t)

	// viper already parses TOML; no new dependency is needed.
	cfg := viper.New()
	cfg.SetConfigFile(filepath.Join("..", "..", "..", file))
	require.NoError(t, cfg.ReadInConfig())

	env := cfg.GetStringMapString("env")
	require.NotEmpty(t, env, "[env] block is missing")

	// viper lowercases keys; uppercase them back into real variables.
	for k, v := range env {
		t.Setenv(strings.ToUpper(k), v)
	}
	t.Setenv("FLY_MACHINE_ID", "d891")
	t.Setenv("FLY_APP_NAME", "upterm")
}

// TestShippedFlyConfigsDecode runs the [env] block from each committed TOML
// file through the real decode path, so a typo in the shipped configuration
// fails here rather than on deploy.
//
// Both Consul states are exercised. With Consul absent only, a UPTERMD_CONSUL_URL
// that had been deleted or misspelled in both files would still yield an empty
// ConsulURL and resolve to embedded — passing while broken.
func TestShippedFlyConfigsDecode(t *testing.T) {
	for _, file := range []string{"fly.toml", "fly.example.toml"} {
		t.Run(file+"/no consul attached", func(t *testing.T) {
			loadShippedFlyEnv(t, file)
			unsetEnv(t, "FLY_CONSUL_URL")

			opt, err := unmarshalForTest(t)
			require.NoError(t, err)

			require.Equal(t, "[::]:2222", opt.SSHAddr)
			require.Equal(t, "[::]:8080", opt.WSAddr)
			require.Equal(t, "[::]:9091", opt.MetricAddr)
			require.True(t, opt.SSHProxyProtocol)
			require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
			require.Equal(t, routing.ModeAuto, opt.Routing)
			require.Empty(t, opt.ConsulURL)
			require.Equal(t, routing.ModeEmbedded, opt.ResolvedRouting())
			require.Equal(t, "1h", opt.ConsulSessionTTL)
			require.NoError(t, opt.Validate())
		})

		t.Run(file+"/consul attached", func(t *testing.T) {
			const consulURL = "https://consul.internal:8500/upterm/"
			loadShippedFlyEnv(t, file)
			t.Setenv("FLY_CONSUL_URL", consulURL)

			opt, err := unmarshalForTest(t)
			require.NoError(t, err)

			// Fails if UPTERMD_CONSUL_URL is missing or misspelled in the file.
			require.Equal(t, consulURL, opt.ConsulURL)
			require.Equal(t, routing.ModeConsul, opt.ResolvedRouting())
			require.Equal(t, "1h", opt.ConsulSessionTTL)
			require.Equal(t, "d891.vm.upterm.internal:2222", opt.NodeAddr)
			require.NoError(t, opt.Validate())
		})
	}
}
