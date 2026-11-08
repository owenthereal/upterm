package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/server"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// probeEnv is what the probe extension's flags read from the environment.
var probeEnv = []string{"UPTERMD_PROBE_URL", "UPTERMD_PROBE_ON"}

// probeFlags registers the probe extension's flags.
func probeFlags(fs *pflag.FlagSet) {
	fs.String("probe-url", "", "where the probe reports")
	fs.Bool("probe-on", false, "whether the probe runs")
}

// errCaptured stops a run once New has seen its Config.
var errCaptured = errors.New("captured")

// execute runs cmd with args and ctx, its output discarded.
func execute(ctx context.Context, cmd *cobra.Command, args ...string) error {
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.ExecuteContext(ctx)
}

// captureConfig runs uptermd, composed with the probe extension, on args, and
// returns the Config its New was given. New stops the run there, so nothing
// listens. An error is the run's own, before New.
func captureConfig(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	var got *Config
	cmd := RootWith(&Extension{Name: "probe", Flags: probeFlags, New: func(_ context.Context, cfg Config) (server.Extensions, error) {
		require.Nil(t, got, "New ran twice")
		got = &cfg
		return server.Extensions{}, errCaptured
	}})
	err := execute(context.Background(), cmd, args...)
	if got == nil {
		require.Error(t, err)
		return Config{}, err
	}
	require.ErrorIs(t, err, errCaptured)
	return *got, nil
}

// freeAddr is a loopback address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	requireRefused(t, addr)
	return addr
}

// requireRefused proves nothing listens at addr.
func requireRefused(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "something listens at %s", addr)
}

func TestRootWithNilIsRoot(t *testing.T) {
	resetUptermdEnv(t)
	a, b := Root(), RootWith(nil)

	type flag struct {
		Name, Shorthand, Type, DefValue, Usage string
		Annotations                            map[string][]string
	}
	flags := func(cmd *cobra.Command) []flag {
		var out []flag
		for _, fs := range []*pflag.FlagSet{cmd.PersistentFlags(), cmd.LocalNonPersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) {
				out = append(out, flag{f.Name, f.Shorthand, f.Value.Type(), f.DefValue, f.Usage, f.Annotations})
			})
		}
		return out
	}
	require.NotEmpty(t, flags(a))
	require.Equal(t, flags(a), flags(b))

	commands := func(cmd *cobra.Command) []string {
		var names []string
		for _, c := range cmd.Commands() {
			names = append(names, c.Name())
		}
		slices.Sort(names)
		return names
	}
	require.Equal(t, commands(a), commands(b))

	help := func(cmd *cobra.Command) []byte {
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--help"})
		require.NoError(t, cmd.Execute())
		return out.Bytes()
	}
	require.NotEmpty(t, help(a))
	require.Equal(t, string(help(a)), string(help(Root())))
	require.Equal(t, string(help(Root())), string(help(RootWith(nil))))

	// An extension adds its own flag and command, and changes nothing else.
	composed := func() *cobra.Command {
		return RootWith(&Extension{
			Name:  "probe",
			Flags: func(fs *pflag.FlagSet) { fs.String("probe-url", "", "where the probe reports") },
			Commands: func() []*cobra.Command {
				return []*cobra.Command{{Use: "probe", Short: "run the probe", Run: func(*cobra.Command, []string) {}}}
			},
		})
	}
	// Fresh commands: executing one adds its help flag.
	plain, c := Root(), composed()
	withoutProbe := func(fs []flag) []flag {
		return slices.DeleteFunc(fs, func(f flag) bool { return f.Name == "probe-url" })
	}
	require.Len(t, flags(c), len(flags(plain))+1)
	require.Equal(t, flags(plain), withoutProbe(flags(c)))
	require.Equal(t, commands(plain), slices.DeleteFunc(commands(c), func(n string) bool { return n == "probe" }))
	withoutProbeLines := func(b []byte) string {
		lines := strings.Split(string(b), "\n")
		return strings.Join(slices.DeleteFunc(lines, func(l string) bool { return strings.Contains(l, "probe") }), "\n")
	}
	composedHelp := help(composed())
	require.Contains(t, string(composedHelp), "--probe-url")
	require.Equal(t, string(help(Root())), withoutProbeLines(composedHelp))

	// Both reach the server's own validation, and both run and stop.
	for _, cmd := range []*cobra.Command{Root(), RootWith(nil)} {
		require.ErrorContains(t, execute(context.Background(), cmd, "--network=unknown"), `unsupported network provider "unknown"`)
	}
	for _, cmd := range []*cobra.Command{Root(), RootWith(nil)} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.NoError(t, execute(ctx, cmd, "--ssh-addr=127.0.0.1:0"))
	}
}

func TestExtensionFlagsResolveLikeUptermds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   bool // the command line sets both
		env    bool // the environment does
		config bool // the config file does
		want   string
	}{
		{name: "default"},
		{name: "config file", config: true, want: "from-config"},
		{name: "environment over config file", env: true, config: true, want: "from-env"},
		{name: "command line over environment", args: true, env: true, config: true, want: "from-args"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetUptermdEnv(t)
			unsetEnv(t, probeEnv...)
			var args []string
			if tc.args {
				args = append(args, "--probe-url=from-args", "--node-addr=from-args")
			}
			if tc.env {
				t.Setenv("UPTERMD_PROBE_URL", "from-env")
				t.Setenv("UPTERMD_NODE_ADDR", "from-env")
			}
			if tc.config {
				path := filepath.Join(t.TempDir(), "uptermd.yaml")
				require.NoError(t, os.WriteFile(path, []byte("probe-url: from-config\nnode-addr: from-config\n"), 0o600))
				args = append(args, "--config", path)
			}
			cfg, err := captureConfig(t, args...)
			require.NoError(t, err)
			require.Equal(t, tc.want, cfg.Opt.NodeAddr)
			got, err := cfg.String("probe-url")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("a reference is expanded once", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		t.Setenv("PROBE_VAR", "${INNER}")
		t.Setenv("INNER", "rescanned")
		cfg, err := captureConfig(t, "--probe-url=${PROBE_VAR}", "--node-addr=${PROBE_VAR}")
		require.NoError(t, err)
		require.Equal(t, "${INNER}", cfg.Opt.NodeAddr)
		got, err := cfg.String("probe-url")
		require.NoError(t, err)
		require.Equal(t, "${INNER}", got)
	})

	t.Run("a bare dollar is literal", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		t.Setenv("PROBE_VAR", "expanded")
		cfg, err := captureConfig(t, "--probe-url=$PROBE_VAR", "--node-addr=$PROBE_VAR")
		require.NoError(t, err)
		require.Equal(t, "$PROBE_VAR", cfg.Opt.NodeAddr)
		got, err := cfg.String("probe-url")
		require.NoError(t, err)
		require.Equal(t, "$PROBE_VAR", got)
	})

	t.Run("an unset reference is an error", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		unsetEnv(t, "PROBE_VAR")
		_, err := captureConfig(t, "--node-addr=${PROBE_VAR}")
		require.ErrorContains(t, err, `required variable "PROBE_VAR" is not set`)
		cfg, err := captureConfig(t, "--probe-url=${PROBE_VAR}")
		require.NoError(t, err)
		_, err = cfg.String("probe-url")
		require.ErrorContains(t, err, `required variable "PROBE_VAR" is not set`)
	})

	t.Run("a missing config file is ignored", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		t.Setenv("UPTERMD_PROBE_URL", "from-env")
		cfg, err := captureConfig(t, "--config", filepath.Join(t.TempDir(), "missing.yaml"))
		require.NoError(t, err)
		got, err := cfg.String("probe-url")
		require.NoError(t, err)
		require.Equal(t, "from-env", got)
	})

	t.Run("a bool flag", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		cfg, err := captureConfig(t)
		require.NoError(t, err)
		on, err := cfg.Bool("probe-on")
		require.NoError(t, err)
		require.False(t, on)

		t.Setenv("PROBE_ON", "true")
		t.Setenv("UPTERMD_PROBE_ON", "${PROBE_ON}")
		cfg, err = captureConfig(t)
		require.NoError(t, err)
		on, err = cfg.Bool("probe-on")
		require.NoError(t, err)
		require.True(t, on)

		cfg, err = captureConfig(t, "--probe-on=false")
		require.NoError(t, err)
		on, err = cfg.Bool("probe-on")
		require.NoError(t, err)
		require.False(t, on)
	})

	t.Run("only the extension's own flags", func(t *testing.T) {
		resetUptermdEnv(t)
		unsetEnv(t, probeEnv...)
		cfg, err := captureConfig(t)
		require.NoError(t, err)
		for _, name := range []string{"node-addr", "config", "help", "absent"} {
			_, err := cfg.String(name)
			require.EqualError(t, err, name+" is not a flag of extension probe")
			_, err = cfg.Bool(name)
			require.EqualError(t, err, name+" is not a flag of extension probe")
		}
	})
}

func TestConfigForInsideASubcommand(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug %v", debug), func(t *testing.T) {
			resetUptermdEnv(t)
			unsetEnv(t, probeEnv...)
			args := []string{"--node-addr=n1:2223", "--node-id=machine-1", "--deny-source=203.0.113.0/24", "--probe-url=x"}
			if debug {
				args = append(args, "--debug")
			}
			want, err := unmarshalForTest(t, slices.DeleteFunc(slices.Clone(args), func(a string) bool { return strings.HasPrefix(a, "--probe-url") })...)
			require.NoError(t, err)

			var (
				got  *Config
				news int
			)
			ext := &Extension{
				Name:  "probe",
				Flags: probeFlags,
				Commands: func() []*cobra.Command {
					return []*cobra.Command{{Use: "probe", RunE: func(c *cobra.Command, _ []string) error {
						cfg, err := ConfigFor(c)
						got = &cfg
						return err
					}}}
				},
				New: func(context.Context, Config) (server.Extensions, error) {
					news++
					return server.Extensions{}, nil
				},
			}
			require.NoError(t, execute(context.Background(), RootWith(ext), append([]string{"probe"}, args...)...))
			require.NotNil(t, got)
			require.Zero(t, news, "a subcommand built the extensions")
			require.Equal(t, want, got.Opt)
			require.Equal(t, "machine-1", got.NodeID)
			require.Empty(t, got.BootID)
			require.Empty(t, got.Opt.BootID)
			url, err := got.String("probe-url")
			require.NoError(t, err)
			require.Equal(t, "x", url)
			require.NotNil(t, got.Logger)
			require.Equal(t, debug, got.Logger.Enabled(context.Background(), slog.LevelDebug))
		})
	}
}

func TestNewErrorFailsStartupAndNamesTheExtension(t *testing.T) {
	resetUptermdEnv(t)
	addr := freeAddr(t)
	cmd := RootWith(&Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
		return server.Extensions{}, errors.New("boom")
	}})
	err := execute(context.Background(), cmd, "--ssh-addr", addr)
	require.EqualError(t, err, "uptermd: extension probe: boom")
	requireRefused(t, addr)
}

func TestNewRunsOnceWithResolvedConfigBeforeAnyListener(t *testing.T) {
	resetUptermdEnv(t)
	t.Setenv("PROBE_NODE", "node.internal:2223")
	t.Setenv("UPTERMD_NODE_ADDR", "${PROBE_NODE}")
	t.Setenv("KEY_DIR", "/keys")
	path := filepath.Join(t.TempDir(), "uptermd.yaml")
	require.NoError(t, os.WriteFile(path, []byte("authorized-keys: [\"${KEY_DIR}/hosts\"]\n"), 0o600))
	addr := freeAddr(t)

	// New records what it saw and ends the run with errCaptured, so nothing
	// after it runs and the outcome can't depend on what the server would do.
	var (
		calls       int
		got         Config
		ctxLogger   bool
		listenedYet error
	)
	cmd := RootWith(&Extension{Name: "probe", New: func(ctx context.Context, cfg Config) (server.Extensions, error) {
		calls++
		got = cfg
		ctxLogger = uptermctx.Logger(ctx) != nil
		conn, err := net.DialTimeout("tcp4", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			listenedYet = fmt.Errorf("%s accepted a dial before New returned", addr)
		}
		return server.Extensions{}, errCaptured
	}})
	err := execute(context.Background(), cmd, "--config", path, "--ssh-addr", addr, "--handshake-timeout=4s")
	require.EqualError(t, err, "uptermd: extension probe: "+errCaptured.Error())
	require.ErrorIs(t, err, errCaptured)
	require.Equal(t, 1, calls)
	require.NotNil(t, got.Logger, "New ran before logging was ready")
	require.True(t, ctxLogger, "New's context carries no logger")
	require.NoError(t, listenedYet)
	require.Equal(t, "node.internal:2223", got.Opt.NodeAddr)
	require.Equal(t, []string{"/keys/hosts"}, got.Opt.AuthorizedKeysFiles)
	require.Equal(t, addr, got.Opt.SSHAddr)
	require.Equal(t, 4*time.Second, got.Opt.HandshakeTimeout)
	requireRefused(t, addr)
}

// uuidV4 is a version 4 UUID in canonical form.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestBootIDIsAFreshUUIDPerRun(t *testing.T) {
	resetUptermdEnv(t)
	var ids []string
	for range 2 {
		cfg, err := captureConfig(t, "--node-id=machine-1")
		require.NoError(t, err)
		require.Regexp(t, uuidV4, cfg.BootID)
		require.Equal(t, cfg.BootID, cfg.Opt.BootID)
		require.Equal(t, "machine-1", cfg.NodeID)
		require.Equal(t, "machine-1", cfg.Opt.NodeID)
		ids = append(ids, cfg.BootID)
	}
	require.NotEqual(t, ids[0], ids[1])
}

func TestNodeIDGrammar(t *testing.T) {
	for _, id := range []string{"", "machine-1", "a.b_C-9", strings.Repeat("a", 128)} {
		t.Run(fmt.Sprintf("accepts %.20q", id), func(t *testing.T) {
			resetUptermdEnv(t)
			opt, err := unmarshalForTest(t, "--node-id="+id)
			require.NoError(t, err)
			require.Equal(t, id, opt.NodeID)
			require.NoError(t, opt.Validate())
		})
	}
	for _, id := range []string{strings.Repeat("a", 129), "a b", "ä", "a/b", "a:b"} {
		t.Run(fmt.Sprintf("refuses %.20q", id), func(t *testing.T) {
			resetUptermdEnv(t)
			opt, err := unmarshalForTest(t, "--node-id="+id)
			require.NoError(t, err)
			require.EqualError(t, opt.Validate(), fmt.Sprintf(`--node-id %q: use at most 128 letters, digits, '.', '_' and '-'`, id))
		})
	}
	t.Run("from the environment", func(t *testing.T) {
		resetUptermdEnv(t)
		t.Setenv("MACHINE", "d891")
		t.Setenv("UPTERMD_NODE_ID", "${MACHINE}")
		opt, err := unmarshalForTest(t)
		require.NoError(t, err)
		require.Equal(t, "d891", opt.NodeID)
	})
}

// panicValue is what fn panics with, failing the test if it doesn't.
func panicValue(t *testing.T, fn func()) (v any) {
	t.Helper()
	defer func() { v = recover() }()
	fn()
	t.Fatal("did not panic")
	return nil
}

func TestExtensionNameCollisionsPanic(t *testing.T) {
	for _, name := range []string{"ssh-addr", "config", "node-id", "deny-source", "help"} {
		t.Run("flag "+name, func(t *testing.T) {
			v := panicValue(t, func() {
				RootWith(&Extension{Name: "probe", Flags: func(fs *pflag.FlagSet) { fs.String(name, "", "") }})
			})
			require.Contains(t, fmt.Sprint(v), fmt.Sprintf("%q", name))
		})
	}
	for _, name := range []string{"version", "help", "completion"} {
		t.Run("command "+name, func(t *testing.T) {
			v := panicValue(t, func() {
				RootWith(&Extension{Name: "probe", Commands: func() []*cobra.Command { return []*cobra.Command{{Use: name}} }})
			})
			require.Contains(t, fmt.Sprint(v), fmt.Sprintf("%q", name))
		})
	}
	t.Run("New without a name", func(t *testing.T) {
		panicValue(t, func() {
			RootWith(&Extension{New: func(context.Context, Config) (server.Extensions, error) { return server.Extensions{}, nil }})
		})
	})
	// Names nothing else uses are taken.
	cmd := RootWith(&Extension{Name: "probe", Flags: probeFlags, Commands: func() []*cobra.Command { return []*cobra.Command{{Use: "probe"}} }})
	require.NotNil(t, cmd.PersistentFlags().Lookup("probe-url"))
	found, _, err := cmd.Find([]string{"probe"})
	require.NoError(t, err)
	require.Equal(t, "probe", found.Name())
}

func TestBadDenySourceFailsStartup(t *testing.T) {
	resetUptermdEnv(t)
	addr := freeAddr(t)
	err := execute(context.Background(), Root(), "--ssh-addr", addr, "--deny-source=203.0.113.0/24", "--deny-source=300.1.1.1")
	require.ErrorContains(t, err, `--deny-source "300.1.1.1": not an IP address or CIDR`)
	requireRefused(t, addr)

	// The environment takes a comma-separated list.
	t.Setenv("UPTERMD_DENY_SOURCE", "203.0.113.0/24,2001:db8::/32,192.0.2.7")
	opt, err := unmarshalForTest(t)
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.0/24", "2001:db8::/32", "192.0.2.7"}, opt.DenySources)
	require.NoError(t, opt.Validate())
	t.Setenv("UPTERMD_DENY_SOURCE", "203.0.113.0/24,nope")
	opt, err = unmarshalForTest(t)
	require.NoError(t, err)
	require.EqualError(t, opt.Validate(), `--deny-source "nope": not an IP address or CIDR`)
}

func TestBadNodeIDOrDenySourcePrecedesNew(t *testing.T) {
	for _, tc := range []struct{ arg, want string }{
		{"--node-id=a b", `uptermd: --node-id "a b": use at most 128 letters, digits, '.', '_' and '-'`},
		{"--deny-source=300.1.1.1", `uptermd: --deny-source "300.1.1.1": not an IP address or CIDR`},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			resetUptermdEnv(t)
			addr := freeAddr(t)
			calls := 0
			cmd := RootWith(&Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
				calls++
				return server.Extensions{}, errCaptured
			}})
			require.EqualError(t, execute(context.Background(), cmd, "--ssh-addr", addr, tc.arg), tc.want)
			require.Zero(t, calls, "New ran with a configuration uptermd refuses")
			requireRefused(t, addr)
		})
	}
}

func TestDecodeErrorPrecedesNew(t *testing.T) {
	resetUptermdEnv(t)
	unsetEnv(t, "ABSENT_NODE")
	cmd := RootWith(&Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
		t.Fatal("New ran before decoding succeeded")
		return server.Extensions{}, nil
	}})
	require.ErrorContains(t, execute(context.Background(), cmd, "--node-addr=${ABSENT_NODE}"), "required variable")
}
