package command

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// testExtension is an extension with three host flags: test-service, bound,
// whose Validate refuses "bad"; test-delegate, per run; and test-hidden,
// hidden. Its Prepare is prepare.
func testExtension(prepare func(context.Context, HostOptions) (Prepared, error)) *Extension {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("test-service", "", "The service the test extension uses.")
	fs.Bool("test-delegate", false, "Delegate the run.")
	fs.String("test-hidden", "", "Not in help.")
	return &Extension{
		Name: "test",
		HostFlags: []HostFlag{
			{Flag: fs.Lookup("test-service"), Validate: func(v any) error {
				if v == "bad" {
					return errors.New("the test extension doesn't know that service")
				}
				return nil
			}},
			{Flag: fs.Lookup("test-delegate"), PerRun: true},
			{Flag: fs.Lookup("test-hidden"), Hidden: true},
		},
		Prepare: prepare,
	}
}

// errStop is what a test's Prepare ends the run with, once it has seen
// what it was asked with.
var errStop = errors.New("stopped by the test")

// preparedWith is a Prepare that records what it was asked with, and ends
// the run.
func preparedWith(got *HostOptions) func(context.Context, HostOptions) (Prepared, error) {
	return func(_ context.Context, o HostOptions) (Prepared, error) {
		*got = o
		return Prepared{}, errStop
	}
}

// commandDump is everything a command tree shows of itself: each command's
// texts, annotations and flags, and its help as it prints it.
func commandDump(t *testing.T, root *cobra.Command) string {
	t.Helper()
	var b strings.Builder
	for _, c := range allCommands(root) {
		fmt.Fprintf(&b, "== %s\nuse=%q short=%q aliases=%q hidden=%v runnable=%v deprecated=%q\nlong=%q\nexample=%q\n",
			c.CommandPath(), c.Use, c.Short, c.Aliases, c.Hidden, c.Runnable(), c.Deprecated, c.Long, c.Example)
		keys := make([]string, 0, len(c.Annotations))
		for k := range c.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "annotation %s=%q\n", k, c.Annotations[k])
		}
		for _, fs := range []*pflag.FlagSet{c.LocalFlags(), c.PersistentFlags(), c.InheritedFlags()} {
			fs.VisitAll(func(f *pflag.Flag) {
				var ann []string
				for k, v := range f.Annotations {
					ann = append(ann, k+"="+strings.Join(v, ","))
				}
				sort.Strings(ann)
				fmt.Fprintf(&b, "flag --%s -%s type=%s def=%q noopt=%q hidden=%v deprecated=%q usage=%q ann=%q\n",
					f.Name, f.Shorthand, f.Value.Type(), f.DefValue, f.NoOptDefVal, f.Hidden, f.Deprecated, f.Usage, ann)
			})
		}
		var help bytes.Buffer
		c.SetOut(&help)
		c.SetErr(&help)
		require.NoError(t, c.Help())
		fmt.Fprintf(&b, "help:\n%s\n", help.String())
	}
	return b.String()
}

func TestRootWithNilIsRootForTheCLI(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	// These two hold by construction, as Root is RootWith(nil) and cliRoot
	// cliRootWith(nil): they guard that staying so. That the public CLI's
	// help is still what it was is guarded by the generated docs and man
	// pages, which make docs regenerates from Root; no CI job checks that
	// they are up to date, so a change to them shows in review alone.
	require.Equal(t, commandDump(t, Root()), commandDump(t, RootWith(nil)))
	require.Equal(t, commandDump(t, cliRoot()), commandDump(t, cliRootWith(nil)))

	// A dry run: upterm version, as Main and MainWith(nil) run it.
	run := func(root func() *cobra.Command) (string, string, int) {
		stdout, stderr, code, _ := runCLIRoot(t, root, "version", "-o", "json")
		return stdout, stderr, code
	}
	stdout, stderr, code := run(cliRoot)
	require.Equal(t, 0, code, stderr)
	wantOut, wantErr, wantCode := stdout, stderr, code
	stdout, stderr, code = run(func() *cobra.Command { return mainRoot(nil) })
	require.Equal(t, []any{wantOut, wantErr, wantCode}, []any{stdout, stderr, code})

	// An extension with nothing in it changes nothing but its name.
	require.Equal(t, commandDump(t, Root()), commandDump(t, RootWith(&Extension{Name: "empty"})))
}

// The tree's configured with an extension's flags: they are upterm host's,
// marked per run and hidden as asked, and config's help lists the per-run
// one.
func TestHostFlagsAreRegisteredAsTheirHostFlagSays(t *testing.T) {
	root := RootWith(testExtension(nil))
	hostCmd, _, err := root.Find([]string{"host"})
	require.NoError(t, err)
	fs := hostCmd.PersistentFlags()
	for _, name := range []string{"test-service", "test-delegate", "test-hidden"} {
		require.NotNil(t, fs.Lookup(name), name)
		require.Equal(t, []string{"test"}, fs.Lookup(name).Annotations[annotationExtension], name)
	}
	require.True(t, hasAnnotation(fs.Lookup("test-delegate"), annotationPerRun))
	require.False(t, hasAnnotation(fs.Lookup("test-service"), annotationPerRun))
	require.True(t, fs.Lookup("test-hidden").Hidden)
	require.False(t, fs.Lookup("test-service").Hidden)

	config, _, err := root.Find([]string{"config"})
	require.NoError(t, err)
	require.Regexp(t, `(?s)\n  host: [^:]*--test-delegate\n  join:`, config.Long)

	// A name upterm uses, or no name, is refused when the tree is built.
	for name, ext := range map[string]*Extension{
		"no name":      {},
		"a bad name":   {Name: "Test"},
		"a host flag":  {Name: "x", HostFlags: []HostFlag{{Flag: &pflag.Flag{Name: "server", Value: newStringValue()}}}},
		"a shorthand":  {Name: "x", HostFlags: []HostFlag{{Flag: &pflag.Flag{Name: "x-flag", Shorthand: "r", Value: newStringValue()}}}},
		"a command":    {Name: "x", Commands: func() []*cobra.Command { return []*cobra.Command{{Use: "join"}} }},
		"cobra's help": {Name: "x", Commands: func() []*cobra.Command { return []*cobra.Command{{Use: "help"}} }},
	} {
		require.Panics(t, func() { RootWith(ext) }, name)
	}
}

func newStringValue() pflag.Value {
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)
	fs.String("v", "", "")
	return fs.Lookup("v").Value
}

func TestHostFlagsBindUnderTheExtensionsMapping(t *testing.T) {
	run := func(t *testing.T, config string, args ...string) (HostOptions, string, int) {
		t.Helper()
		restoreFlags(t)
		inProcessHostEnv(t)
		withConfig(t, config)
		var got HostOptions
		_, stderr, code := runCLIWith(t, testExtension(preparedWith(&got)), append([]string{"host", "--detach", "--accept"}, args...)...)
		return got, stderr, code
	}

	t.Run("command line", func(t *testing.T) {
		got, stderr, _ := run(t, "extensions: {test: {test-service: x}}\n", "--test-service", "cli", "--proxy", "http://user:hunter2@proxy.example:3128", "--", "true")
		require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
		require.Equal(t, FlagValue{Value: "cli", Source: SourceCommandLine}, got.Extension["test-service"])
		// A proxy's URL can hold its credentials, so Prepare isn't told it.
		require.Equal(t, FlagValue{Value: "", Source: SourceCommandLine}, got.Flags["proxy"])
	})
	t.Run("env", func(t *testing.T) {
		t.Setenv("UPTERM_TEST_SERVICE", "env")
		got, stderr, _ := run(t, "extensions: {test: {test-service: x}}\n", "--", "true")
		require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
		require.Equal(t, FlagValue{Value: "env", Source: SourceEnv}, got.Extension["test-service"])
	})
	t.Run("config", func(t *testing.T) {
		got, stderr, _ := run(t, "extensions: {test: {test-service: x}, other: {anything: 1}}\n", "--", "true")
		require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
		require.Equal(t, FlagValue{Value: "x", Source: SourceConfig}, got.Extension["test-service"])
		require.NotContains(t, got.Flags, "test-service", "an extension's flag is among upterm's own")
	})
	t.Run("default", func(t *testing.T) {
		got, _, _ := run(t, "", "--", "true")
		require.Equal(t, FlagValue{Value: "", Source: SourceDefault}, got.Extension["test-service"])
	})

	path := func() string { return utils.UptermConfigFilePath() }
	t.Run("a top-level key is unknown", func(t *testing.T) {
		_, stderr, code := run(t, "test-service: x\n", "--", "true")
		require.Equal(t, 1, code)
		require.Equal(t, fmt.Sprintf("upterm: unknown config key %q in %s; remove it or correct the spelling\n", "test-service", path()), stderr)
	})
	t.Run("an unknown key in its entry", func(t *testing.T) {
		_, stderr, code := run(t, "extensions: {test: {nope: 1}}\n", "--", "true")
		require.Equal(t, 1, code)
		require.Equal(t, fmt.Sprintf("upterm: unknown config key %q in %s; remove it or correct the spelling\n", "extensions.test.nope", path()), stderr)

		// Whichever command reads the file.
		_, stderr, code = runCLIWith(t, testExtension(nil), "session", "list")
		require.NotEqual(t, 0, code)
		require.Contains(t, stderr, `unknown config key "extensions.test.nope"`)
	})
	t.Run("config edit checks the entry", func(t *testing.T) {
		restoreFlags(t)
		setupSessionRoots(t)
		withConfig(t, "extensions: {test: {test-service: bad, nope: 1, test-delegate: true}}\n")
		t.Setenv("VISUAL", "true")
		_, stderr, code := runCLIWith(t, testExtension(nil), "config", "edit")
		require.Equal(t, 1, code)
		require.Equal(t, "upterm: ignoring the extensions.test.test-delegate key in "+path()+"; pass --test-delegate\n"+
			"upterm: "+path()+": unknown key \"extensions.test.nope\"; run upterm config edit to fix it\n"+
			"upterm: "+path()+": extensions.test.test-service: the test extension doesn't know that service; run upterm config edit to fix it\n", stderr)

		// A build without it checks nothing inside the entry.
		_, stderr, code = runCLI(t, "config", "edit")
		require.Equal(t, 0, code, stderr)
	})
	t.Run("config view names only the entries this build lacks", func(t *testing.T) {
		restoreFlags(t)
		setupSessionRoots(t)
		withConfig(t, "extensions: {test: {test-service: x}, other: {a: 1}}\n")
		_, stderr, code := runCLIWith(t, testExtension(nil), "config", "view")
		require.Equal(t, 0, code)
		require.Equal(t, "upterm: config.yaml holds settings for extensions this build doesn't have: other\n", stderr)
	})
}

func TestPerRunHostFlagIgnoresEnvAndConfig(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "extensions: {test: {test-delegate: true}}\n")
	t.Setenv("UPTERM_TEST_DELEGATE", "true")
	var got HostOptions
	_, stderr, code := runCLIWith(t, testExtension(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: ignoring UPTERM_TEST_DELEGATE; pass --test-delegate\n"+
		"upterm: ignoring the extensions.test.test-delegate key in "+utils.UptermConfigFilePath()+"; pass --test-delegate\n"+
		"upterm: "+errStop.Error()+"\n", stderr)
	require.Equal(t, FlagValue{Value: "false", Source: SourceDefault}, got.Extension["test-delegate"])

	// The command line still sets it.
	_, _, _ = runCLIWith(t, testExtension(preparedWith(&got)), "host", "--detach", "--accept", "--test-delegate", "--", "true")
	require.Equal(t, FlagValue{Value: "true", Source: SourceCommandLine}, got.Extension["test-delegate"])
}

func TestWriteConfigValueKeepsTheRestOfTheFile(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	const before = `# upterm's config
server: ssh://relay.example:22 # the team's relay
extensions:
  other:
    anything: 1
  test:
    # what the test extension uses
    test-service: old # keep this
read-only: true
`
	withConfig(t, before)
	path := utils.UptermConfigFilePath()
	old, err := os.Stat(path)
	require.NoError(t, err)
	// On Windows a FileInfo's file ID is read by its path the first time
	// SameFile needs it, so old's is read now, before the file is replaced:
	// read later, it would be the replacement's.
	require.True(t, os.SameFile(old, old))

	ext := testExtension(nil)
	require.NoError(t, WriteConfigValue(ext, "test-service", "new"))
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, strings.Replace(before, "test-service: old", "test-service: new", 1), string(content))
	now, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, os.SameFile(old, now), "the file was written in place, not renamed into it")
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), now.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "a temporary file was left behind")

	// What it wrote is what a run reads.
	var got HostOptions
	_, _, _ = runCLIWith(t, testExtension(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
	require.Equal(t, FlagValue{Value: "new", Source: SourceConfig}, got.Extension["test-service"])

	// A file without the mapping gains it, after what it has.
	withConfig(t, "# mine\nread-only: true\n")
	require.NoError(t, WriteConfigValue(ext, "test-service", "x"))
	content, err = os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "# mine\nread-only: true\nextensions:\n  test:\n    test-service: x\n", string(content))

	// No file at all is one with only the entry.
	require.NoError(t, os.Remove(utils.UptermConfigFilePath()))
	require.NoError(t, WriteConfigValue(ext, "test-service", "z"))
	content, err = os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "extensions:\n  test:\n    test-service: z\n", string(content))

	// Only a flag the entry binds.
	for key, want := range map[string]string{
		"test-delegate": "test-delegate is not a setting of extension test",
		"nope":          "nope is not a setting of extension test",
		"read-only":     "read-only is not a setting of extension test",
	} {
		require.EqualError(t, WriteConfigValue(ext, key, true), want)
	}
	require.EqualError(t, WriteConfigValue(ext, "test-service", "bad"), "the test extension doesn't know that service")
	content, err = os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "extensions:\n  test:\n    test-service: z\n", string(content), "a refused write changed the file")
}

// keysServer is an HTTPS server that counts the connections made to it.
func keysServer(t *testing.T) (url string, conns *atomic.Int32) {
	t.Helper()
	conns = &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no keys here", http.StatusNotFound)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Config.ErrorLog = nil
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, conns
}

func TestPrepareRunsBeforeAnyNetworkOrNameWork(t *testing.T) {
	run := func(t *testing.T, prepare func(context.Context, HostOptions) (Prepared, error)) (stderr string, code, draws, spawns int, conns int32, knownHostsChanged bool) {
		t.Helper()
		restoreFlags(t)
		dir := inProcessHostEnv(t)
		url, seen := keysServer(t)
		knownHosts := filepath.Join(dir, "known_hosts")
		const lines = "relay.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
		require.NoError(t, os.WriteFile(knownHosts, []byte(lines), 0o600))
		origDraw := drawName
		t.Cleanup(func() { drawName = origDraw })
		drawName = func(command []string) string {
			draws++
			return origDraw(command)
		}
		spawned := countSpawns(t)

		_, stderr, code = runCLIWith(t, testExtension(prepare), "host", "--detach", "--accept", "--server", "ssh://127.0.0.1:1",
			"--known-hosts", knownHosts, "--authorized-user", url+"/alice", "--", "true")
		content, err := os.ReadFile(knownHosts)
		require.NoError(t, err)
		return stderr, code, draws, *spawned, seen.Load(), string(content) != lines
	}

	stderr, code, draws, spawns, conns, changed := run(t, func(context.Context, HostOptions) (Prepared, error) {
		return Prepared{}, errors.New("this run can't be hosted here\nask your administrator\x1b[2J")
	})
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: this run can't be hosted here\nask your administrator\uFFFD[2J\n", stderr)
	require.Zero(t, draws, "a name was drawn")
	require.Zero(t, spawns, "a session process was started")
	require.Zero(t, conns, "a user's keys were fetched")
	require.False(t, changed, "known_hosts changed")

	// The control: an ordinary run that Prepare lets through does each of
	// those, so their counters count.
	_, _, draws, spawns, _, _ = run(t, func(context.Context, HostOptions) (Prepared, error) { return Prepared{}, nil })
	require.Equal(t, 1, draws)
	require.Equal(t, 1, spawns)
}

// A delegated run's checks skip only --server and the default
// --known-hosts, which its placement replaces.
func TestADelegatedRunSkipsOnlyTheRelaysChecks(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	spawns := countSpawns(t)
	delegate := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil })
	delegate.Broker = unusedBroker

	_, stderr, _ := runCLIWith(t, delegate, "host", "--detach", "--accept", "--server", "ftp://nowhere", "--", "true")
	require.NotContains(t, stderr, "unsupported server protocol")
	require.Equal(t, 1, *spawns)

	_, stderr, code := runCLIWith(t, delegate, "host", "--detach", "--accept", "--server", "ftp://nowhere", "--join-timeout", "-1s", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: --join-timeout cannot be negative; use 0 to wait forever\n", stderr)

	// With no home directory to find the default --known-hosts in.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	*spawns = 0
	_, stderr, _ = runCLIWith(t, delegate, "host", "--detach", "--accept", "--", "true")
	require.NotContains(t, stderr, "home directory")
	require.Equal(t, 1, *spawns)

	// An ordinary run checks them both.
	ordinary := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{}, nil })
	_, stderr, _ = runCLIWith(t, ordinary, "host", "--detach", "--accept", "--server", "ftp://nowhere", "--", "true")
	require.Contains(t, stderr, "unsupported server protocol ftp")
	require.Contains(t, stderr, "can't find your home directory for the default --known-hosts")
}

// A --name that NormalizeName makes no session name, empty included, is
// refused as a drawn one would be, before a name is drawn or anything
// started; a session name it makes is claimed.
func TestANormalizedNameMustBeASessionName(t *testing.T) {
	run := func(t *testing.T, normalized string) (stderr string, code, draws int, claimed []string) {
		t.Helper()
		restoreFlags(t)
		inProcessHostEnv(t)
		origDraw := drawName
		t.Cleanup(func() { drawName = origDraw })
		drawName = func(command []string) string {
			draws++
			return origDraw(command)
		}
		origSpawn := hostSpawn
		t.Cleanup(func() { hostSpawn = origSpawn })
		hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
			claimed = append(claimed, so.name)
			return nil, nil, errors.New("no session process in this test")
		}
		ext := testExtension(func(context.Context, HostOptions) (Prepared, error) {
			return Prepared{NormalizeName: func(string) (string, error) { return normalized, nil }}, nil
		})
		_, stderr, code = runCLIWith(t, ext, "host", "--detach", "--accept", "--server", "ssh://127.0.0.1:1", "--name", "Work", "--", "true")
		return stderr, code, draws, claimed
	}

	for _, normalized := range []string{"", "wo rk"} {
		t.Run(fmt.Sprintf("%q", normalized), func(t *testing.T) {
			stderr, code, draws, claimed := run(t, normalized)
			require.Equal(t, 1, code)
			require.Equal(t, "upterm: "+sessiondir.ValidateName(normalized).Error()+"\n", stderr)
			require.Zero(t, draws, "a name was drawn")
			require.Empty(t, claimed, "a session process was started")
		})
	}

	_, _, draws, claimed := run(t, "work")
	require.Zero(t, draws)
	require.Equal(t, []string{"work"}, claimed)
}

func TestNormalizedNamesAreClaimed(t *testing.T) {
	normalize := func(name string) (string, error) {
		if strings.HasPrefix(name, "Refused") {
			return "", errors.New("that name isn't allowed here\nchoose another")
		}
		return strings.ToLower(name), nil
	}
	ext := func() *Extension {
		return testExtension(func(context.Context, HostOptions) (Prepared, error) {
			return Prepared{NormalizeName: normalize}, nil
		})
	}
	claimed := func(t *testing.T, args ...string) ([]string, string, int) {
		t.Helper()
		restoreFlags(t)
		inProcessHostEnv(t)
		orig := hostSpawn
		t.Cleanup(func() { hostSpawn = orig })
		var names []string
		hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
			names = append(names, so.name)
			return nil, nil, errors.New("no session process in this test")
		}
		_, stderr, code := runCLIWith(t, ext(), append([]string{"host", "--detach", "--accept", "--server", "ssh://127.0.0.1:1"}, args...)...)
		return names, stderr, code
	}

	names, _, _ := claimed(t, "--", "R")
	require.Len(t, names, 1)
	require.Regexp(t, `^r-[0-9a-f]{4}$`, names[0])

	names, _, _ = claimed(t, "--name", "Work", "--", "R")
	require.Equal(t, []string{"work"}, names)

	names, stderr, code := claimed(t, "--name", "Refused", "--", "R")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: that name isn't allowed here\nchoose another\n", stderr)
	require.Empty(t, names)

	names, stderr, code = claimed(t, "--", "Refused")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: that name isn't allowed here\nchoose another\n", stderr)
	require.Empty(t, names)

	// Every redraw too, each checked as a session name.
	var runs []string
	draws := []string{"A-0001", "B-0002"}
	err := runWithNormalizedNames(discardLogger(), "", func() string { d := draws[0]; draws = draws[1:]; return d }, normalize, func(name string) error {
		runs = append(runs, name)
		if len(runs) == 1 {
			return &host.NameTakenError{Text: "taken there"}
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"a-0001", "b-0002"}, runs)
	err = runWithNormalizedNames(discardLogger(), "", func() string { return "x" }, func(string) (string, error) { return "a/b", nil },
		func(string) error { t.Fatal("ran under an invalid name"); return nil })
	require.EqualError(t, err, sessiondir.ValidateName("a/b").Error())
}

// inProcessDelegatedDaemons is inProcessDaemons for a delegated run: each
// session process reads the handoff it was started with, as its pre-run
// does, and runs as runDaemon runs it, with ext.
func inProcessDelegatedDaemons(t *testing.T, ext *Extension, command []string) {
	t.Helper()
	orig := hostSpawn
	t.Cleanup(func() { hostSpawn = orig })
	var daemons sync.WaitGroup
	t.Cleanup(daemons.Wait)
	hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
		var d *daemonHandoffState
		if so.handoff != "" {
			d = readHandoff(so.handoff)
		}
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		daemons.Add(1)
		go func() {
			defer daemons.Done()
			_ = runDaemon(context.Background(), discardLogger(), ext, d, command, a, so.name)
			_ = a.Close()
		}()
		return b, nil, nil
	}
}

func TestFactoryErrorIsVerbatim(t *testing.T) {
	delegated := func(broker func(context.Context, Handoff) (host.Broker, error)) *Extension {
		ext := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil })
		ext.Broker = broker
		return ext
	}
	seeLog := func() string { return regexp.QuoteMeta("\n(see " + utils.UptermLogFilePath() + ")\n") }

	t.Run("the factory's", func(t *testing.T) {
		restoreFlags(t)
		inProcessHostEnv(t)
		ext := delegated(func(context.Context, Handoff) (host.Broker, error) { return nil, errors.New("no login here") })
		inProcessDelegatedDaemons(t, ext, []string{"true"})
		_, stderr, code := runCLIWith(t, ext, "host", "--detach", "--accept", "--", "true")
		require.Equal(t, 1, code)
		require.Regexp(t, "^upterm: no login here"+seeLog()+"$", stderr)
	})

	t.Run("Place's", func(t *testing.T) {
		restoreFlags(t)
		inProcessHostEnv(t)
		ext := delegated(func(context.Context, Handoff) (host.Broker, error) {
			return placeFunc(func(context.Context, host.Run) (host.Placement, error) {
				return host.Placement{}, errors.New("refused where it was placed\nsee the console\x1b[2J")
			}), nil
		})
		inProcessDelegatedDaemons(t, ext, []string{"true"})
		_, stderr, code := runCLIWith(t, ext, "host", "--detach", "--accept", "--", "true")
		require.Equal(t, 1, code)
		require.Regexp(t, "^upterm: refused where it was placed\nsee the console�\\[2J"+seeLog()+"$", stderr)
		require.NotContains(t, stderr, "could not start")
	})
}

// Prepare, the broker factory and an extension's commands are given the
// command's context, whose logger Logger returns.
func TestExtensionCodeGetsTheCommandsContext(t *testing.T) {
	require.NotNil(t, Logger(context.Background()))
	Logger(context.Background()).Error("goes nowhere")

	restoreFlags(t)
	inProcessHostEnv(t)
	var seen []*slog.Logger
	record := func(ctx context.Context) {
		l := uptermctx.Logger(ctx)
		require.NotNil(t, l)
		require.Same(t, l.Logger, Logger(ctx))
		seen = append(seen, Logger(ctx))
	}
	ext := testExtension(func(ctx context.Context, _ HostOptions) (Prepared, error) {
		record(ctx)
		return Prepared{}, errStop
	})
	ext.Commands = func() []*cobra.Command {
		return []*cobra.Command{{Use: "test-login", RunE: func(c *cobra.Command, _ []string) error {
			record(c.Context())
			return nil
		}}}
	}
	_, _, _ = runCLIWith(t, ext, "host", "--detach", "--accept", "--", "true")
	_, stderr, code := runCLIWith(t, ext, "test-login")
	require.Equal(t, 0, code, stderr)
	require.Len(t, seen, 2)
}

// An extension's command that runs, and has commands of its own, still runs
// its own handler; one that only groups its commands answers an unknown one
// as upterm's groups do.
func TestAnExtensionsCommandsWithCommandsOfTheirOwn(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	var ran [][]string
	ext := &Extension{Name: "test", Commands: func() []*cobra.Command {
		runnable := &cobra.Command{Use: "test-run", Args: cobra.MaximumNArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			ran = append(ran, append([]string{"test-run"}, args...))
			return nil
		}}
		group := &cobra.Command{Use: "test-group"}
		for _, parent := range []*cobra.Command{runnable, group} {
			parent.AddCommand(&cobra.Command{Use: "sub", RunE: func(c *cobra.Command, _ []string) error {
				ran = append(ran, []string{c.Parent().Name(), "sub"})
				return nil
			}})
		}
		return []*cobra.Command{runnable, group}
	}}

	for _, args := range [][]string{{"test-run"}, {"test-run", "x"}, {"test-run", "sub"}, {"test-group", "sub"}} {
		ran = nil
		_, stderr, code := runCLIWith(t, ext, args...)
		require.Equal(t, 0, code, stderr)
		require.Equal(t, [][]string{args}, ran)
	}
	ran = nil
	_, stderr, code := runCLIWith(t, ext, "test-run", "x", "y")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "accepts at most 1 arg(s), received 2")
	require.Empty(t, ran)
	stdout, stderr, code := runCLIWith(t, ext, "test-run", "x", "--help")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "upterm test-run [command]")

	// The group, as upterm session does.
	_, want, wantCode := runCLIWith(t, ext, "session", "nope")
	_, stderr, code = runCLIWith(t, ext, "test-group", "nope")
	require.Equal(t, wantCode, code)
	require.Equal(t, strings.ReplaceAll(want, "session", "test-group"), stderr)
	require.Empty(t, ran)
}

// An extension's command that runs, and has commands of its own, gets the
// pre-run every runnable command gets: its flags from the config file and
// the environment, and the run's logger. A group that runs nothing itself
// still reads no config, so a broken file doesn't stop its help.
func TestAnExtensionsRunnableCommandWithCommandsGetsThePreRun(t *testing.T) {
	newExt := func(level *string, logged *[]bool) *Extension {
		return &Extension{Name: "test", Commands: func() []*cobra.Command {
			runnable := &cobra.Command{Use: "test-run", RunE: func(c *cobra.Command, _ []string) error {
				*logged = append(*logged, uptermctx.Logger(c.Context()) != nil)
				Logger(c.Context()).Error("test-run ran", "level", *level)
				return nil
			}}
			runnable.Flags().StringVar(level, "test-level", "default", "")
			runnable.AddCommand(&cobra.Command{Use: "sub", RunE: func(*cobra.Command, []string) error { return nil }})
			group := &cobra.Command{Use: "test-group"}
			group.AddCommand(&cobra.Command{Use: "sub", RunE: func(*cobra.Command, []string) error { return nil }})
			return []*cobra.Command{runnable, group}
		}}
	}
	for name, tc := range map[string]struct{ config, env, want string }{
		"config": {config: "test-level: from-config\n", want: "from-config"},
		"env":    {env: "from-env", want: "from-env"},
	} {
		t.Run(name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			if tc.env != "" {
				t.Setenv("UPTERM_TEST_LEVEL", tc.env)
			}
			var level string
			var logged []bool
			_, stderr, code := runCLIWith(t, newExt(&level, &logged), "test-run")
			require.Equal(t, 0, code, stderr)
			require.Equal(t, tc.want, level)
			require.Equal(t, []bool{true}, logged, "the command ran with no logger of the run's")
			content, err := os.ReadFile(utils.UptermLogFilePath())
			require.NoError(t, err)
			require.Contains(t, string(content), "test-run ran")
			require.Contains(t, string(content), tc.want)
		})
	}

	t.Run("its usage", func(t *testing.T) {
		setupSessionRoots(t)
		withConfig(t, "")
		var level string
		var logged []bool
		stdout, stderr, code := runCLIWith(t, newExt(&level, &logged), "test-run", "--help")
		require.Equal(t, 0, code, stderr)
		require.Contains(t, stdout, "upterm test-run [flags]\n  upterm test-run [command]")
	})

	t.Run("a group", func(t *testing.T) {
		setupSessionRoots(t)
		withConfig(t, "read-only: [nope\n")
		var level string
		var logged []bool
		stdout, stderr, code := runCLIWith(t, newExt(&level, &logged), "test-group")
		require.Equal(t, 0, code, stderr)
		require.Contains(t, stdout, "upterm test-group [command]")
	})
}

func TestUpgradeIsTheExtensions(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	var ran []string
	ext := &Extension{Name: "test", Upgrade: func(c *cobra.Command) error {
		ran = append(ran, c.CommandPath())
		return errors.New("upgrade this build with its own installer")
	}}
	_, stderr, code := runCLIWith(t, ext, "upgrade")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: upgrade this build with its own installer\n", stderr)
	require.Equal(t, []string{"upterm upgrade"}, ran)

	stdout, _, code := runCLI(t, "upgrade", "--help")
	require.Equal(t, 0, code)
	extStdout, _, extCode := runCLIWith(t, ext, "upgrade", "--help")
	require.Equal(t, 0, extCode)
	require.Equal(t, stdout, extStdout)
	require.Contains(t, stdout, "Replace this upterm")
}

// A delegated run's host is built from its settings alone: it resolves no
// user's keys, reads no authorized_keys file, has no relay key check, and is
// told whether its name was drawn.
func TestADelegatedHostResolvesNoKeysAndChecksNoRelayKey(t *testing.T) {
	hostCmd()
	daemonTestRoots(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	child := bootstrap.NewChild(a, nil)
	t.Cleanup(func() { _ = child.Close() })
	url, conns := keysServer(t)
	ref, err := host.ParseUserRef(url + "/alice")
	require.NoError(t, err)
	knownHosts := filepath.Join(t.TempDir(), "no", "such", "dir", "known_hosts")

	s := hostSettingsFromFlags()
	s.AuthorizedKeys = filepath.Join(t.TempDir(), "no-such-file")
	s.KnownHosts = knownHosts
	opts := testHostOptions()
	opts.refs, opts.authorizationRequested, opts.delegated, opts.nameGenerated = []host.UserRef{ref}, true, true, true
	h, err := buildDaemonHost(context.Background(), s, "d", opts, child, discardLogger())
	require.NoError(t, err)
	require.Empty(t, h.AuthorizedKeys)
	require.Nil(t, h.HostKeyCallback)
	require.Nil(t, h.RelayKeyTrusted)
	require.True(t, h.NameGenerated)
	require.Zero(t, conns.Load(), "a user's keys were fetched")
	require.NoDirExists(t, filepath.Dir(knownHosts))

	// The control: an ordinary run with the same settings reads the file.
	opts.delegated = false
	_, err = buildDaemonHost(context.Background(), s, "d", opts, child, discardLogger())
	require.ErrorContains(t, err, "error reading authorized keys file")
}

// A file of comments alone, as config edit creates it from the example, keeps
// every line it had, and gains the entry after them.
func TestWriteConfigValueKeepsACommentOnlyFile(t *testing.T) {
	for name, tc := range map[string]struct{ before, kept string }{
		"the example":         {exampleConfig(), exampleConfig()},
		"one comment":         {"# only a comment\n", "# only a comment\n"},
		"no final newline":    {"# no newline", "# no newline\n"},
		"comments and blanks": {"\n# a\n\n# b\n", "\n# a\n\n# b\n"},
		// A document of null alone holds nothing either: its comments are
		// kept where they were, and the null itself goes.
		"a null":               {"# a\nnull\n", "# a\n"},
		"a tilde with comment": {"# c\n~ # x\n", "# c\n# x\n"},
		"a start after":        {"# a\n---\n", "# a\n---\n"},
		"a start before":       {"---\n# a\n", "---\n# a\n"},
		"a start and example":  {"---\n" + exampleConfig(), "---\n" + exampleConfig()},
		"a byte order mark":    {"\ufeff# c\n", "\ufeff# c\n"},
	} {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			inProcessHostEnv(t)
			withConfig(t, tc.before)
			require.NoError(t, WriteConfigValue(testExtension(nil), "test-service", "kept"))
			content, err := os.ReadFile(utils.UptermConfigFilePath())
			require.NoError(t, err)
			require.Equal(t, tc.kept+"extensions:\n  test:\n    test-service: kept\n", string(content), "the file's lines were lost or moved")

			var got HostOptions
			_, stderr, _ := runCLIWith(t, testExtension(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
			require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
			require.Equal(t, FlagValue{Value: "kept", Source: SourceConfig}, got.Extension["test-service"])
		})
	}
}

// A value no run would take, null, is refused before the file is touched:
// every run would refuse the key that held it.
func TestWriteConfigValueRefusesNoValue(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	const before = "# mine\nread-only: true\n"
	withConfig(t, before)
	for name, value := range map[string]any{"nil": nil, "a nil pointer": (*string)(nil)} {
		t.Run(name, func(t *testing.T) {
			require.EqualError(t, WriteConfigValue(testExtension(nil), "test-service", value), "extensions.test.test-service: config key has no value")
			content, err := os.ReadFile(utils.UptermConfigFilePath())
			require.NoError(t, err)
			require.Equal(t, before, string(content), "a refused value changed the file")
		})
	}
}

// A file of more than one document is refused, and left as it was: only the
// first could be written back.
func TestWriteConfigValueRefusesSeveralDocuments(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	const before = "read-only: true\n---\nserver: ssh://x:22\n"
	withConfig(t, before)
	path := utils.UptermConfigFilePath()
	require.EqualError(t, WriteConfigValue(testExtension(nil), "test-service", "x"),
		path+": the file holds more than one YAML document; "+fixConfig)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, string(content), "a refused file was changed")
}

// A write through a YAML anchor or alias on its way is refused, and the file
// left as it was: the rewrite would drop an anchor an alias elsewhere names,
// or change what an alias shares. Commands read such a file, and config
// edit takes it, so it can be fixed there.
func TestWriteConfigValueRefusesAnchorsAndAliases(t *testing.T) {
	fix := "; " + fixConfig
	for name, tc := range map[string]struct{ before, want string }{
		"an anchored value an alias names": {
			"extensions:\n  test:\n    test-service: &svc old\n  other:\n    anything: *svc\n",
			"extensions.test.test-service has the YAML anchor &svc, which upterm can't keep when it writes there",
		},
		"an anchored value": {
			"extensions:\n  test:\n    test-service: &svc old\n",
			"extensions.test.test-service has the YAML anchor &svc, which upterm can't keep when it writes there",
		},
		"an aliased entry": {
			"extensions:\n  other: &base\n    test-service: old\n  test: *base\n",
			"extensions.test is the YAML alias *base, which upterm can't write through",
		},
		"an anchored entry": {
			"extensions:\n  test: &t\n    test-service: old\n",
			"extensions.test has the YAML anchor &t, which upterm can't keep when it writes there",
		},
		"an anchored extensions mapping": {
			"extensions: &e\n  test:\n    test-service: old\n",
			"extensions has the YAML anchor &e, which upterm can't keep when it writes there",
		},
	} {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			inProcessHostEnv(t)
			withConfig(t, tc.before)
			path := utils.UptermConfigFilePath()

			// A run reads the file, and config edit's check passes it.
			var got HostOptions
			_, stderr, _ := runCLIWith(t, testExtension(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
			require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
			require.Equal(t, FlagValue{Value: "old", Source: SourceConfig}, got.Extension["test-service"])
			errs, _ := checkConfigFileWith(RootWith(testExtension(nil)), path, testExtension(nil))
			require.Empty(t, errs)

			require.EqualError(t, WriteConfigValue(testExtension(nil), "test-service", "new"), path+": "+tc.want+fix)
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, tc.before, string(content), "a refused write changed the file")
		})
	}

	// An anchor elsewhere is no matter.
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "extensions:\n  other: &o\n    anything: 1\n  test:\n    test-service: old\n")
	require.NoError(t, WriteConfigValue(testExtension(nil), "test-service", "new"))
	content, err := os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "extensions:\n  other: &o\n    anything: 1\n  test:\n    test-service: new\n", string(content))
}

// A value the flag itself refuses is never written, whatever Validate says.
func TestWriteConfigValueChecksTheFlagsType(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "read-only: true\n")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Int("test-port", 0, "")
	fs.String("test-service", "", "")
	fs.StringSlice("test-list", nil, "")
	ext := &Extension{Name: "test", HostFlags: []HostFlag{{Flag: fs.Lookup("test-port")}, {Flag: fs.Lookup("test-service")}, {Flag: fs.Lookup("test-list")}}}

	require.ErrorContains(t, WriteConfigValue(ext, "test-port", "abc"), `test-port: cannot use value "abc"`)
	require.ErrorContains(t, WriteConfigValue(ext, "test-service", []any{"a", "b"}), "test-service: expected a single value")
	content, err := os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "read-only: true\n", string(content), "a refused value was written")
	require.Equal(t, "0", fs.Lookup("test-port").Value.String(), "the check set the flag itself")

	require.NoError(t, WriteConfigValue(ext, "test-port", 8080))
	require.Equal(t, "0", fs.Lookup("test-port").Value.String(), "writing the value set the flag itself")
	require.NoError(t, WriteConfigValue(ext, "test-list", []string{"a", "b"}))
	content, err = os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "read-only: true\nextensions:\n  test:\n    test-port: 8080\n    test-list:\n      - a\n      - b\n", string(content))
}

// A config.yaml that is a link is written where it leads, and stays a link.
func TestWriteConfigValueFollowsALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a link needs a privilege Windows grants few accounts")
	}
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "")
	path := utils.UptermConfigFilePath()
	target := filepath.Join(t.TempDir(), "dotfiles", "upterm.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
	require.NoError(t, os.WriteFile(target, []byte("read-only: true\n"), 0o600))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink(target, path))

	require.NoError(t, WriteConfigValue(testExtension(nil), "test-service", "linked"))
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.NotZero(t, fi.Mode()&os.ModeSymlink, "the link was replaced by a file")
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "read-only: true\nextensions:\n  test:\n    test-service: linked\n", string(content))
}

// An ordinary run's session process checks the name its parent handed it,
// which the extension normalized, not the --name its argv still holds.
func TestAnOrdinarySessionProcessChecksTheNameItWasHanded(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	root := RootWith(testExtension(nil))
	host, _, err := root.Find([]string{"host"})
	require.NoError(t, err)
	require.NoError(t, host.ParseFlags([]string{"--name", "Work Space"}))
	require.Equal(t, "Work Space", flagName)

	asDaemon(t)
	t.Setenv(daemonNameEnv, "work-space")
	require.NoError(t, host.PreRunE(host, nil))
	require.Equal(t, "work-space", flagName)

	// A name it was handed that isn't one is still refused.
	t.Setenv(daemonNameEnv, "a/b")
	require.Error(t, host.PreRunE(host, nil))
}

// unusedBroker is the Broker factory of an extension whose runs never reach
// a session process.
func unusedBroker(context.Context, Handoff) (host.Broker, error) {
	return nil, errors.New("no session process in this test")
}

// A run Prepare delegates in a build whose extension has no Broker is
// refused before anything starts.
func TestADelegatedRunNeedsABroker(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	spawns := countSpawns(t)
	ext := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil })
	_, stderr, code := runCLIWith(t, ext, "host", "--detach", "--accept", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: this upterm can't host a delegated run\n", stderr)
	require.Zero(t, *spawns)
}

// delegatedHandoff is the handoff a run of upterm host with args, which
// ext's Prepare delegates, starts its session process with.
func delegatedHandoff(t *testing.T, ext *Extension, args ...string) string {
	t.Helper()
	orig := hostSpawn
	defer func() { hostSpawn = orig }()
	var handoffs []string
	hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
		handoffs = append(handoffs, so.handoff)
		return nil, nil, errors.New("no session process in this test")
	}
	_, stderr, _ := runCLIWith(t, ext, append([]string{"host"}, args...)...)
	require.Len(t, handoffs, 1, stderr)
	require.NotEmpty(t, handoffs[0])
	return handoffs[0]
}

// sessionPreRun runs what a session process, started with handoff and the
// parent's args, runs before upterm host's run: root's pre-run, then upterm
// host's, in a tree composed with ext. handoff is a delegated run's, or ""
// for an ordinary run. It returns upterm host's pre-run's error.
func sessionPreRun(t *testing.T, ext *Extension, handoff string, args ...string) error {
	t.Helper()
	origSupplied, origCommandLine, origRunning := suppliedFlags, commandLineFlags, runningCmd
	t.Cleanup(func() { suppliedFlags, commandLineFlags, runningCmd = origSupplied, origCommandLine, origRunning })
	asDaemon(t)
	t.Setenv(handoffEnv, handoff)
	host, _, err := RootWith(ext).Find([]string{"host"})
	require.NoError(t, err)
	require.NoError(t, host.ParseFlags(args))
	host.SetContext(context.Background())
	require.NoError(t, rootPreRun(host))
	t.Cleanup(func() { _ = uptermctx.Logger(host.Context()).Close() })
	if handoff != "" {
		require.NotNil(t, daemonHandoff, "the session process read no handoff")
		require.NoError(t, daemonHandoff.err)
	}
	return host.PreRunE(host, host.Flags().Args())
}

// An empty --name names nothing: a delegated run draws its name, and tells
// its Broker so, as a run with no --name does.
func TestAnEmptyNameIsNoName(t *testing.T) {
	for name, nameArgs := range map[string][]string{
		"no --name":   nil,
		"--name \"\"": {"--name", ""},
	} {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			inProcessHostEnv(t)
			var runs []host.Run
			ext := func() *Extension {
				e := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil })
				e.Broker = func(context.Context, Handoff) (host.Broker, error) {
					return placeFunc(func(_ context.Context, run host.Run) (host.Placement, error) {
						runs = append(runs, run)
						return host.Placement{}, errors.New("placed nowhere in this test")
					}), nil
				}
				return e
			}
			args := append(append([]string{"--detach", "--accept"}, nameArgs...), "--", "true")
			handoff := delegatedHandoff(t, ext(), args...)

			session := ext()
			require.NoError(t, sessionPreRun(t, session, handoff, args...))
			daemonFailure(t, session, daemonHandoff)
			require.Len(t, runs, 1)
			require.True(t, runs[0].NameGenerated, "the Broker was told the name was given")
		})
	}
}

// everyKind is an extension with a host flag of each kind a setting can
// be, test-<kind>, and prepare as its Prepare.
func everyKind(prepare func(context.Context, HostOptions) (Prepared, error)) *Extension {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("test-string", "", "")
	fs.Bool("test-bool", false, "")
	fs.Int("test-int", 0, "")
	fs.Float64("test-float", 0, "")
	fs.Duration("test-duration", 0, "")
	fs.StringSlice("test-slice", nil, "")
	fs.StringArray("test-array", nil, "")
	fs.IntSlice("test-ints", nil, "")
	fs.StringToString("test-map", nil, "")
	fs.StringToInt("test-intmap", nil, "")
	ext := &Extension{Name: "test", Prepare: prepare}
	fs.VisitAll(func(f *pflag.Flag) { ext.HostFlags = append(ext.HostFlags, HostFlag{Flag: f}) })
	return ext
}

// hostReads is what a run of upterm host prints when it reads config.yaml as
// it is: "upterm: " and errStop when the file is one it takes.
func hostReads(t *testing.T) string {
	t.Helper()
	var got HostOptions
	_, stderr, _ := runCLIWith(t, everyKind(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
	return stderr
}

// A list WriteConfigValue writes is checked as a run reads it back from the
// file, where an empty element is refused.
func TestWriteConfigValueRefusesWhatARunWouldRefuse(t *testing.T) {
	const before = "read-only: true\n"
	for _, key := range []string{"test-slice", "test-array"} {
		for _, elems := range [][]string{{""}, {" "}, {"a", ""}} {
			t.Run(fmt.Sprintf("%s %q", key, elems), func(t *testing.T) {
				restoreFlags(t)
				inProcessHostEnv(t)
				// What a run says of the file the write would leave.
				var file strings.Builder
				enc := yaml.NewEncoder(&file)
				enc.SetIndent(2)
				require.NoError(t, enc.Encode(map[string]any{"read-only": true, "extensions": map[string]any{"test": map[string]any{key: elems}}}))
				withConfig(t, file.String())
				stderr := hostReads(t)
				require.NotEqual(t, "upterm: "+errStop.Error()+"\n", stderr, "the run took the file")

				withConfig(t, before)
				err := WriteConfigValue(everyKind(nil), key, elems)
				require.EqualError(t, err, strings.TrimSuffix(strings.TrimPrefix(stderr, "upterm: "), "\n"))
				content, rerr := os.ReadFile(utils.UptermConfigFilePath())
				require.NoError(t, rerr)
				require.Equal(t, before, string(content), "a refused value changed the file")
			})
		}
	}

	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, before)
	require.NoError(t, WriteConfigValue(everyKind(nil), "test-slice", []string{"a", "b"}))
	var got HostOptions
	_, stderr, _ := runCLIWith(t, everyKind(preparedWith(&got)), "host", "--detach", "--accept", "--", "true")
	require.Equal(t, "upterm: "+errStop.Error()+"\n", stderr)
	require.Equal(t, FlagValue{Value: "[a,b]", Source: SourceConfig}, got.Extension["test-slice"])

	// A flag whose name has a capital: the file's keys are read in lower
	// case, so a run would find no such setting, and refuses the key.
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("test-Level", "", "")
	upper := &Extension{Name: "test", HostFlags: []HostFlag{{Flag: fs.Lookup("test-Level")}}}
	withConfig(t, before)
	require.EqualError(t, WriteConfigValue(upper, "test-Level", "x"), "extensions.test.test-Level: a run can't read this key back from the config file")
	content, err := os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, before, string(content), "a refused value changed the file")
}

// Whatever WriteConfigValue writes, a run reads back: for each kind of
// setting, a value is either refused, the file left as it was, or written
// and taken by upterm host.
func TestWriteConfigValueWritesOnlyWhatARunReads(t *testing.T) {
	const before = "read-only: true\n"
	values := []any{
		"x", "", " ", "a,b", `"q"`, "yes", "1h", "8080", "0.1", "a=1,b=2", "true",
		true, false, 8080, -1, int64(1) << 40, 0.1, 1e-9, time.Second,
		[]string{"a", "b"}, []string{}, []string{"a,b"}, []string{" a"}, []any{"a", 1}, []int{1, 2},
		map[string]string{"a": "b"}, map[string]any{"a": 1}, map[string]int{"a": 1},
	}
	keys := []string{"test-string", "test-bool", "test-int", "test-float", "test-duration", "test-slice", "test-array", "test-ints", "test-map", "test-intmap"}
	accepted := 0
	for _, key := range keys {
		for _, value := range values {
			t.Run(fmt.Sprintf("%s %T %v", key, value, value), func(t *testing.T) {
				restoreFlags(t)
				inProcessHostEnv(t)
				withConfig(t, before)
				if err := WriteConfigValue(everyKind(nil), key, value); err != nil {
					content, rerr := os.ReadFile(utils.UptermConfigFilePath())
					require.NoError(t, rerr)
					require.Equal(t, before, string(content), "a refused value changed the file")
					return
				}
				accepted++
				require.Equal(t, "upterm: "+errStop.Error()+"\n", hostReads(t), "a run refused what was written")
			})
		}
	}
	require.NotZero(t, accepted)
}

// pflag's own struct-backed types are checked as the scalar ones are.
func TestWriteConfigValueChecksPflagsStructTypes(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "read-only: true\n")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.StringArray("test-array", nil, "")
	fs.IntSlice("test-ints", nil, "")
	fs.StringToString("test-map", nil, "")
	ext := &Extension{Name: "test", HostFlags: []HostFlag{{Flag: fs.Lookup("test-array")}, {Flag: fs.Lookup("test-ints")}, {Flag: fs.Lookup("test-map")}}}

	require.ErrorContains(t, WriteConfigValue(ext, "test-array", map[string]any{"a": 1}), "test-array: expected a list")
	require.ErrorContains(t, WriteConfigValue(ext, "test-ints", []any{"x"}), `test-ints: cannot use value "x"`)
	require.ErrorContains(t, WriteConfigValue(ext, "test-map", "noequals"), `test-map: cannot use value "noequals"`)
	content, err := os.ReadFile(utils.UptermConfigFilePath())
	require.NoError(t, err)
	require.Equal(t, "read-only: true\n", string(content), "a refused value was written")

	require.NoError(t, WriteConfigValue(ext, "test-ints", []any{"1", "2"}))
	require.NoError(t, WriteConfigValue(ext, "test-map", "a=1,b=2"))
	require.Equal(t, "[]", fs.Lookup("test-ints").Value.String(), "the check set the flag itself")
}

// mapValue is a pflag.Value of a map, through a pointer: a new one holds no
// map, and setting it panics.
type mapValue map[string]string

func (m *mapValue) Set(s string) error { (*m)[s] = s; return nil }
func (m *mapValue) String() string     { return fmt.Sprint(map[string]string(*m)) }
func (m *mapValue) Type() string       { return "testMap" }

// A value of a type a copy can't be made of is left to Validate.
func TestWriteConfigValueLeavesAnUncopyableTypeToValidate(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	withConfig(t, "")
	m := mapValue{}
	var validated []any
	ext := &Extension{Name: "test", HostFlags: []HostFlag{{
		Flag: &pflag.Flag{Name: "test-custom", Value: &m},
		Validate: func(v any) error {
			validated = append(validated, v)
			if v == "bad" {
				return errors.New("not that one")
			}
			return nil
		},
	}}}
	require.EqualError(t, WriteConfigValue(ext, "test-custom", "bad"), "not that one")
	require.NoError(t, WriteConfigValue(ext, "test-custom", "fine"))
	require.Equal(t, []any{"bad", "fine"}, validated)
	require.Empty(t, m, "the check set the flag itself")
}
