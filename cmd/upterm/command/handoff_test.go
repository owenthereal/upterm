package command

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// writeKeyFile writes an authorized_keys file of n new keys at path, or at a
// new path when path is "", and returns the path.
func writeKeyFile(t *testing.T, path string, n int) string {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "authorized_keys")
	}
	var b strings.Builder
	for range n {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		key, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)
		b.Write(ssh.MarshalAuthorizedKey(key))
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

// everySetting is a HostSettings with every field set, so that a field the
// handoff loses can't go unseen.
func everySetting(t *testing.T) HostSettings {
	t.Helper()
	var s HostSettings
	v := reflect.ValueOf(&s).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		name := v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.String:
			f.SetString("v-" + name)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"a-" + name, "b-" + name}))
		case reflect.Int64:
			f.SetInt(int64(time.Duration(i+1) * time.Minute))
		default:
			t.Fatalf("HostSettings.%s is a %s, which everySetting can't set", name, f.Kind())
		}
	}
	s.AllowForwarding = string(forwardAny)
	return s
}

// handoffJSON is the JSON enc encodes.
func handoffJSON(t *testing.T, enc string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(enc)
	require.NoError(t, err)
	return string(b)
}

// credentialName is a JSON key named like something secret.
var credentialName = regexp.MustCompile(`(?i)pass|secret|token|credential|cookie|private-key-data|cookie`)

// requireNoCredentialField fails when a JSON object key in v named like a
// credential holds a value.
func requireNoCredentialField(t *testing.T, path string, v any) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if credentialName.MatchString(k) {
				require.Truef(t, child == nil || child == "" || child == false, "%s.%s holds %v", path, k, child)
			}
			requireNoCredentialField(t, path+"."+k, child)
		}
	case []any:
		for _, child := range v {
			requireNoCredentialField(t, path+"[]", child)
		}
	}
}

func TestHandoffRoundTripAndRedaction(t *testing.T) {
	keyFile, err := readAuthorizedKeyFile(writeKeyFile(t, "", 3))
	require.NoError(t, err)
	alice, err := host.ParseUserRef("github:alice")
	require.NoError(t, err)
	bob, err := host.ParseUserRef("gitlab:bob")
	require.NoError(t, err)

	const proxy = "http://user:hunter2@proxy.example:3128"
	settings := everySetting(t)
	settings.Proxy = proxy
	h := Handoff{
		Name:     "work",
		Settings: settings,
		Options: HostOptions{
			Name:      "Work",
			NameGiven: true,
			Flags: map[string]FlagValue{
				"read-only": {Value: "true", Source: SourceEnv},
				"proxy":     {Value: proxy, Source: SourceConfig},
				"server":    {Value: "ssh://uptermd.upterm.dev:22", Source: SourceDefault},
				"name":      {Value: "Work", Source: SourceCommandLine},
			},
			AuthorizedKeys: []AuthorizedKeyFile{keyFile},
			UserRefs:       []UserRef{{Flag: "--authorized-user", Ref: alice}, {Flag: "--gitlab-user", Ref: bob}},
			Extension:      map[string]FlagValue{"test-service": {Value: "one", Source: SourceConfig}},
		},
		Payload: []byte("opaque\x00bytes"),
	}

	enc, err := encodeHandoff(h, nil)
	require.NoError(t, err)
	text := handoffJSON(t, enc)
	require.NotContains(t, text, "hunter2", "the proxy's credential travels in the handoff")

	got, err := decodeHandoff(enc)
	require.NoError(t, err)
	want := h
	want.Settings.Proxy = ""
	want.Options.Flags = map[string]FlagValue{}
	for k, v := range h.Options.Flags {
		want.Options.Flags[k] = v
	}
	want.Options.Flags["proxy"] = FlagValue{Value: "", Source: SourceConfig}
	require.Equal(t, want, got)
	require.Empty(t, got.Settings.Proxy)
	require.Empty(t, got.Options.Flags["proxy"].Value)

	// What decodes encodes the same.
	again, err := encodeHandoff(got, nil)
	require.NoError(t, err)
	require.Equal(t, enc, again)

	var tree any
	require.NoError(t, json.Unmarshal([]byte(text), &tree))
	requireNoCredentialField(t, "handoff", tree)
	// The key file travels as its path, digest and count, never its keys.
	require.Contains(t, text, `"path":`+mustJSON(t, keyFile.Path))
	require.Contains(t, text, hex.EncodeToString(keyFile.SHA256[:]))
	require.Contains(t, text, `"count":3`)
	require.NotContains(t, text, base64.StdEncoding.EncodeToString(keyFile.Keys[0].Marshal()))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestHandoffFitsEveryPlatformOrRefusesBeforeSpawn(t *testing.T) {
	t.Run("a thousand keys", func(t *testing.T) {
		path := writeKeyFile(t, "", 1000)
		file, err := readAuthorizedKeyFile(path)
		require.NoError(t, err)
		require.Len(t, file.Keys, 1000)

		enc, err := encodeHandoff(Handoff{Name: "big", Settings: everySetting(t), Options: HostOptions{AuthorizedKeys: []AuthorizedKeyFile{file}}}, nil)
		require.NoError(t, err)
		require.Less(t, len(enc), maxHandoffBytes)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		digest := sha256.Sum256(content)
		require.Contains(t, handoffJSON(t, enc), hex.EncodeToString(digest[:]))

		got, err := decodeHandoff(enc)
		require.NoError(t, err)
		require.Len(t, got.Options.AuthorizedKeys, 1)
		require.Len(t, got.Options.AuthorizedKeys[0].Keys, 1000, "the session process reads the keys the file lists")
	})

	t.Run("over the cap", func(t *testing.T) {
		restoreFlags(t)
		inProcessHostEnv(t)
		spawns := countSpawns(t)
		ext := &Extension{Name: "test", Prepare: func(context.Context, HostOptions) (Prepared, error) {
			return Prepared{Delegated: true}, nil
		}, Broker: unusedBroker}

		_, stderr, code := runCLIWith(t, ext, "host", "--detach", "--accept", "--force-command", strings.Repeat("x", 40000), "--", "true")
		require.Equal(t, 1, code, stderr)
		require.Regexp(t, `^upterm: this run's settings take \d+ bytes, more than the 30000 a session process can be handed; shorten its flag values, such as --force-command\n$`, stderr)
		require.Zero(t, *spawns, "a session process was started")
	})
}

// countSpawns has hostSpawn count its calls and fail each, until the test
// ends.
func countSpawns(t *testing.T) *int {
	t.Helper()
	orig := hostSpawn
	t.Cleanup(func() { hostSpawn = orig })
	var n int
	hostSpawn = func(spawnOptions) (net.Conn, *os.Process, error) {
		n++
		return nil, nil, errors.New("no session process in this test")
	}
	return &n
}

// asDaemon makes this process look like a session process to
// isDaemonProcess, until the test ends.
func asDaemon(t *testing.T) {
	t.Helper()
	t.Setenv(daemonHandoffEnv, "3")
	t.Cleanup(func() { daemonHandoff = nil })
}

// daemonFailure is what runDaemon, run with d, tells its parent.
func daemonFailure(t *testing.T, ext *Extension, d *daemonHandoffState) *api.Failed {
	t.Helper()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	parent := bootstrap.NewParent(b, nil, io.Discard, nil)
	done := make(chan error, 1)
	go func() {
		err := runDaemon(context.Background(), discardLogger(), ext, d, []string{"sh"}, a, "kf")
		_ = a.Close()
		done <- err
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{})
	require.NoError(t, err)
	require.Error(t, <-done)
	require.NotNil(t, out.Failed)
	return out.Failed
}

func TestKeyFileChangedBetweenParentAndDaemon(t *testing.T) {
	path := writeKeyFile(t, "", 2)
	file, err := readAuthorizedKeyFile(path)
	require.NoError(t, err)
	enc, err := encodeHandoff(Handoff{Name: "kf", Options: HostOptions{AuthorizedKeys: []AuthorizedKeyFile{file}}}, nil)
	require.NoError(t, err)

	// Rewritten between the parent's read and the session process's.
	writeKeyFile(t, path, 2)
	want := file.Path + " changed after this run started; start it again"

	_, err = decodeHandoff(enc)
	require.EqualError(t, err, want)

	// The session process finds it as its pre-run reads its handoff, and its
	// run tells the parent so, as it is.
	asDaemon(t)
	t.Setenv(handoffEnv, enc)
	d := takeHandoff()
	require.NotNil(t, d)
	require.EqualError(t, d.err, want)
	_, set := os.LookupEnv(handoffEnv)
	require.False(t, set, "the handoff is still in the environment the hosted command inherits")

	f := daemonFailure(t, nil, d)
	require.True(t, f.Verbatim)
	require.Equal(t, want, f.Error)

	// A file that's gone has changed too.
	require.NoError(t, os.Remove(path))
	_, err = decodeHandoff(enc)
	require.EqualError(t, err, want)
}

func TestAHandoffThatDoesntDecodeIsSaid(t *testing.T) {
	const want = "the settings this run was started with can't be read; start it again"
	good, err := encodeHandoff(Handoff{Name: "ok"}, nil)
	require.NoError(t, err)
	wire := func(mutate func(map[string]any)) string {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(handoffJSON(t, good)), &m))
		mutate(m)
		b, err := json.Marshal(m)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	for name, enc := range map[string]string{
		"not base64":      "garbage!",
		"not JSON":        base64.RawURLEncoding.EncodeToString([]byte("{")),
		"another version": wire(func(m map[string]any) { m["v"] = 2 }),
		"unknown field":   wire(func(m map[string]any) { m["secret"] = "x" }),
		"a bad name":      wire(func(m map[string]any) { m["name"] = "a/b" }),
		"a bad source": wire(func(m map[string]any) {
			m["options"].(map[string]any)["flags"] = map[string]any{"read-only": map[string]any{"value": "true", "source": "guess"}}
		}),
		"a bad user": wire(func(m map[string]any) {
			m["options"].(map[string]any)["userRefs"] = []any{map[string]any{"flag": "--authorized-user", "ref": "nope:"}}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeHandoff(enc)
			require.EqualError(t, err, want)
		})
	}

	t.Run("told the parent", func(t *testing.T) {
		asDaemon(t)
		t.Setenv(handoffEnv, "garbage!")
		d := takeHandoff()
		require.NotNil(t, d)
		f := daemonFailure(t, nil, d)
		require.True(t, f.Verbatim)
		require.Equal(t, want, f.Error)
	})
}

func TestInheritedHandoffIsIgnoredOutsideTheDaemon(t *testing.T) {
	t.Run("the parent ignores it", func(t *testing.T) {
		t.Setenv(handoffEnv, "garbage")
		require.Nil(t, takeHandoff())
		require.Equal(t, "garbage", os.Getenv(handoffEnv))
	})

	t.Run("an ordinary run hands the session process none", func(t *testing.T) {
		restoreFlags(t)
		inProcessHostEnv(t)
		t.Setenv(handoffEnv, "garbage")
		orig := hostSpawn
		t.Cleanup(func() { hostSpawn = orig })
		var handoffs []string
		hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
			handoffs = append(handoffs, so.handoff)
			return nil, nil, errors.New("no session process in this test")
		}
		_, stderr, code := runCLI(t, "host", "--detach", "--accept", "--server", "ssh://127.0.0.1:1", "--", "true")
		require.Equal(t, 1, code)
		require.Contains(t, stderr, "could not start the session daemon")
		require.Equal(t, []string{""}, handoffs)
	})

	t.Run("the spawn resets it", requireTheSpawnResetsAnInheritedHandoff)

	t.Run("an ordinary session process reads none", func(t *testing.T) {
		asDaemon(t)
		t.Setenv(handoffEnv, "")
		require.Nil(t, takeHandoff())
		_, set := os.LookupEnv(handoffEnv)
		require.False(t, set, "the empty handoff is still in the environment the hosted command inherits")
	})
}

// requireTheSpawnResetsAnInheritedHandoff checks that the real spawn sets
// the variable whatever this process inherited, so the session process of an
// ordinary run is never handed this one's.
func requireTheSpawnResetsAnInheritedHandoff(t *testing.T) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "upterm.log")
	conn, proc, err := spawnDaemon(spawnOptions{
		executable: os.Args[0],
		args:       []string{"-test.run=^TestSpawnHelperProcess$"},
		env:        append(os.Environ(), "UPTERM_SPAWN_HELPER=1", handoffEnv+"=garbage"),
		name:       "helper-2",
		logPath:    logPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		exited := make(chan struct{})
		go func() {
			_, _ = proc.Wait()
			close(exited)
		}()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = proc.Kill()
			<-exited
		}
	})
	c := bootstrap.NewConn(conn)
	require.NoError(t, c.Send(&api.Startup{Msg: &api.Startup_Print{Print: &api.Print{Text: "ping"}}}))
	_, err = c.Recv()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool {
		b, _ := os.ReadFile(logPath)
		return strings.Contains(string(b), "REPORT done=true")
	}, 10*time.Second, 50*time.Millisecond)
	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.Contains(t, string(b), "REPORT settings=\"\"\n")
}

// A key file with no key in it is named in the error that says so.
func TestAKeyFileThatDoesntParseIsNamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte("# nobody yet\n"), 0o600))
	_, err := readAuthorizedKeyFile(path)
	require.ErrorContains(t, err, path)
	require.NoError(t, os.WriteFile(path, []byte("not a key\n"), 0o600))
	_, err = readAuthorizedKeyFile(path)
	require.ErrorContains(t, err, path)
}

// A delegated run's session process reads its host settings from its
// handoff alone, and --debug, which is no host setting, as any command reads
// it: from UPTERM_DEBUG and the config file too.
func TestADelegatedSessionProcessStillReadsDebug(t *testing.T) {
	for name, tc := range map[string]struct{ config, env string }{
		"config": {config: "debug: true\nread-only: true\n"},
		"env":    {config: "read-only: true\n", env: "true"},
	} {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			inProcessHostEnv(t)
			withConfig(t, tc.config)
			if tc.env != "" {
				t.Setenv("UPTERM_DEBUG", tc.env)
			}
			enc, err := encodeHandoff(Handoff{Name: "d"}, nil)
			require.NoError(t, err)
			asDaemon(t)
			t.Setenv(handoffEnv, enc)

			host, _, err := RootWith(nil).Find([]string{"host"})
			require.NoError(t, err)
			require.NoError(t, host.ParseFlags(nil))
			host.SetContext(context.Background())
			require.NoError(t, rootPreRun(host))
			t.Cleanup(func() { _ = uptermctx.Logger(host.Context()).Close() })
			debug, err := host.Flags().GetBool("debug")
			require.NoError(t, err)
			require.True(t, debug, "debug wasn't read")
			require.False(t, flagReadOnly, "a host setting was read from the config file")
			// Binding sets a flag's Changed, and applySettings, which assigns
			// the variable, doesn't: a host setting bound from the file
			// would show here even with its variable reset.
			require.False(t, host.Flags().Lookup("read-only").Changed, "read-only was bound from the config file")
			require.Empty(t, suppliedFlags)
		})
	}
}

// delegating is an extension whose Prepare delegates every run, with a
// Broker that's never reached.
func delegating() *Extension {
	ext := testExtension(func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil })
	ext.Broker = unusedBroker
	return ext
}

// A delegated run's session process knows which flags were given, and from
// where, as its parent did: root's pre-run records its own first, and the
// handoff's replace them. So --full-access with --authorized-user from the
// environment passes its checks there, as it did in the parent.
func TestADelegatedSessionProcessKnowsWhatWasGiven(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	t.Setenv("UPTERM_AUTHORIZED_USER", "github:alice")
	args := []string{"--detach", "--accept", "--full-access", "--", "true"}
	handoff := delegatedHandoff(t, delegating(), args...)

	require.NoError(t, sessionPreRun(t, delegating(), handoff, args...))
	require.True(t, suppliedFlags["authorized-user"])
	require.False(t, commandLineFlags["authorized-user"])
	require.True(t, commandLineFlags["full-access"])
	require.True(t, authorizationRequested())
}

// A delegated run's session process skips the checks its parent skipped: a
// --server, and no home for the default --known-hosts, which an ordinary
// run's session process refuses.
func TestADelegatedSessionProcessSkipsTheRelaysChecks(t *testing.T) {
	restoreFlags(t)
	inProcessHostEnv(t)
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	args := []string{"--detach", "--accept", "--server", "ftp://nowhere", "--", "true"}
	handoff := delegatedHandoff(t, delegating(), args...)

	require.NoError(t, sessionPreRun(t, delegating(), handoff, args...))
	require.Equal(t, "ftp://nowhere", flagServer)

	// The control: an ordinary run's session process, with the same argv.
	err := sessionPreRun(t, delegating(), "", args...)
	require.ErrorContains(t, err, "unsupported server protocol ftp")
	require.ErrorContains(t, err, "can't find your home directory for the default --known-hosts")
}

// applySettings gives each flag variable the handoff's value: every
// HostSettings field, read back from the variables as an ordinary run reads
// them, is the handoff's, and none of those is its flag's default.
func TestApplySettingsAssignsTheHandoffsValues(t *testing.T) {
	restoreFlags(t)
	origSupplied, origCommandLine := suppliedFlags, commandLineFlags
	t.Cleanup(func() { suppliedFlags, commandLineFlags = origSupplied, origCommandLine })
	Root()
	suppliedFlags, commandLineFlags = map[string]bool{}, map[string]bool{}
	// shouldHideClientIP reads the flag's Changed, which applySettings
	// doesn't set: its variable is what a session process's host is built
	// from.
	read := func() HostSettings {
		s := hostSettingsFromFlags()
		s.HideClientIP = flagHideClientIP
		return s
	}
	defaults := read()

	refs := make(map[string]host.UserRef)
	for _, raw := range []string{"github:alice", "codeberg:carol", "github:gina", "gitlab:bob", "srht:sam"} {
		ref, err := host.ParseUserRef(raw)
		require.NoError(t, err)
		refs[raw] = ref
	}
	want := everySetting(t)
	applySettings(Handoff{Name: "work", Settings: want, Options: HostOptions{
		Name:      "Work",
		NameGiven: true,
		Flags: map[string]FlagValue{
			// IdentitiesOnly is whether --private-key was given.
			"private-key": {Value: "[a-PrivateKeys,b-PrivateKeys]", Source: SourceCommandLine},
			"output":      {Value: "json", Source: SourceCommandLine},
		},
		UserRefs: []UserRef{
			{Flag: "--authorized-user", Ref: refs["github:alice"]},
			{Flag: "--codeberg-user", Ref: refs["codeberg:carol"]},
			{Flag: "--github-user", Ref: refs["github:gina"]},
			{Flag: "--gitlab-user", Ref: refs["gitlab:bob"]},
			{Flag: "--srht-user", Ref: refs["srht:sam"]},
		},
	}})

	got := read()
	d, w, g := reflect.ValueOf(defaults), reflect.ValueOf(want), reflect.ValueOf(got)
	for i := range w.NumField() {
		name := w.Type().Field(i).Name
		require.NotEqualf(t, d.Field(i).Interface(), w.Field(i).Interface(), "the handoff's HostSettings.%s is its flag's default", name)
		require.Equalf(t, w.Field(i).Interface(), g.Field(i).Interface(), "HostSettings.%s", name)
	}
	require.Equal(t, "work", flagName)
	require.Equal(t, "json", flagHostOutput)
	require.Equal(t, []string{"github:alice"}, flagAuthorizedUsers)
	require.Equal(t, []string{"carol"}, flagCodebergUsers)
	require.Equal(t, []string{"gina"}, flagGitHubUsers)
	require.Equal(t, []string{"bob"}, flagGitLabUsers)
	require.Equal(t, []string{"sam"}, flagSourceHutUsers)

	// One bool at a time, so that no two of them can stand in for each
	// other: each reads back true alone.
	for i := range w.NumField() {
		if w.Field(i).Kind() != reflect.Bool {
			continue
		}
		name := w.Type().Field(i).Name
		var one HostSettings
		reflect.ValueOf(&one).Elem().Field(i).SetBool(true)
		var flags map[string]FlagValue
		if name == "IdentitiesOnly" {
			flags = map[string]FlagValue{"private-key": {Value: "[k]", Source: SourceCommandLine}}
		}
		applySettings(Handoff{Name: "work", Settings: one, Options: HostOptions{Flags: flags}})
		g := reflect.ValueOf(read())
		for j := range w.NumField() {
			if w.Field(j).Kind() == reflect.Bool {
				require.Equalf(t, i == j, g.Field(j).Bool(), "with only HostSettings.%s true, HostSettings.%s", name, w.Type().Field(j).Name)
			}
		}
	}
}

// An extension's bound flag holds, in a delegated run's session process, the
// value its parent resolved, from wherever the parent took it.
func TestADelegatedSessionProcessGetsTheExtensionsFlags(t *testing.T) {
	withService := func() (*Extension, *string) {
		var service string
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		fs.StringVar(&service, "test-service", "", "")
		return &Extension{
			Name:      "test",
			HostFlags: []HostFlag{{Flag: fs.Lookup("test-service")}},
			Prepare:   func(context.Context, HostOptions) (Prepared, error) { return Prepared{Delegated: true}, nil },
			Broker:    unusedBroker,
		}, &service
	}
	for name, tc := range map[string]struct {
		args        []string
		env, config string
	}{
		"command line": {args: []string{"--test-service", "one"}},
		"env":          {env: "one"},
		"config":       {config: "extensions:\n  test:\n    test-service: one\n"},
	} {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			inProcessHostEnv(t)
			withConfig(t, tc.config)
			if tc.env != "" {
				t.Setenv("UPTERM_TEST_SERVICE", tc.env)
			}
			args := append(append([]string{"--detach", "--accept"}, tc.args...), "--", "true")
			parent, _ := withService()
			handoff := delegatedHandoff(t, parent, args...)

			session, service := withService()
			require.NoError(t, sessionPreRun(t, session, handoff, args...))
			require.Equal(t, "one", *service)
		})
	}
}

// An encoded handoff of exactly 30,000 bytes is handed over, and the next
// longer one is refused. Unpadded base64 has no length of 30,001: the next
// is 30,002.
func TestHandoffCapIsTheMostItTakes(t *testing.T) {
	sized := func(n int) Handoff {
		return Handoff{Name: "cap", Settings: HostSettings{ForceCommand: strings.Repeat("x", n)}}
	}
	enc, err := encodeHandoff(sized(0), nil)
	require.NoError(t, err)
	// 22,500 bytes of JSON are 30,000 of unpadded base64.
	fill := 22500 - len(handoffJSON(t, enc))

	enc, err = encodeHandoff(sized(fill), nil)
	require.NoError(t, err)
	require.Len(t, enc, 30000)

	_, err = encodeHandoff(sized(fill+1), nil)
	require.EqualError(t, err, "this run's settings take 30002 bytes, more than the 30000 a session process can be handed; shorten its flag values, such as --force-command")
}

// The Broker factory is given a context that ends when the parent goes:
// one that waits on it doesn't keep the session process running after the
// operator has given up on the run.
func TestTheBrokerFactoryEndsWhenTheParentGoes(t *testing.T) {
	entered, stop := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop) })
	ext := &Extension{Name: "test", Broker: func(ctx context.Context, _ Handoff) (host.Broker, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-stop:
			return nil, errors.New("the test ended first")
		}
	}}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	done := make(chan error, 1)
	go func() {
		done <- runDaemon(context.Background(), discardLogger(), ext, &daemonHandoffState{h: Handoff{Name: "gone"}}, []string{"sh"}, a, "gone")
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the factory wasn't called")
	}
	require.NoError(t, b.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, host.ErrSessionAbandoned)
	case <-time.After(10 * time.Second):
		t.Fatal("the factory's context didn't end when the parent went")
	}
}
