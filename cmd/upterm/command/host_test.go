package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func Test_validateShareRequiredFlags_readOnlyAndLocalTCPForwarding(t *testing.T) {
	origServer := flagServer
	origReadOnly := flagReadOnly
	origAllowLocalTCPForwarding := flagAllowLocalTCPForwarding
	t.Cleanup(func() {
		flagServer = origServer
		flagReadOnly = origReadOnly
		flagAllowLocalTCPForwarding = origAllowLocalTCPForwarding
	})

	flagServer = "ssh://uptermd.upterm.dev:22"

	cases := []struct {
		name                    string
		readOnly                bool
		allowLocalTCPForwarding bool
		wantErrSubstr           string
	}{
		{name: "neither", readOnly: false, allowLocalTCPForwarding: false},
		{name: "read-only only", readOnly: true, allowLocalTCPForwarding: false},
		{name: "forwarding only", readOnly: false, allowLocalTCPForwarding: true},
		{
			name:                    "both rejected",
			readOnly:                true,
			allowLocalTCPForwarding: true,
			wantErrSubstr:           "--read-only and --allow-local-tcp-forwarding cannot be used together",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			flagReadOnly = cc.readOnly
			flagAllowLocalTCPForwarding = cc.allowLocalTCPForwarding

			err := validateShareRequiredFlags(nil, nil)
			if cc.wantErrSubstr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, cc.wantErrSubstr)
		})
	}
}

// Test_UserDiscardedError_IsAnAbandonedSession pins how declining or
// interrupting the confirmation prompt is recorded. displaySession returns
// UserDiscardedError or UserInterruptedError from SessionCreatedCallback, and
// Host classifies such an error as a failed startup unless it wraps
// ErrSessionAbandoned — so without the unwrap the record tells whoever reads
// it that something broke, for a session where the operator simply said no
// or hit Ctrl+C.
func Test_UserDiscardedError_IsAnAbandonedSession(t *testing.T) {
	err := error(UserDiscardedError{})

	require.ErrorIs(t, err, host.ErrSessionAbandoned)

	// shareRunE reads the same error the other way round to exit cleanly. An
	// unwrap that broke that would turn a discard into a failure at the shell.
	var discarded UserDiscardedError
	require.ErrorAs(t, fmt.Errorf("session created callback: %w", err), &discarded)

	interruptedErr := error(UserInterruptedError{})

	require.ErrorIs(t, interruptedErr, host.ErrSessionAbandoned)

	// shareRunE's errors.As at :413 keeps finding it through a wrap too.
	var interrupted UserInterruptedError
	require.ErrorAs(t, fmt.Errorf("session created callback: %w", interruptedErr), &interrupted)
}

// Test_printBanner_DoesNotBlockOnAnUndrainedPipe pins the banner as something
// startup survives. It is printed from SessionCreatedCallback — before the
// admin socket is bound and before the command is started — so a banner
// larger than the pipe buffer, written straight at a stdout nobody reads,
// stopped the host there for good: a write already in the kernel is not
// something cancellation can interrupt, the command never ran, and the record
// stayed at starting with the name held.
func Test_printBanner_DoesNotBlockOnAnUndrainedPipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		// Closing the write end releases the sink's drain goroutine if it is
		// still parked in a write to it.
		_ = w.Close()
		_ = r.Close()
	})

	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	// Well past the 64 KiB a pipe buffers, so the banner cannot be delivered
	// to a reader that never reads.
	detail := tui.SessionDetail{Name: "banner", Command: strings.Repeat("x", 200<<10)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Discarded rather than defaulted: closing the pipe in the cleanup
		// drops the sink, and that warning is expected here and would
		// otherwise land in the middle of the test output.
		printBanner(slog.New(slog.NewTextHandler(io.Discard, nil)), detail)
	}()

	select {
	case <-done:
	case <-time.After(bannerFlushTimeout + 10*time.Second):
		t.Fatal("printBanner blocked on a stdout nobody was reading")
	}

	// It gave up on the flush, not on the banner: what reached the pipe is the
	// banner, from its first byte.
	want := tui.FormatSessionDetail(detail)
	got := make([]byte, 512)
	n, err := io.ReadFull(r, got)
	require.NoError(t, err)
	require.Equal(t, want[:n], string(got[:n]))
}

// Test_printBanner_DeliversTheWholeBannerToAReaderThatReads is the other half
// of the bargain: not blocking is only worth having if the banner still
// arrives. The sink hands its bytes to a drain goroutine, so a flush that
// returned too early — or a Close before it, which discards what is still
// pending — would truncate the banner rather than fail anything.
func Test_printBanner_DeliversTheWholeBannerToAReaderThatReads(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	// Read as it arrives: the banner is several drain chunks long, so a reader
	// that only started afterwards would be the undrained-pipe case again.
	collected := make(chan string, 1)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	detail := tui.SessionDetail{Name: "banner", Command: strings.Repeat("x", 200<<10)}
	want := tui.FormatSessionDetail(detail)

	// Nil: the default logger is what a caller with no logger of its own gets,
	// and nothing here is expected to log at all.
	printBanner(nil, detail)

	require.NoError(t, w.Close())
	got := <-collected
	require.NoError(t, r.Close())

	require.Equal(t, len(want), len(got), "the whole banner must arrive, not just what was delivered when the flush returned")
	require.True(t, want == got, "the banner arrived corrupted")
}

func Test_ResolveSessionName(t *testing.T) {
	require.Equal(t, "mine", resolveSessionName("mine", []string{"bash"}))
	require.Regexp(t, `^bash-[0-9a-f]{4}$`, resolveSessionName("", []string{"/bin/bash", "-l"}))
}

// logRecord is one record a capturingHandler was given, flattened to what a
// test cares about. Comparing these rather than formatted output means an
// assertion says which record carried which name, not which substring
// appeared somewhere in a stream.
type logRecord struct {
	Level slog.Level
	Msg   string
	Attrs map[string]string
}

// capturingHandler collects every record written to a logger built on it.
//
// Only valid for a logger nothing has called With or WithGroup on: WithAttrs
// and WithGroup below return the receiver and drop what they are handed, so a
// derived logger's attributes and group prefixes would be missing from the
// records collected here rather than merely unasserted. Accumulating them
// means carrying a prefix and an attribute list into every record, which is
// more machinery than the one call site needs — every logger in these tests
// comes straight from slog.New(&capturingHandler{}).
type capturingHandler struct {
	mu      sync.Mutex
	records []logRecord
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{Level: r.Level, Msg: r.Message, Attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs[a.Key] = a.Value.String()
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, rec)
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) captured() []logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]logRecord(nil), h.records...)
}

// redrawLogs is what one redraw of each of names is expected to look like.
func redrawLogs(names ...string) []logRecord {
	var want []logRecord
	for _, name := range names {
		want = append(want, logRecord{
			Level: slog.LevelInfo,
			Msg:   "session name is taken, drawing another",
			Attrs: map[string]string{"name": name},
		})
	}
	return want
}

// Test_runWithGeneratedNameRetry covers the difference between a name upterm
// picked and a name the user typed. A generated name that collides is a lost
// dice roll and re-rolling is what the user wants; an explicit one that
// collides is the answer to their question.
//
// Every case also pins what was logged. A redraw is the one moment upterm
// hosts under a name other than the one it drew, and the operator who later
// cannot find that name has the log and nothing else — so a redraw that says
// nothing, or a refusal that claims one happened, are both wrong.
func Test_runWithGeneratedNameRetry(t *testing.T) {
	inUse := func(name string) error {
		return fmt.Errorf("claiming %s: %w", name, sessiondir.ErrNameInUse)
	}

	t.Run("a generated name is retried with a fresh one", func(t *testing.T) {
		logs := &capturingHandler{}
		var names []string
		err := runWithGeneratedNameRetry(slog.New(logs), "", []string{"bash"}, func(name string) error {
			names = append(names, name)
			if len(names) < 3 {
				return inUse(name)
			}
			return nil
		})

		require.NoError(t, err)
		require.Len(t, names, 3)

		distinct := map[string]bool{}
		for _, n := range names {
			distinct[n] = true
		}
		require.Len(t, distinct, 3, "retrying the name that was taken would collide again")

		require.Equal(t, redrawLogs(names[0], names[1]), logs.captured(),
			"each name that was taken is logged once, as it is given up")
	})

	t.Run("an explicit name is never retried", func(t *testing.T) {
		logs := &capturingHandler{}
		var names []string
		err := runWithGeneratedNameRetry(slog.New(logs), "mine", []string{"bash"}, func(name string) error {
			names = append(names, name)
			return inUse(name)
		})

		require.ErrorIs(t, err, sessiondir.ErrNameInUse)
		require.Equal(t, []string{"mine"}, names,
			"hosting under a different name would answer a question the user did not ask")
		require.Empty(t, logs.captured(), "nothing was redrawn, so nothing is announced")
	})

	t.Run("retrying is bounded", func(t *testing.T) {
		logs := &capturingHandler{}
		var names []string
		err := runWithGeneratedNameRetry(slog.New(logs), "", []string{"bash"}, func(name string) error {
			names = append(names, name)
			return fmt.Errorf("attempt %d: %w", len(names), inUse(name))
		})

		require.Len(t, names, maxGeneratedNameAttempts)
		require.ErrorIs(t, err, sessiondir.ErrNameInUse)
		require.ErrorContains(t, err, "attempt 5", "the last failure is the one the user sees")

		// One short of the attempts: the last collision is returned rather
		// than redrawn, and logging it would claim a session was hosted
		// somewhere when none was hosted at all.
		require.Equal(t, redrawLogs(names[:maxGeneratedNameAttempts-1]...), logs.captured())
	})

	t.Run("any other failure is final", func(t *testing.T) {
		logs := &capturingHandler{}
		refused := errors.New("dial tcp: connection refused")
		var calls int
		err := runWithGeneratedNameRetry(slog.New(logs), "", []string{"bash"}, func(string) error {
			calls++
			return refused
		})

		require.ErrorIs(t, err, refused)
		require.Equal(t, 1, calls, "a fresh name fixes a collision and nothing else")
		require.Empty(t, logs.captured(), "a failure that is not a collision is not a redraw")
	})

	t.Run("a nil logger still redraws", func(t *testing.T) {
		// The CLI always has a logger to pass. The guard is what keeps an
		// embedder that has none from turning a redraw into a nil panic, so
		// what this case needs is a collision reaching the log line with no
		// logger behind it.
		//
		// Where that record lands is deliberately not asserted. Capturing it
		// would mean swapping slog's default, which is process-global and
		// backs the standard log package too — a test that reaches that far
		// out to check a nil check is worse than the nil check.
		var names []string
		err := runWithGeneratedNameRetry(nil, "", []string{"bash"}, func(name string) error {
			names = append(names, name)
			if len(names) < 2 {
				return inUse(name)
			}
			return nil
		})

		require.NoError(t, err)
		require.Len(t, names, 2,
			"the collision was redrawn, so the log line ran with no logger to run it on")
	})
}

// Test_resolveTerm pins the order the hosted command's TERM is decided in.
//
// The middle case is the one with a bug behind it: the default used to be
// taken whenever stdout was not a terminal, so `upterm host ... | tee log`
// from a real terminal replaced a known-good TERM with a guess.
func Test_resolveTerm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flag      string
		inherited string
		want      string
	}{
		{
			name:      "the flag wins over everything",
			flag:      "screen-256color",
			inherited: "xterm",
			want:      "screen-256color",
		},
		{
			name: "the flag stands on its own",
			flag: "screen-256color",
			want: "screen-256color",
		},
		{
			name:      "an inherited TERM beats the default",
			inherited: "rxvt-unicode-256color",
			want:      "rxvt-unicode-256color",
		},
		{
			name: "no TERM anywhere falls back to the default",
			want: defaultTerm,
		},
		{
			// dumb declares no capabilities, so inheriting it into the pty
			// upterm allocates renders a full-screen command as line noise.
			// It is an absent answer, not an answer to be respected.
			name:      "a dumb TERM counts as no TERM",
			inherited: "dumb",
			want:      defaultTerm,
		},
		{
			name:      "the flag may still ask for dumb",
			flag:      "dumb",
			inherited: "xterm",
			want:      "dumb",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, resolveTerm(tc.flag, tc.inherited))
		})
	}
}

func Test_ResolveSessionName_RejectsUnsafeExplicitName(t *testing.T) {
	// The CLI must refuse early with a readable message rather than letting
	// Claim reject it after the process is already underway.
	require.Error(t, validateSessionNameFlag(".."))
	require.Error(t, validateSessionNameFlag("a/b"))
	require.NoError(t, validateSessionNameFlag(""))
	require.NoError(t, validateSessionNameFlag("demo"))
}

func Test_ValidateSessionNameFlag_RejectsANameWhoseSocketPathWouldNotFit(t *testing.T) {
	// A runtime root deep enough that a legal 60-character name overflows a
	// unix socket address. The limit belongs at flag validation because the
	// only other place it can surface is net.Listen, which runs after the
	// tunnel is up — a session that looked like it was starting normally.
	t.Setenv("XDG_RUNTIME_DIR", string(filepath.Separator)+strings.Repeat("d", 80))

	err := validateSessionNameFlag(strings.Repeat("a", 60))
	require.ErrorIs(t, err, sessiondir.ErrSocketPathTooLong)
	require.ErrorContains(t, err, "limit 103")
}

func Test_parseURL(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		wantScheme string
		wantHost   string
		wantPort   string
	}{
		{
			name:       "port 443",
			url:        "wss://foo.com:443",
			wantScheme: "wss",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
		{
			name:       "port 80",
			url:        "http://foo.com:80",
			wantScheme: "http",
			wantHost:   "foo.com",
			wantPort:   "80",
		},
		{
			name:       "port 22",
			url:        "ssh://foo.com:22",
			wantScheme: "ssh",
			wantHost:   "foo.com",
			wantPort:   "22",
		},
		{
			name:       "no port",
			url:        "wss://foo.com",
			wantScheme: "wss",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			t.Parallel()

			_, scheme, host, port, err := parseURL(cc.url)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(cc.wantScheme, scheme); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantHost, host); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantPort, port); diff != "" {
				t.Fatal(diff)
			}
		})
	}

}

func Test_collectUserRefs(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	origGitHub := flagGitHubUsers
	origSourceHut := flagSourceHutUsers
	t.Cleanup(func() {
		flagAuthorizedUsers = origAuthorized
		flagGitHubUsers = origGitHub
		flagSourceHutUsers = origSourceHut
	})

	t.Setenv("GH_HOST", "github.com")

	flagAuthorizedUsers = []string{"github:alice", "gitea:carol@git.corp.com"}
	flagGitHubUsers = []string{"bob"}
	flagSourceHutUsers = []string{"dave"}

	refs, err := collectUserRefs()
	require.NoError(t, err)

	got := make([]string, 0, len(refs))
	for _, r := range refs {
		got = append(got, r.Display())
	}

	// Legacy per-provider flags translate into the same grammar and append
	// after the new flag's values.
	assert.Equal(t, []string{
		"github:alice@github.com",
		"gitea:carol@git.corp.com",
		"github:bob@github.com",
		"srht:dave@meta.sr.ht",
	}, got)
}

func Test_collectUserRefs_reportsEveryBadReference(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = origAuthorized })

	flagAuthorizedUsers = []string{"nope", "gitea:alice", "http://git.corp.com/bob"}

	_, err := collectUserRefs()
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing provider")
	assert.ErrorContains(t, err, "requires a host")
	assert.ErrorContains(t, err, "refusing to fetch keys over http://")
}

// Test_collectUserRefs_legacyFlagsMatchTheNewForm pins the compatibility
// requirement that --codeberg-user alice and --authorized-user codeberg:alice
// are the same request. It covers all four legacy flags because the only way
// the translation can break is a swapped entry in the legacyUserFlags table,
// which a github-only test would not catch.
func Test_collectUserRefs_legacyFlagsMatchTheNewForm(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	origCodeberg := flagCodebergUsers
	origGitHub := flagGitHubUsers
	origGitLab := flagGitLabUsers
	origSourceHut := flagSourceHutUsers
	t.Cleanup(func() {
		flagAuthorizedUsers = origAuthorized
		flagCodebergUsers = origCodeberg
		flagGitHubUsers = origGitHub
		flagGitLabUsers = origGitLab
		flagSourceHutUsers = origSourceHut
	})

	t.Setenv("GH_HOST", "github.com")

	resetAllUserFlags := func() {
		flagAuthorizedUsers = nil
		flagCodebergUsers = nil
		flagGitHubUsers = nil
		flagGitLabUsers = nil
		flagSourceHutUsers = nil
	}

	cases := []struct {
		name     string
		provider string
		values   *[]string
	}{
		{"codeberg", "codeberg", &flagCodebergUsers},
		{"github", "github", &flagGitHubUsers},
		{"gitlab", "gitlab", &flagGitLabUsers},
		{"srht", "srht", &flagSourceHutUsers},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// legacy form
			resetAllUserFlags()
			*c.values = []string{"alice"}
			viaLegacy, err := collectUserRefs()
			require.NoError(t, err)
			require.Len(t, viaLegacy, 1)

			// new form
			resetAllUserFlags()
			flagAuthorizedUsers = []string{c.provider + ":alice"}
			viaNew, err := collectUserRefs()
			require.NoError(t, err)
			require.Len(t, viaNew, 1)

			// Compare the whole UserRef, not just Display(): a swapped provider
			// in legacyUserFlags would still produce a plausible-looking Display()
			// string for the wrong provider, so only a full comparison catches it.
			assert.Equal(t, viaNew[0], viaLegacy[0],
				"the legacy flag must translate to exactly the new-form reference")
		})
	}
}

func Test_authorizationRequested(t *testing.T) {
	orig := suppliedFlags
	t.Cleanup(func() { suppliedFlags = orig })

	suppliedFlags = map[string]bool{}
	assert.False(t, authorizationRequested())

	// A flag set on the command line is recorded via the flag.Changed seed,
	// which is the only origin that sees it.
	suppliedFlags = map[string]bool{"authorized-keys": true}
	assert.True(t, authorizationRequested())

	suppliedFlags = map[string]bool{"github-user": true}
	assert.True(t, authorizationRequested())

	suppliedFlags = map[string]bool{"read-only": true}
	assert.False(t, authorizationRequested())
}

// Test_hostCmd_authorizedKeysErrorNamesTheFileOnce pins that shareRunE does not
// re-wrap an error AuthorizedKeysFromFile has already described.
func Test_hostCmd_authorizedKeysErrorNamesTheFileOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	missing := filepath.Join(dir, "nope")

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"host", "--accept", "--authorized-keys", missing, "--", "true"})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading authorized keys file "+missing)
	assert.NotContains(t, err.Error(), "error reading authorized keys: error reading authorized keys")
}

// Test_hostCmd_legacyFlagsAreRegisteredAndHidden pins the MarkHidden loop
// against legacyUserFlags: the loop's only failure mode is a name that is not a
// registered flag, which MarkHidden reports by returning an error nobody reads.
func Test_hostCmd_legacyFlagsAreRegisteredAndHidden(t *testing.T) {
	cmd := hostCmd()

	for _, lf := range legacyUserFlags {
		t.Run(lf.flag, func(t *testing.T) {
			flag := cmd.PersistentFlags().Lookup(lf.flag)
			require.NotNil(t, flag, "legacyUserFlags names a flag that is not registered")
			assert.True(t, flag.Hidden, "superseded flags stay working but hidden")
		})
	}
}

// Test_hostCmd_authorizedUserNewlineIsAnError pins the reported defect: pflag's
// own stringSliceValue.Set reads only the first CSV record, so a newline used
// to silently drop everything after it ("github:alice\ngithub:bob" became
// just "github:alice") and the command proceeded to dial with bob never
// authorized. --server points at a port nothing can accept on, so if the
// value were ever silently truncated instead of rejected, this test would
// fail by observing a dial/connection error instead of a parse error naming
// the flag.
func Test_hostCmd_authorizedUserNewlineIsAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"host", "--accept", "--server", "ssh://127.0.0.1:1",
		"--authorized-user", "github:alice\ngithub:bob",
		"--", "true",
	})

	err := root.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "authorized-user")
	assert.ErrorContains(t, err, "unexpected newline")
}

// Test_hostCmd_githubUserNewlineIsAnError is the same regression as
// Test_hostCmd_authorizedUserNewlineIsAnError, but for a legacy per-provider
// flag, since all five authorization flags share the same value type.
func Test_hostCmd_githubUserNewlineIsAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"host", "--accept", "--server", "ssh://127.0.0.1:1",
		"--github-user", "alice\nbob",
		"--", "true",
	})

	err := root.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "github-user")
	assert.ErrorContains(t, err, "unexpected newline")
}

// Test_hostCmd_authorizedUserFlag_repeatedAppends pins pflag's repeat-flag
// semantics: the first Set replaces the (empty) default and every subsequent
// Set appends, so `--authorized-user a --authorized-user b` must yield both
// rather than just the last one.
func Test_hostCmd_authorizedUserFlag_repeatedAppends(t *testing.T) {
	orig := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = orig })

	cmd := hostCmd()
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", "github:alice"))
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", "github:bob"))

	assert.Equal(t, []string{"github:alice", "github:bob"}, flagAuthorizedUsers)

	refs, err := collectUserRefs()
	require.NoError(t, err)
	assert.Len(t, refs, 2)
}

// Test_hostCmd_authorizedUserFlag_quotedCommaSurvives pins that switching to
// splitCSV did not regress pflag's own CSV-quoting behavior: a single element
// containing a comma, written with CSV quotes, must still come through as one
// element rather than being split on the embedded comma.
func Test_hostCmd_authorizedUserFlag_quotedCommaSurvives(t *testing.T) {
	orig := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = orig })

	cmd := hostCmd()
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", `"gitea:bob,carol@git.corp.com"`))

	assert.Equal(t, []string{"gitea:bob,carol@git.corp.com"}, flagAuthorizedUsers)
}

func Test_countKeys_ignoresNilEntries(t *testing.T) {
	assert.Zero(t, countKeys(nil))
	assert.Zero(t, countKeys([]*host.AuthorizedKey{nil}))
	assert.Equal(t, 1, countKeys([]*host.AuthorizedKey{{PublicKeys: []ssh.PublicKey{nil}}}))
}

// Test_hostCmd_refusesEmptyAuthorization exercises the real path from
// command-line parsing through ingestion to refusal, rather than populating
// suppliedFlags by hand. --accept keeps it non-interactive, and every case
// fails before any network call.
func Test_hostCmd_refusesEmptyAuthorization(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	emptyKeys := filepath.Join(dir, "empty.keys")
	require.NoError(t, os.WriteFile(emptyKeys, nil, 0600))

	cases := []struct {
		name          string
		args          []string
		wantErrSubstr string
	}{
		{
			name:          "empty authorized_keys file",
			args:          []string{"host", "--accept", "--authorized-keys", emptyKeys, "--", "true"},
			wantErrSubstr: "no public keys found",
		},
		{
			name:          "missing authorized_keys file",
			args:          []string{"host", "--accept", "--authorized-keys", filepath.Join(dir, "nope"), "--", "true"},
			wantErrSubstr: "error reading authorized keys",
		},
		{
			name:          "unparseable reference",
			args:          []string{"host", "--accept", "--authorized-user", "nonsense", "--", "true"},
			wantErrSubstr: "missing provider",
		},
		{
			name:          "plaintext reference",
			args:          []string{"host", "--accept", "--authorized-user", "http://git.corp.com/bob", "--", "true"},
			wantErrSubstr: "refusing to fetch keys over http://",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs(c.args)

			err := root.Execute()
			assert.ErrorContains(t, err, c.wantErrSubstr)
		})
	}
}

// Test_hostCmd_guardRefusesWhenRequestedButEmpty reaches the guard itself.
//
// An empty flag value supplies the flag — pflag records Changed and stores an
// empty slice — while producing no references at all, so no parser runs and
// nothing errors earlier. Deleting the guard branch makes these cases start a
// session that accepts any client, so they must go through Root().Execute()
// rather than asserting on helpers.
func Test_hostCmd_guardRefusesWhenRequestedButEmpty(t *testing.T) {
	const wantErr = "authorization was requested but no public keys were resolved"

	t.Run("empty flag value", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--authorized-user", "", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})

	t.Run("empty config list", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)

		confDir := filepath.Join(dir, "upterm")
		require.NoError(t, os.MkdirAll(confDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(confDir, "config.yaml"), []byte("authorized-user: []\n"), 0o600))

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})

	t.Run("empty environment variable", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		t.Setenv("UPTERM_AUTHORIZED_USER", "")

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})
}

// Test_hostCmd_guardCoversEveryAuthorizationFlag drives every flag that asks
// for a restriction, because authorizationRequested() is a list of names and a
// name missing from it fails open: an empty value supplies the flag, resolves
// no keys, errors nowhere earlier, and the session then accepts any client
// holding the token. Only --github-user was covered before, so mutating the
// other three names left the whole suite green.
func Test_hostCmd_guardCoversEveryAuthorizationFlag(t *testing.T) {
	const wantErr = "authorization was requested but no public keys were resolved"

	// A port nothing can accept on: should the guard ever fail to fire, the
	// command proceeds to dial and the test fails loudly instead of hanging or
	// reaching a real server.
	const unreachable = "ssh://127.0.0.1:1"

	flags := []string{"authorized-keys", "authorized-user"}
	for _, lf := range legacyUserFlags {
		flags = append(flags, lf.flag)
	}
	require.Len(t, flags, 6, "every authorization flag must be exercised")

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())

			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			// An empty value, including for --authorized-keys: pflag records
			// Changed, shareRunE reads no file and parses no reference, so the
			// guard is the only thing standing between this and a session that
			// accepts anyone. (An empty authorized_keys *file* fails earlier,
			// inside AuthorizedKeysFromFile — covered above.)
			root.SetArgs([]string{"host", "--accept", "--server", unreachable, "--" + name, "", "--", "true"})

			assert.ErrorContains(t, root.Execute(), wantErr)
		})
	}
}

// A session that did not happen, or a hosted command that exited non-zero, is
// not the user mistyping a flag. Printing the usage block after `exit 2`
// buries the one line that says what happened under thirty lines of flags —
// which is what `upterm host -- bash` did on every non-zero exit, since the
// command's status comes back as an ordinary error from RunE.
//
// The failure here is a malformed --proxy because it is deterministic and
// reaches nothing: no keys, no relay, no session. What is under test is where
// SilenceUsage is set, not which error follows it.
func Test_hostUsageIsForUsageErrorsOnly(t *testing.T) {
	origAccept, origProxy := flagAccept, flagProxy
	t.Cleanup(func() { flagAccept, flagProxy = origAccept, origProxy })

	var out strings.Builder
	root := Root()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"host", "--accept", "--proxy", "://not-a-url", "--", "true"})

	require.Error(t, root.Execute())
	require.NotContains(t, out.String(), "Usage:", "a failure to host is not a usage error")
	require.NotContains(t, out.String(), "--force-command", "and the flag list has nothing to do with it")

	// The other half of the contract: a flag combination that is genuinely
	// wrong still explains itself with the usage the user needs.
	out.Reset()
	root = Root()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"host", "--nonexistent-flag"})
	require.Error(t, root.Execute())
	require.Contains(t, out.String(), "Usage:", "an unknown flag is exactly what usage is for")
}
