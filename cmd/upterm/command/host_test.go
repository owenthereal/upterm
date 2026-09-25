package command

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// Test_validateShareRequiredFlags_detachNeedsAcceptAndOutputNeedsDetach pins
// the three combinations that cannot work: a background session nobody can
// confirm, an output format for a foreground run that has none, and a format
// this does not speak.
func Test_validateShareRequiredFlags_detachNeedsAcceptAndOutputNeedsDetach(t *testing.T) {
	origServer, origDetach, origAccept, origOutput := flagServer, flagDetach, flagAccept, flagHostOutput
	t.Cleanup(func() {
		flagServer, flagDetach, flagAccept, flagHostOutput = origServer, origDetach, origAccept, origOutput
	})

	// Built once, before any case sets a flag: registering a flag writes its
	// default into the variable behind it, so constructing the command per
	// call would undo the case it was meant to exercise. It is also where
	// --server's default comes from, which keeps that check quiet.
	cmd := hostCmd()
	reset := func() { flagDetach, flagAccept, flagHostOutput = false, false, "" }

	reset()
	flagDetach = true
	require.ErrorContains(t, validateShareRequiredFlags(cmd, nil), "--detach requires --accept")

	reset()
	flagHostOutput = "json"
	require.ErrorContains(t, validateShareRequiredFlags(cmd, nil), "--output requires --detach")

	reset()
	flagDetach, flagAccept, flagHostOutput = true, true, "yaml"
	require.ErrorContains(t, validateShareRequiredFlags(cmd, nil), "must be 'json'")

	reset()
	flagDetach, flagAccept, flagHostOutput = true, true, "json"
	require.NoError(t, validateShareRequiredFlags(cmd, nil))
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
	bash := func() string { return sessiondir.GenerateName([]string{"/bin/bash", "-l"}) }

	// One draw, so there is nothing for it to collide with: what is pinned is
	// that an explicit name is taken as given and an empty one reaches the
	// generator, not that two generated names differ.
	require.Equal(t, "mine", resolveSessionName("mine", bash))
	require.Regexp(t, `^bash-[0-9a-f]{4}$`, resolveSessionName("", bash))
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

// generatedNames is a stand-in for the real generator that hands out
// bash-0001, bash-0002, ... on successive calls.
//
// A test that asks for three real draws is also betting on three crypto/rand
// values being distinct, and sessiondir's four hex digits collide about once
// in 22,000 such runs — which is the generator's business and not the retry's,
// and was read as a regression on the Windows job before it was recognised
// (#574). Knowing the names up front also lets the assertions below name what
// they expect instead of comparing the drawn names to themselves.
func generatedNames() func() string {
	var drawn int
	return func() string {
		drawn++
		return fmt.Sprintf("bash-%04d", drawn)
	}
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
//
// The retry itself is exercised through runWithNameRetry with names of the
// test's own; the last case is the one that holds the wrapper to drawing the
// real ones.
func Test_runWithGeneratedNameRetry(t *testing.T) {
	inUse := func(name string) error {
		return fmt.Errorf("claiming %s: %w", name, sessiondir.ErrNameInUse)
	}

	t.Run("a generated name is retried with a fresh one", func(t *testing.T) {
		logs := &capturingHandler{}
		var names []string
		err := runWithNameRetry(slog.New(logs), "", generatedNames(), func(name string) error {
			names = append(names, name)
			if len(names) < 3 {
				return inUse(name)
			}
			return nil
		})

		require.NoError(t, err)
		// Every attempt draws: retrying the name that was taken, rather than
		// drawing a fresh one, would collide again and again until the bound
		// gave up.
		require.Equal(t, []string{"bash-0001", "bash-0002", "bash-0003"}, names)

		require.Equal(t, redrawLogs("bash-0001", "bash-0002"), logs.captured(),
			"each name that was taken is logged once, as it is given up")
	})

	t.Run("an explicit name is never retried", func(t *testing.T) {
		logs := &capturingHandler{}
		var names []string
		err := runWithNameRetry(slog.New(logs), "mine", generatedNames(), func(name string) error {
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
		err := runWithNameRetry(slog.New(logs), "", generatedNames(), func(name string) error {
			names = append(names, name)
			return fmt.Errorf("attempt %d: %w", len(names), inUse(name))
		})

		require.Len(t, names, maxGeneratedNameAttempts)
		require.ErrorIs(t, err, sessiondir.ErrNameInUse)
		require.ErrorContains(t, err, "attempt 5", "the last failure is the one the user sees")

		// One short of the attempts: the last collision is returned rather
		// than redrawn, and logging it would claim a session was hosted
		// somewhere when none was hosted at all. Spelled out rather than
		// sliced out of names, so a redraw that announced the wrong name
		// would be a failure instead of a tautology.
		require.Equal(t, redrawLogs("bash-0001", "bash-0002", "bash-0003", "bash-0004"), logs.captured())
	})

	t.Run("any other failure is final", func(t *testing.T) {
		logs := &capturingHandler{}
		refused := errors.New("dial tcp: connection refused")
		var calls int
		err := runWithNameRetry(slog.New(logs), "", generatedNames(), func(string) error {
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
		err := runWithNameRetry(nil, "", generatedNames(), func(name string) error {
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

	t.Run("the wrapper draws from the real generator", func(t *testing.T) {
		// Every case above supplies its own names, which leaves the wrapper as
		// the only thing still saying where a real one comes from: a seam that
		// quietly stopped calling sessiondir would pass all of them. One
		// attempt is enough to see the generator, and one draw cannot collide
		// with anything.
		logs := &capturingHandler{}
		var names []string
		err := runWithGeneratedNameRetry(slog.New(logs), "", []string{"/bin/bash", "-l"}, func(name string) error {
			names = append(names, name)
			return nil
		})

		require.NoError(t, err)
		require.Len(t, names, 1)
		require.Regexp(t, `^bash-[0-9a-f]{4}$`, names[0])
		require.Empty(t, logs.captured(), "nothing was redrawn, so nothing is announced")
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

func Test_identitiesOnlyRequested(t *testing.T) {
	orig := suppliedFlags
	t.Cleanup(func() { suppliedFlags = orig })

	suppliedFlags = map[string]bool{}
	assert.False(t, identitiesOnlyRequested())

	suppliedFlags = map[string]bool{"private-key": true}
	assert.True(t, identitiesOnlyRequested())

	suppliedFlags = map[string]bool{"authorized-keys": true}
	assert.False(t, identitiesOnlyRequested())
}

// Test_guardedSpawn_RefusesInsideATestBinary pins hostSpawn's default: the
// refusal is production code, so a test in any package that reaches the real
// spawn gets an error rather than a copy of its own test binary running the
// whole suite, once per spawn.
//
// The options name an executable that does not exist, and that is
// deliberate: the guard never looks at them, but it means that a build with
// the guard removed — the mutation that proves this test — fails in
// exec.Start with ENOENT instead of re-executing this test binary. The
// child-side guard in TestMain is the second net under that proof.
func Test_guardedSpawn_RefusesInsideATestBinary(t *testing.T) {
	dir := t.TempDir()

	conn, proc, err := guardedSpawn(spawnOptions{
		executable: filepath.Join(dir, "no-such-upterm"),
		args:       []string{"host", "--", "true"},
		env:        []string{},
		name:       "guarded-1",
		logPath:    filepath.Join(dir, "upterm.log"),
	})
	require.ErrorContains(t, err, "refusing to spawn the daemon from a test binary")
	assert.Contains(t, err.Error(), "runHostInProcess", "the refusal has to name the seam that replaces it")
	assert.Nil(t, conn, "nothing was connected")
	assert.Nil(t, proc, "nothing was started")

	// Reached before spawnDaemon, not after it failed: spawnDaemon opens the
	// log path it is given before it forks, so an untouched log is proof the
	// call returned above it.
	_, statErr := os.Stat(filepath.Join(dir, "upterm.log"))
	assert.True(t, os.IsNotExist(statErr), "the guard returns before spawnDaemon opens the log")
}

// runHostInProcess runs `upterm host <argv...>` with the daemon in a
// goroutine of this process instead of a child of it, and returns what the
// command returned.
//
// The exchange is the real one — a real bootstrap.Child on the far end of a
// pipe, reporting through the same messages — but the daemon is not started
// by spawnDaemon, which re-executes this process's own argv. Under `go test`
// that argv is the test runner's, so a test that reached spawnDaemon would
// start a second copy of the test binary and run the whole suite inside it,
// once per spawn.
//
// The daemon's hostOptions come from the arguments after `--`, which is what
// cobra hands shareRunE and therefore what the real daemon parses out of the
// argv it inherits.
func runHostInProcess(t *testing.T, argv ...string) error {
	t.Helper()

	orig := hostSpawn
	t.Cleanup(func() { hostSpawn = orig })

	// Registered before the connections' own cleanup and therefore run after
	// it: the close is what ends the daemon, and the daemon reads the flag
	// variables the next test is about to write.
	var daemons sync.WaitGroup
	t.Cleanup(daemons.Wait)

	var command []string
	for i, a := range argv {
		if a == "--" {
			command = argv[i+1:]
			break
		}
	}

	hostSpawn = func(so spawnOptions) (net.Conn, *os.Process, error) {
		opts, err := parseHostOptions(command)
		if err != nil {
			return nil, nil, err
		}
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		daemons.Add(1)
		go func() {
			defer daemons.Done()
			_ = runDaemonProcess(context.Background(), discardLogger(), opts, a, so.name,
				func(ctx context.Context, h *host.Host) error { return h.Run(ctx) })
		}()
		return b, nil, nil
	}

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(argv)
	return root.Execute()
}

// Test_hostCmd_authorizedKeysErrorNamesTheFileOnce pins that nobody re-wraps
// an error AuthorizedKeysFromFile has already described. The daemon is what
// resolves the keys and so what produces the error; the parent adds only its
// own "session NAME could not start:" prefix, which is what the assertions
// below check — the file is named once, and never with the doubled "error
// reading authorized keys: error reading authorized keys".
func Test_hostCmd_authorizedKeysErrorNamesTheFileOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	missing := filepath.Join(dir, "nope")

	err := runHostInProcess(t, "host", "--accept", "--authorized-keys", missing, "--", "true")
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
			assert.ErrorContains(t, runHostInProcess(t, c.args...), c.wantErrSubstr)
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

		assert.ErrorContains(t,
			runHostInProcess(t, "host", "--accept", "--authorized-user", "", "--", "true"), wantErr)
	})

	t.Run("empty config list", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)

		confDir := filepath.Join(dir, "upterm")
		require.NoError(t, os.MkdirAll(confDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(confDir, "config.yaml"), []byte("authorized-user: []\n"), 0o600))

		assert.ErrorContains(t, runHostInProcess(t, "host", "--accept", "--", "true"), wantErr)
	})

	t.Run("empty environment variable", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		t.Setenv("UPTERM_AUTHORIZED_USER", "")

		assert.ErrorContains(t, runHostInProcess(t, "host", "--accept", "--", "true"), wantErr)
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

			// An empty value, including for --authorized-keys: pflag records
			// Changed, the daemon reads no file and parses no reference, so
			// the guard is the only thing standing between this and a session
			// that accepts anyone. (An empty authorized_keys *file* fails
			// earlier, inside AuthorizedKeysFromFile — covered above.)
			assert.ErrorContains(t, runHostInProcess(t,
				"host", "--accept", "--server", unreachable, "--"+name, "", "--", "true"), wantErr)
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

// runHostCmd executes `upterm host --accept <args> -- true` in a controlled
// environment: a fresh HOME holding one plain default identity, no agent,
// short XDG roots, and a relay nobody answers on. Every case that gets past
// identity resolution then fails on the dial, which is how a case that should
// have stopped earlier shows up: with a different error. Callers set the
// config file themselves, with withConfig, so it is not touched here.
func runHostCmd(t *testing.T, args ...string) error {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	t.Setenv("SSH_AUTH_SOCK", "")
	xdg, err := os.MkdirTemp("", "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(xdg) })
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	t.Setenv("XDG_STATE_HOME", xdg)

	// A default identity, so that "the default list" is a real, loadable
	// list and an empty variable that failed to clear it would be visible.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(block), 0o600))

	// Through the in-process seam, never root.Execute() directly: on Unix
	// upterm host spawns its daemon by re-executing os.Args, and in a test
	// binary that argv is the test runner's — the child would run this whole
	// suite again, once per spawn. TestMain trips any test that reaches the
	// real spawn; this is the path it points at. The daemon is what resolves
	// identities, so its error arrives under the parent's "session NAME could
	// not start:" prefix, which ErrorContains looks through.
	return runHostInProcess(t, append([]string{"host", "--accept", "--server", "ssh://127.0.0.1:1"}, append(args, "--", "true")...)...)
}

func Test_hostCmd_privateKeyIsIdentitiesOnlyFromEveryOrigin(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	t.Run("flag", func(t *testing.T) {
		withConfig(t, "")
		err := runHostCmd(t, "--private-key", missing)
		require.ErrorContains(t, err, "cannot read private key "+missing)
	})

	t.Run("config", func(t *testing.T) {
		withConfig(t, "private-key: ["+missing+"]\n")
		err := runHostCmd(t)
		require.ErrorContains(t, err, "cannot read private key "+missing)
	})

	t.Run("env", func(t *testing.T) {
		withConfig(t, "")
		t.Setenv("UPTERM_PRIVATE_KEY", missing)
		err := runHostCmd(t)
		require.ErrorContains(t, err, "cannot read private key "+missing)
	})
}

func Test_hostCmd_emptyPrivateKeyListIsAnErrorFromEveryOrigin(t *testing.T) {
	const want = "private-key was supplied but names no files"

	t.Run("flag", func(t *testing.T) {
		withConfig(t, "")
		require.ErrorContains(t, runHostCmd(t, "--private-key="), want)
	})

	t.Run("config", func(t *testing.T) {
		withConfig(t, "private-key: []\n")
		require.ErrorContains(t, runHostCmd(t), want)
	})

	t.Run("env alone", func(t *testing.T) {
		withConfig(t, "")
		t.Setenv("UPTERM_PRIVATE_KEY", "")
		require.ErrorContains(t, runHostCmd(t), want)
	})
}

func Test_hostCmd_emptyPrivateKeyEnvPreservesAnExplicitValue(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	// Reaching "cannot read <missing>" proves two things at once: the
	// explicit value survived the empty variable, and identities-only
	// applied to it.
	t.Run("config survives", func(t *testing.T) {
		withConfig(t, "private-key: ["+missing+"]\n")
		t.Setenv("UPTERM_PRIVATE_KEY", "")
		require.ErrorContains(t, runHostCmd(t), "cannot read private key "+missing)
	})

	t.Run("CLI survives", func(t *testing.T) {
		withConfig(t, "")
		t.Setenv("UPTERM_PRIVATE_KEY", "")
		require.ErrorContains(t, runHostCmd(t, "--private-key", missing), "cannot read private key "+missing)
	})
}
