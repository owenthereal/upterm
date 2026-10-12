package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/join"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func mustTarget(t *testing.T) join.Target {
	t.Helper()
	tg, err := join.ParseTarget("ssh://abc@relay.test")
	require.NoError(t, err)
	return tg
}

// waiting is a Waiting event whose next attempt is n seconds away. The status
// writer measures against time.Now, so the line it renders says n s for as
// long as less than a second has passed since this was built.
func waiting(why join.WaitReason, n int) join.Event {
	now := time.Now()
	return join.Event{Kind: join.Waiting, Why: why, Since: now, Next: now.Add(time.Duration(n) * time.Second)}
}

func TestRenderEveryText(t *testing.T) {
	tg, _ := join.ParseTarget("ssh://abc@relay.test")
	since := time.Date(2026, 10, 7, 14, 2, 11, 0, time.Local)
	next := since.Add(8 * time.Second)
	refused := errors.New("agent refused operation")
	for want, e := range map[string]join.Event{
		"upterm: waiting for the host since 14:02:11; next try in 8 s":                                                             {Kind: join.Waiting, Why: join.NoHost, Since: since, Next: next},
		"upterm: can't reach relay.test since 14:02:11 (dial tcp: refused); next try in 8 s":                                       {Kind: join.Waiting, Why: join.Unreachable, Err: errors.New("dial tcp: refused"), Since: since, Next: next},
		"upterm: the relay can't look up sessions since 14:02:11; next try in 8 s":                                                 {Kind: join.Waiting, Why: join.RelayLookup, Since: since, Next: next},
		"upterm: the relay can't reach the host since 14:02:11; next try in 8 s":                                                   {Kind: join.Waiting, Why: join.Upstream, Since: since, Next: next},
		"upterm: your SSH agent can't sign since 14:02:11 (agent refused operation); next try in 8 s":                              {Kind: join.Waiting, Why: join.IdentityFailure, Err: &join.IdentityError{Key: "SHA256:k", Err: &host.AgentRefusedError{Key: "SHA256:k", Err: refused}}, Since: since, Next: next},
		"upterm: can't start the session since 14:02:11 (shell request refused); next try in 8 s":                                  {Kind: join.Waiting, Why: join.Setup, Err: errors.New("shell request refused"), Since: since, Next: next},
		"upterm: waiting for the host since 14:02:11; next try in 8 s. The session may have ended or moved; check with the host.":  {Kind: join.Waiting, Why: join.NoHost, Since: since, Next: next, Long: true},
		"upterm: no host is connected for session abc right now; retrying for 30 s (Ctrl-C to stop)":                               {Kind: join.Waiting, Why: join.NoHost, First: true, Since: since, Next: next},
		"upterm: rejoined session abc after 1m12s":                                                                                 {Kind: join.Joined, Rejoin: true, Down: 72 * time.Second},
		"upterm: lost the connection to session abc (no bytes from the peer for 30s); rejoining. Enter retries now, Ctrl-C stops.": {Kind: join.Lost, Err: fmt.Errorf("%w for %s", liveness.ErrSilent, 30*time.Second)},
		// A first join is quiet, as ssh is.
		"": {Kind: join.Joined},
	} {
		require.Equal(t, want, renderEvent(e, tg, next.Add(-8*time.Second), false), want)
	}
	require.Equal(t, "upterm: no host is connected for session abc right now; waiting (Ctrl-C to stop)",
		renderEvent(join.Event{Kind: join.Waiting, Why: join.NoHost, First: true, Since: since, Next: next}, tg, since, true))

	// One row per remaining §7 line, the same way, through renderOutcome. The
	// target as typed is what the -i PATH lines name.
	const typed = "ssh://abc@relay.test"
	changedText, changed := changedKeyRefusal(t)
	deadlineOnIdentity := &join.DeadlineError{Why: join.IdentityFailure, Err: refused}
	otherHostKey := &join.HostKeyError{Err: errors.New("knownhosts: known_hosts:3: illegal base64 data at input byte 4")}
	for _, tc := range []struct {
		out  join.Outcome
		src  join.KeySource
		want string
	}{
		{failedWith(&join.DeadlineError{Why: join.NoHost}), join.KeySource{}, "upterm: no host is connected for session abc on relay.test. It may have ended, or the ID may be wrong."},
		{failedWith(&join.DeadlineError{Why: join.Unreachable, Err: errors.New("dial tcp: refused")}), join.KeySource{}, "upterm: can't reach relay.test: dial tcp: refused"},
		{failedWith(&join.DeadlineError{Why: join.RelayLookup}), join.KeySource{}, "upterm: the relay can't look up sessions right now. Try again shortly."},
		{failedWith(&join.DeadlineError{Why: join.Upstream}), join.KeySource{}, "upterm: the relay can't reach the host of session abc. Try again shortly."},
		{failedWith(&join.DeadlineError{Why: join.Setup, Err: errors.New("shell request refused")}), join.KeySource{}, "upterm: can't start session abc: shell request refused"},

		{failedWith(&join.RefusedError{}), join.KeySource{Agent: 2, Files: 1}, "upterm: session abc refused your keys (2 from the agent, 1 from files). If another key is authorized, pass it with upterm join -i PATH ssh://abc@relay.test; otherwise ask the host to add one of yours."},
		{failedWith(&join.RefusedError{}), join.KeySource{Agent: 2}, "upterm: session abc refused your keys (2 from the agent). If another key is authorized, pass it with upterm join -i PATH ssh://abc@relay.test; otherwise ask the host to add one of yours."},
		{failedWith(&join.RefusedError{}), join.KeySource{Files: 1, Explicit: true}, "upterm: session abc refused your keys (1 from files). If another key is authorized, pass it with upterm join -i PATH ssh://abc@relay.test; otherwise ask the host to add one of yours."},
		{failedWith(&join.RefusedError{}), join.KeySource{Generated: true}, "upterm: session abc admits only authorized users, and you have no SSH key. Create one with ssh-keygen -t ed25519 and ask the host to add it."},
		// Ambiguous comes first: without evidence, the key may not have been refused at all.
		{failedWith(&join.RefusedError{Ambiguous: true}), join.KeySource{Generated: true}, "upterm: session abc refused your keys, or the relay has no such session."},

		{failedWith(&join.IdentityError{Key: "SHA256:k", Err: &host.AgentRefusedError{Key: "SHA256:k", Err: refused}}), join.KeySource{Agent: 1}, "upterm: your SSH agent couldn't sign with SHA256:k: agent refused operation"},
		{failedWith(&join.IdentityError{Key: "SHA256:k", Err: &host.AgentUnavailableError{Socket: "/tmp/agent.sock", Err: errors.New("connection refused")}}), join.KeySource{Agent: 1}, "upterm: your SSH agent couldn't sign with SHA256:k: connection refused"},
		{failedWith(&join.IdentityError{List: true, Err: errors.New("i/o timeout")}), join.KeySource{}, "upterm: couldn't list your SSH agent's keys: i/o timeout. Fix the agent, or pass a key with upterm join -i PATH ssh://abc@relay.test."},
		// No key file loaded either; the agent is the line, as §7 has it.
		{failedWith(&join.IdentityError{List: true, Load: []string{"/k/id_rsa: bad"}, Err: errors.New("i/o timeout")}), join.KeySource{}, "upterm: couldn't list your SSH agent's keys: i/o timeout. Fix the agent, or pass a key with upterm join -i PATH ssh://abc@relay.test."},
		{failedWith(&join.IdentityError{Load: []string{"/k/id_rsa: bad", "/k/id_ecdsa: worse"}}), join.KeySource{}, "upterm: couldn't load your SSH keys (/k/id_rsa: bad; /k/id_ecdsa: worse). Fix them, or pass a key with upterm join -i PATH ssh://abc@relay.test."},

		{failedWith(&join.HostKeyError{Err: fmt.Errorf("refused: %w", join.ErrHostKeyUnknown)}), join.KeySource{}, "upterm: the relay's key is not one you trust; run upterm join again to check it."},
		{failedWith(&join.HostKeyError{Declined: true}), join.KeySource{}, "upterm: the relay's key is not one you trust; run upterm join again to check it."},
		// ssh's mismatch warning, as the host package words it.
		{failedWith(&join.HostKeyError{Changed: true, Err: changed}), join.KeySource{}, changedText},
		{failedWith(join.ErrUpstreamHostKey), join.KeySource{}, "upterm: the relay couldn't verify the host of session abc."},

		{join.Outcome{Kind: join.Exited, Status: 7}, join.KeySource{}, "upterm: connection to session abc ended (status 7)"},
		{join.Outcome{Kind: join.Left}, join.KeySource{}, "upterm: left session abc"},
		{join.Outcome{Kind: join.Stopped}, join.KeySource{}, "upterm: stopped"},

		// Failures §7 has no line for (ruling R3): the error as it is.
		{failedWith(deadlineOnIdentity), join.KeySource{}, "upterm: " + deadlineOnIdentity.Error()},
		{failedWith(otherHostKey), join.KeySource{}, "upterm: " + otherHostKey.Error()},
		{failedWith(errors.New("unable to set terminal to raw mode: bad file descriptor")), join.KeySource{}, "upterm: unable to set terminal to raw mode: bad file descriptor"},
	} {
		line, _ := renderOutcome(tc.out, tg, tc.src, typed)
		require.Equal(t, tc.want, line)
	}

	// The lines the command writes itself, before it joins.
	for want, got := range map[string]string{
		"upterm: skipping /k/id_ed25519_sk: unsupported key type":                                              skipLine("/k/id_ed25519_sk", errors.New("unsupported key type")),
		"upterm: skipping the SSH agent: i/o timeout":                                                          agentSkipLine(errors.New("i/o timeout")),
		"upterm: upterm join needs a terminal.":                                                                needsATerminal,
		"upterm: not a join target: https://abc@relay.test. Use ssh://ID@host, wss://ID@host or ID@host.":      notATargetLine("https://abc@relay.test", parseErr(t, "https://abc@relay.test")),
		"upterm: not a join target: ssh abc@relay.test -p 2222. Did you mean upterm join abc@relay.test:2222?": notATargetLine("ssh abc@relay.test -p 2222", parseErr(t, "ssh abc@relay.test -p 2222")),
		"upterm: not a join target: ssh abc@relay.test. Did you mean upterm join abc@relay.test?":              notATargetLine("ssh abc@relay.test", parseErr(t, "ssh abc@relay.test")),
	} {
		require.Equal(t, want, got)
	}
}

func failedWith(err error) join.Outcome { return join.Outcome{Kind: join.Failed, Err: err} }

func parseErr(t *testing.T, s string) error {
	t.Helper()
	_, err := join.ParseTarget(s)
	require.Error(t, err)
	return err
}

// changedKeyRefusal is the host package's own text for a relay whose known_hosts
// line names another key, and what the CheckHostKey seam returns for it.
func changedKeyRefusal(t *testing.T) (string, error) {
	t.Helper()
	pinned, presented := newPublicKey(t), newPublicKey(t)
	kh := host.KnownHosts{File: writeKnownHosts(t, knownhosts.Line([]string{"relay.test:22"}, pinned)), Stdout: io.Discard}
	hostErr := kh.Check("relay.test:22", relayAddr, presented)
	require.ErrorIs(t, hostErr, host.ErrHostKeyChanged)
	err := newRelayKeys(kh, false, nil).check("relay.test:22", relayAddr, presented)
	require.ErrorIs(t, err, join.ErrHostKeyChanged)
	return hostErr.Error(), err
}

func TestExitCodes(t *testing.T) {
	tg, _ := join.ParseTarget("abc@relay.test")
	for _, tc := range []struct {
		out  join.Outcome
		code int
	}{
		{join.Outcome{Kind: join.Exited, Status: 7}, 7},
		{join.Outcome{Kind: join.Exited}, 0},
		{join.Outcome{Kind: join.Left}, 0},
		{join.Outcome{Kind: join.Stopped}, 130},
		{join.Outcome{Kind: join.Failed, Err: &join.RefusedError{}}, 255},
	} {
		_, code := renderOutcome(tc.out, tg, join.KeySource{Agent: 1}, "abc@relay.test")
		require.Equal(t, tc.code, code)
	}
}

func TestStatusPlainLinesWhenStderrIsNotATerminal(t *testing.T) { // Review Focus 3
	var b bytes.Buffer
	s := newStatus(&b, false /* tty */, mustTarget(t), false)
	s.event(waiting(join.NoHost, 1))
	s.event(waiting(join.NoHost, 2))
	require.NotContains(t, b.String(), "\r\033[K")
	require.Equal(t, 2, strings.Count(b.String(), "\n"))
}

func TestStatusRewritesTheWaitingLineInPlaceOnATerminal(t *testing.T) {
	var b bytes.Buffer
	s := newStatus(&b, true, mustTarget(t), false)
	s.raw(true) // after TakeTerminal
	s.event(waiting(join.NoHost, 1))
	s.event(waiting(join.NoHost, 2))
	s.event(join.Event{Kind: join.Joined, Rejoin: true, Down: time.Second})
	out := b.String()
	require.Equal(t, 2, strings.Count(out, "\r\033[K"))
	require.Contains(t, out, "next try in 2 s\r\nupterm: rejoined session")
	require.True(t, strings.HasSuffix(out, "\r\n"))
}

// A first join says nothing, but the waiting line it ends is put on a line
// of its own, so the session's output starts at the left margin.
func TestStatusEndsTheWaitingLineWhenAFirstJoinSucceeds(t *testing.T) {
	var b bytes.Buffer
	s := newStatus(&b, true, mustTarget(t), false)
	s.event(waiting(join.NoHost, 1))
	s.raw(true)
	s.event(join.Event{Kind: join.Joined})
	require.True(t, strings.HasSuffix(b.String(), "next try in 1 s\r\n"), "%q", b.String())
}

func TestPassphrasePromptRestoresEchoOnEveryWayOut(t *testing.T) { // spec test 19 (the command's half), D11
	type modeLog struct {
		mu  sync.Mutex
		ops []string
	}
	newPrompt := func(in io.Reader, log *modeLog, offGate chan struct{}) passphrasePrompt {
		return passphrasePrompt{in: in, out: io.Discard, echoOff: func() (func(), error) {
			if offGate != nil {
				<-offGate // a slow mode change: cancel lands meanwhile
			}
			log.mu.Lock()
			log.ops = append(log.ops, "off")
			log.mu.Unlock()
			return func() { log.mu.Lock(); log.ops = append(log.ops, "on"); log.mu.Unlock() }, nil
		}}
	}
	final := func(log *modeLog) []string { log.mu.Lock(); defer log.mu.Unlock(); return slices.Clone(log.ops) }

	t.Run("cancelled before echo is off", func(t *testing.T) {
		log, gate := &modeLog{}, make(chan struct{})
		never, _ := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := newPrompt(never, log, gate).prompt(ctx, "id"); done <- err }()
		cancel()
		close(gate)
		require.ErrorIs(t, <-done, context.Canceled)
		require.Equal(t, []string{"off", "on"}, final(log)) // never left off
	})
	t.Run("cancelled mid-read", func(t *testing.T) {
		log := &modeLog{}
		never, _ := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := newPrompt(never, log, nil).prompt(ctx, "id"); done <- err }()
		require.Eventually(t, func() bool { return len(final(log)) == 1 }, time.Second, time.Millisecond)
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(50 * time.Millisecond):
			t.Fatal("the passphrase prompt ignored cancellation")
		}
		time.Sleep(20 * time.Millisecond) // nothing may touch the modes afterwards
		require.Equal(t, []string{"off", "on"}, final(log))
	})
	t.Run("answered, nothing after the line is read", func(t *testing.T) {
		log := &modeLog{}
		in := strings.NewReader("secret\nNEXT")
		pass, err := newPrompt(in, log, nil).prompt(context.Background(), "id")
		require.NoError(t, err)
		require.Equal(t, "secret", string(pass))
		rest, _ := io.ReadAll(in)
		require.Equal(t, "NEXT", string(rest))
		require.Equal(t, []string{"off", "on"}, final(log))
	})
}

// countingReader counts the reads made of it.
type countingReader struct {
	r  io.Reader
	mu sync.Mutex
	n  int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.r.Read(p)
}

func (c *countingReader) reads() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// Once the line is complete no read is pending, so whatever reads the
// terminal next, another prompt or join itself, gets every key typed after
// it.
func TestPassphrasePromptLeavesNoReadPending(t *testing.T) {
	in := &countingReader{r: strings.NewReader("secret\nNEXT")}
	p := passphrasePrompt{in: in, out: io.Discard, echoOff: func() (func(), error) { return func() {}, nil }}
	_, err := p.prompt(context.Background(), "id")
	require.NoError(t, err)
	require.Never(t, func() bool { return in.reads() != len("secret\n") }, 50*time.Millisecond, time.Millisecond)
}

// The prompt is today's, and the newline the guest's Enter didn't echo is
// written for it.
func TestPassphrasePromptAsksForTheFile(t *testing.T) {
	var out bytes.Buffer
	p := passphrasePrompt{in: strings.NewReader("secret\n"), out: &out, echoOff: func() (func(), error) { return func() {}, nil }}
	_, err := p.prompt(context.Background(), "/k/id_ed25519")
	require.NoError(t, err)
	require.Equal(t, "Enter passphrase for key '/k/id_ed25519': \n", out.String())
}

func TestJoinRefusesABadTargetAndANonTerminal(t *testing.T) {
	// runRoot runs Root() with args, pipe stdin and stdout, and returns
	// stderr and the ExitCodeError's code.
	stderr, code := runRoot(t, "join", "https://abc@relay.test")
	require.Equal(t, 255, code)
	require.Equal(t, "upterm: not a join target: https://abc@relay.test. Use ssh://ID@host, wss://ID@host or ID@host.\n", stderr)

	stderr, code = runRoot(t, "join", "ssh://abc@relay.test") // stdin and stdout are pipes
	require.Equal(t, 255, code)
	require.Equal(t, "upterm: upterm join needs a terminal.\n", stderr)
}

// An unquoted paste of an ssh command arrives as several arguments, which
// are read as one text so that the command it is can be recognised.
func TestJoinSuggestsTheTargetOfAPastedSSHCommand(t *testing.T) {
	stderr, code := runRoot(t, "join", "ssh", "abc@relay.test")
	require.Equal(t, 255, code)
	require.Equal(t, "upterm: not a join target: ssh abc@relay.test. Did you mean upterm join abc@relay.test?\n", stderr)
}

// runRoot runs Root() with args, stdin and stdout pipes, and returns what it
// wrote to stderr and the status main would exit with. The configuration
// and state directories are the test's own, so the developer's config file
// sets no flag.
func runRoot(t *testing.T, args ...string) (string, int) {
	t.Helper()
	withConfig(t, "")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, f := range []*os.File{stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW} {
			_ = f.Close()
		}
	})
	origIn, origOut, origErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, stderrW
	defer func() { os.Stdin, os.Stdout, os.Stderr = origIn, origOut, origErr }()

	collected := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stderrR)
		collected <- string(b)
	}()

	root := Root()
	root.SetArgs(args)
	cmd, err := root.ExecuteC()
	// A command that fails skips PersistentPostRunE, which closes the log
	// file; Windows won't remove the state directory while it is open.
	if logger := uptermctx.Logger(cmd.Context()); logger != nil {
		_ = logger.Close()
	}
	require.NoError(t, stderrW.Close())
	return <-collected, exitStatus(err)
}

var relayAddr = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 22}

func newPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return key
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	return file
}

// The command lets join prompt about the relay's key only when known_hosts
// could find it unknown: otherwise join takes the terminal as it starts, and
// a first join's waits answer Enter and ~. (spec rule 4).
func TestConfirmHostKeyOnlyWhenKnownHostsCouldAnswerUnknown(t *testing.T) {
	key := newPublicKey(t)
	authorized := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n")
	const relay = "relay.test:22"
	for _, tc := range []struct {
		name   string
		lines  []string // nil: no file at all
		skip   bool
		prompt bool
	}{
		{name: "no file", prompt: true},
		{name: "no line for the relay", lines: []string{"# nothing here"}, prompt: true},
		{name: "a plain line for the relay", lines: []string{knownhosts.Line([]string{relay}, key)}},
		{name: "a hashed line for the relay", lines: []string{knownhosts.HashHostname(knownhosts.Normalize(relay)) + " " + authorized}},
		{name: "a wildcard line that matches the relay", lines: []string{"*.test " + authorized}},
		{name: "an @cert-authority line for the relay", lines: []string{"@cert-authority relay.test " + authorized}},
		{name: "a line for another host only", lines: []string{knownhosts.Line([]string{"other.test:22"}, key)}, prompt: true},
		{name: "--skip-host-key-check", skip: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "known_hosts")
			if tc.lines != nil {
				file = writeKnownHosts(t, tc.lines...)
			}
			confirm := newRelayKeys(host.KnownHosts{File: file, Stdout: io.Discard}, tc.skip, nil).confirmFor(relay)
			require.Equal(t, tc.prompt, confirm != nil)
		})
	}
}

// CheckHostKey tells join what KnownHosts.Check found, in join's terms, and
// keeps the host package's words for it.
func TestCheckHostKeyMapsKnownHostsAnswers(t *testing.T) {
	pinned, other := newPublicKey(t), newPublicKey(t)
	file := writeKnownHosts(t, knownhosts.Line([]string{"relay.test:22"}, pinned))
	kh := host.KnownHosts{File: file, Stdout: io.Discard}
	keys := newRelayKeys(kh, false, nil)

	require.NoError(t, keys.check("relay.test:22", relayAddr, pinned))

	err := keys.check("elsewhere.test:22", relayAddr, other)
	require.ErrorIs(t, err, join.ErrHostKeyUnknown)
	require.ErrorIs(t, err, host.ErrUnknownHostKey)
	require.NotErrorIs(t, err, join.ErrHostKeyChanged)

	err = keys.check("relay.test:22", relayAddr, other)
	require.ErrorIs(t, err, join.ErrHostKeyChanged)
	require.ErrorIs(t, err, host.ErrHostKeyChanged)
	require.NotErrorIs(t, err, join.ErrHostKeyUnknown)
	require.Equal(t, kh.Check("relay.test:22", relayAddr, other).Error(), err.Error())
}

// --skip-host-key-check accepts a new relay key, as OpenSSH's accept-new
// does, and never a changed one (spec test 30's middle clause; ruling R10).
func TestSkipHostKeyCheckStillRefusesAChangedKey(t *testing.T) {
	pinned, presented := newPublicKey(t), newPublicKey(t)
	file := writeKnownHosts(t, knownhosts.Line([]string{"relay.test:22"}, pinned))
	before, err := os.ReadFile(file)
	require.NoError(t, err)
	var announced bytes.Buffer
	keys := newRelayKeys(host.KnownHosts{File: file, Stdout: &announced}, true, nil)

	err = keys.check("relay.test:22", relayAddr, presented)
	require.ErrorIs(t, err, join.ErrHostKeyChanged)

	after, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "nothing recorded")
	require.Empty(t, announced.String())
}

// With --skip-host-key-check an unknown relay key is recorded, and the line
// saying so, which can come once the terminal is raw, is one of status's.
func TestSkipHostKeyCheckRecordsANewKeyOnAStatusLine(t *testing.T) {
	key := newPublicKey(t)
	file := filepath.Join(t.TempDir(), "known_hosts")
	var b bytes.Buffer
	st := newStatus(&b, true, mustTarget(t), false)
	st.event(waiting(join.Unreachable, 1))
	st.raw(true)
	keys := newRelayKeys(host.KnownHosts{File: file, Stdout: st.writer()}, true, nil)

	require.NoError(t, keys.check("relay.test:22", relayAddr, key))
	require.NoError(t, host.KnownHosts{File: file}.Check("relay.test:22", relayAddr, key), "recorded")

	out := b.String()
	require.Contains(t, out, "next try in 1 s\r\n", "the open waiting line is ended first")
	require.Contains(t, out, "Permanently added")
	require.True(t, strings.HasSuffix(out, "\r\n"), "%q", out)
	require.NotContains(t, strings.ReplaceAll(out, "\r\n", ""), "\n", "every line ends \\r\\n in raw mode")
}

// ConfirmHostKey's signature has no address, so the prompt names the one
// CheckHostKey was given.
func TestConfirmHostKeyShowsTheAddressCheckHostKeyWasGiven(t *testing.T) {
	key := newPublicKey(t)
	var out bytes.Buffer
	keys := newRelayKeys(host.KnownHosts{File: filepath.Join(t.TempDir(), "known_hosts"), Stdout: &out}, false, strings.NewReader("no\n"))
	confirm := keys.confirmFor("relay.test:22")
	require.NotNil(t, confirm)

	require.ErrorIs(t, keys.check("relay.test:22", relayAddr, key), join.ErrHostKeyUnknown)
	accepted, err := confirm(context.Background(), "relay.test:22", key)
	require.NoError(t, err)
	require.False(t, accepted)
	require.Contains(t, out.String(), "'relay.test (192.0.2.7)'")
}
