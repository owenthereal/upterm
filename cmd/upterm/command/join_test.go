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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/join"
	"github.com/spf13/cobra"
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

	// One row per line a run can end with, the same way, through
	// renderOutcome. The target as typed is what the -i PATH lines name.
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
		// No key file loaded either; the agent's failure is the one told.
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

		// Failures with no line of their own: the error as it is.
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
	err := newRelayKeys(kh, false, nil, nil).check("relay.test:22", relayAddr, presented)
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

func TestStatusPlainLinesWhenStderrIsNotATerminal(t *testing.T) {
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

// A waiting line wider than the terminal wraps, and "\033[K" clears only the
// row the cursor is on, its last: the rows above it would pile up, one set
// at each attempt. So the rewrite goes up to the line's first row and clears
// to the end of the screen, and only the newest line is left.
func TestStatusRewritesAWrappedWaitingLineWhole(t *testing.T) {
	since := time.Date(2026, 10, 7, 14, 2, 11, 0, time.Local)
	now := since.Add(time.Minute)
	wait := func(n int, long bool) join.Event {
		return join.Event{Kind: join.Waiting, Why: join.NoHost, Since: since, Next: now.Add(time.Duration(n) * time.Second), Long: long}
	}
	const (
		long1 = "upterm: waiting for the host since 14:02:11; next try in 8 s. The session may have ended or moved; check with the host."
		long2 = "upterm: waiting for the host since 14:02:11; next try in 4 s. The session may have ended or moved; check with the host."
		short = "upterm: waiting for the host since 14:02:11; next try in 2 s"
	)

	var b bytes.Buffer
	s := newStatus(&b, true, mustTarget(t), false)
	s.now = func() time.Time { return now }
	s.columns = func() int { return 40 }
	s.event(wait(8, true))
	s.event(wait(4, true))
	require.Equal(t, "\r\033[K"+long1+"\r\033[2A\033[J"+long2, b.String())
	require.Equal(t, wrapAt(long2, 40), screen(t, b.String(), 40))

	// A line that fits after one that wrapped clears the rows the wrapped
	// one took, and the next is rewritten as any line that fits is.
	b.Reset()
	s = newStatus(&b, true, mustTarget(t), false)
	s.now = func() time.Time { return now }
	s.columns = func() int { return 80 }
	s.event(wait(8, true))
	s.event(wait(2, false))
	s.event(wait(2, false))
	require.Equal(t, "\r\033[K"+long1+"\r\033[1A\033[J"+short+"\r\033[K"+short, b.String())
	require.Equal(t, []string{short}, screen(t, b.String(), 80))
}

// A wrapped waiting line's rewrite never clears what is above it, whichever
// way the terminal's width changed between the two writes (see rewind).
func TestStatusRewriteNeverClearsAboveTheWaitingLine(t *testing.T) {
	since := time.Date(2026, 10, 7, 14, 2, 11, 0, time.Local)
	now := since.Add(time.Minute)
	wait := func(n int) join.Event {
		return join.Event{Kind: join.Waiting, Why: join.NoHost, Since: since, Next: now.Add(time.Duration(n) * time.Second), Long: true}
	}
	const (
		above = "$ upterm join ssh://abc@relay.test"
		long1 = "upterm: waiting for the host since 14:02:11; next try in 8 s. The session may have ended or moved; check with the host."
		long2 = "upterm: waiting for the host since 14:02:11; next try in 4 s. The session may have ended or moved; check with the host."
	)
	rewrite := func(from, to int) string {
		var b bytes.Buffer
		b.WriteString(above + "\n")
		width := from
		s := newStatus(&b, true, mustTarget(t), false)
		s.now = func() time.Time { return now }
		s.columns = func() int { return width }
		s.event(wait(8))
		width = to
		s.event(wait(4))
		return b.String()
	}

	// Three rows at 40 columns, two once the terminal widens to 80 and
	// reflows it.
	out := rewrite(40, 80)
	// The reflowed screen is what the output so far shows at 80 columns.
	require.Equal(t, append([]string{above}, wrapAt(long2, 80)...), screen(t, out, 80))
	require.Equal(t, above+"\n\r\033[K"+long1+"\r\033[1A\033[J"+long2, out)

	// Two rows at 80; narrowed to 40 they stay two on a terminal that
	// doesn't reflow, so the rewrite goes up one, not two.
	require.Equal(t, above+"\n\r\033[K"+long1+"\r\033[1A\033[J"+long2, rewrite(80, 40))
}

// wrapAt is line as a terminal width columns wide shows it.
func wrapAt(line string, width int) []string {
	var rows []string
	for r := []rune(line); len(r) > 0; r = r[min(width, len(r)):] {
		rows = append(rows, string(r[:min(width, len(r))]))
	}
	return rows
}

// screen is what a terminal width columns wide shows once out is written to
// it, for the few of a terminal's controls the status writes: "\r", "\n",
// cursor up ("\033[nA"), and clearing to the end of the row ("\033[K") or
// of the screen ("\033[J"). Text wraps at the right margin, as it does on a
// terminal with auto-wrap on, and trailing blanks are dropped.
func screen(t *testing.T, out string, width int) []string {
	t.Helper()
	var rows [][]rune
	row, col := 0, 0
	reach := func() {
		for len(rows) <= row {
			rows = append(rows, nil)
		}
	}
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRuneInString(out[i:])
		i += size
		switch r {
		case '\r':
			col = 0
		case '\n':
			row, col = row+1, 0
		case '\033':
			end := strings.IndexAny(out[i:], "AJK")
			require.True(t, end > 0 && out[i] == '[', "an unexpected control in %q", out)
			arg, final := out[i+1:i+end], out[i+end]
			i += end + 1
			reach()
			switch final {
			case 'A':
				n := 1
				if arg != "" {
					var err error
					n, err = strconv.Atoi(arg)
					require.NoError(t, err)
				}
				row, col = max(0, row-n), min(col, width-1)
			case 'K':
				rows[row] = rows[row][:min(col, len(rows[row]))]
			case 'J':
				rows[row] = rows[row][:min(col, len(rows[row]))]
				rows = rows[:row+1]
			}
		default:
			if col == width {
				row, col = row+1, 0
			}
			reach()
			for len(rows[row]) <= col {
				rows[row] = append(rows[row], ' ')
			}
			rows[row][col] = r
			col++
		}
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, strings.TrimRight(string(r), " "))
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// stuckWriter is a terminal that stopped taking output: a Write blocks until
// the test ends.
type stuckWriter struct {
	entered chan struct{}
	once    sync.Once
	release chan struct{}
}

func (w *stuckWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

// A status line that join abandoned as it stopped may still be writing to a
// terminal that stopped taking output, holding the status's lock
// (join.Config.Events). What upterm join does once Run returns waits on it
// no longer than the last line's bound, or a stop could never exit.
func TestFinishJoinDoesNotWaitOnAnAbandonedStatusLine(t *testing.T) {
	w := &stuckWriter{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(w.release) })
	s := newStatus(w, true, mustTarget(t), false)
	s.raw(true)
	go s.event(waiting(join.NoHost, 1))
	<-w.entered

	restored, done := make(chan struct{}), make(chan struct{})
	go func() {
		finishJoin(func() { close(restored) }, s, "upterm: stopped")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(logging.LogBound + time.Second):
		t.Fatal("upterm join's exit waited on a status line that join abandoned")
	}
	select {
	case <-restored:
	default:
		t.Fatal("the terminal wasn't restored")
	}
}

// A cancelled passphrase prompt returns at once, and however the prompt
// ends, echo is back on and nothing touches the modes afterwards.
func TestPassphrasePromptRestoresEchoOnEveryWayOut(t *testing.T) {
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
		}, flush: noFlush}
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
		// Slack for -race on CI; a prompt that ignores cancellation never returns.
		case <-time.After(250 * time.Millisecond):
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
// The same holds on both platforms' line ends.
func TestPassphrasePromptLeavesNoReadPending(t *testing.T) {
	for _, crlf := range []bool{false, true} {
		src := strings.NewReader("secret\nNEXT")
		in := &countingReader{r: src}
		p := passphrasePrompt{in: in, out: io.Discard, echoOff: noEcho, flush: noFlush, crlf: crlf}
		pass, err := p.prompt(context.Background(), "id")
		require.NoError(t, err)
		require.Equal(t, "secret", string(pass))
		require.Never(t, func() bool { return in.reads() != len("secret\n") }, 50*time.Millisecond, time.Millisecond, "crlf=%v", crlf)
		rest, _ := io.ReadAll(src)
		require.Equal(t, "NEXT", string(rest), "crlf=%v", crlf)
	}
}

// The Windows console, in the line input the prompt keeps, hands a line over
// with its Enter as "\r\n". The prompt reads it to the '\n', so neither the
// next prompt nor another try at the same key reads an empty passphrase from
// what it left.
func TestPassphrasePromptReadsTheConsoleLineToItsEnd(t *testing.T) {
	in := strings.NewReader("a\r\nb\r\n")
	p := passphrasePrompt{in: in, out: io.Discard, echoOff: noEcho, flush: noFlush, crlf: true}
	first, err := p.prompt(context.Background(), "id")
	require.NoError(t, err)
	second, err := p.prompt(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, []string{string(first), string(second)})
}

// The prompt is today's, and the newline the guest's Enter didn't echo is
// written for it.
func TestPassphrasePromptAsksForTheFile(t *testing.T) {
	var out bytes.Buffer
	p := passphrasePrompt{in: strings.NewReader("secret\n"), out: &out, echoOff: noEcho, flush: noFlush}
	_, err := p.prompt(context.Background(), "/k/id_ed25519")
	require.NoError(t, err)
	require.Equal(t, "Enter passphrase for key '/k/id_ed25519': \n", out.String())
}

func noEcho() (func(), error) { return func() {}, nil }

func noFlush() error { return nil }

// opLog is the order in which things happened.
type opLog struct {
	mu  sync.Mutex
	ops []string
}

func (l *opLog) add(op string) { l.mu.Lock(); defer l.mu.Unlock(); l.ops = append(l.ops, op) }

func (l *opLog) list() []string { l.mu.Lock(); defer l.mu.Unlock(); return slices.Clone(l.ops) }

// loggedReader logs each read of r.
type loggedReader struct {
	log *opLog
	r   io.Reader
}

func (l loggedReader) Read(p []byte) (int, error) {
	l.log.add("read")
	return l.r.Read(p)
}

// A line typed while the agent was listed, or while the relay was dialled,
// is dropped before a question reads its answer, so that it can't be taken
// for a passphrase or answer the relay-key question.
func TestPromptsDropWhatWasTypedBeforeThem(t *testing.T) {
	flushedFirst := func(t *testing.T, log *opLog) {
		t.Helper()
		ops := log.list()
		require.Contains(t, ops, "flush")
		require.Contains(t, ops, "read")
		require.Less(t, slices.Index(ops, "flush"), slices.Index(ops, "read"), "%q", ops)
	}

	log := &opLog{}
	p := passphrasePrompt{
		in: loggedReader{log, strings.NewReader("secret\n")}, out: io.Discard, echoOff: noEcho,
		flush: func() error { log.add("flush"); return nil },
	}
	_, err := p.prompt(context.Background(), "id")
	require.NoError(t, err)
	flushedFirst(t, log)

	log = &opLog{}
	key := newPublicKey(t)
	keys := newRelayKeys(host.KnownHosts{File: filepath.Join(t.TempDir(), "known_hosts"), Stdout: io.Discard}, false,
		loggedReader{log, strings.NewReader("no\n")}, func() error { log.add("flush"); return nil })
	require.ErrorIs(t, keys.check("relay.test:22", relayAddr, key), join.ErrHostKeyUnknown)
	_, err = keys.confirmFor("relay.test:22")(context.Background(), "relay.test:22", key)
	require.NoError(t, err)
	flushedFirst(t, log)
}

// With stderr redirected, as in 2>join.log, both questions are asked on
// stdout, the terminal the guest answers at: in the file, a passphrase
// prompt, which turns echo off, would leave a join that looks hung. With
// stderr a terminal, they are asked there. Either way the line saying that
// --skip-host-key-check recorded a new key, which asks nothing, is a status
// line, on stderr.
func TestJoinAsksAtTheTerminalWhenStderrIsRedirected(t *testing.T) {
	const relay = "relay.test:22"
	key := newPublicKey(t)
	for _, stderrTTY := range []bool{false, true} {
		var stderr, stdout bytes.Buffer
		st := newStatus(&stderr, stderrTTY, mustTarget(t), false)
		f := &joinFlags{knownHosts: filepath.Join(t.TempDir(), "known_hosts")}
		passphrase, keys := f.prompts(st, os.Stdin, &stdout, false)
		// The answers: the terminal's modes and input are other tests'.
		passphrase.in, passphrase.echoOff, passphrase.flush = strings.NewReader("secret\n"), noEcho, noFlush
		keys.in, keys.flush = strings.NewReader("no\n"), noFlush

		_, err := passphrase.prompt(context.Background(), "/k/id_ed25519")
		require.NoError(t, err)
		require.ErrorIs(t, keys.check(relay, relayAddr, key), join.ErrHostKeyUnknown)
		_, err = keys.confirmFor(relay)(context.Background(), relay, key)
		require.NoError(t, err)

		asked, other := stdout.String(), stderr.String()
		if stderrTTY {
			asked, other = other, asked
		}
		require.Contains(t, asked, "Enter passphrase for key '/k/id_ed25519': ", "stderr a terminal: %v", stderrTTY)
		require.Contains(t, asked, "Are you sure you want to continue connecting", "stderr a terminal: %v", stderrTTY)
		require.Empty(t, other, "stderr a terminal: %v", stderrTTY)
	}

	var stderr, stdout bytes.Buffer
	st := newStatus(&stderr, false, mustTarget(t), false)
	f := &joinFlags{knownHosts: filepath.Join(t.TempDir(), "known_hosts"), skipHostKeyCheck: true}
	_, keys := f.prompts(st, os.Stdin, &stdout, false)
	require.NoError(t, keys.check(relay, relayAddr, key))
	require.Contains(t, stderr.String(), "Permanently added")
	require.Empty(t, stdout.String())
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
// are read as one text so that the command it is can be recognised. join's
// flags stop at the first argument, so the command's own flags, -p and -o,
// arrive among them.
func TestJoinSuggestsTheTargetOfAPastedSSHCommand(t *testing.T) {
	// The commands as upterm prints them, and the arguments the guest's shell
	// makes of each.
	direct, err := buildSessionDetail(&api.GetSessionResponse{Host: "ssh://relay.test:2222", SshUser: "abc"})
	require.NoError(t, err)
	require.Equal(t, "ssh abc@relay.test -p 2222", direct.SSHCommand)
	proxied, err := buildSessionDetail(&api.GetSessionResponse{Host: "wss://relay.test", SshUser: "abc"})
	require.NoError(t, err)
	require.Equal(t, `ssh -o ProxyCommand='upterm proxy '\''wss://abc@relay.test'\''' abc@relay.test:443`, proxied.SSHCommand)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"ssh", "abc@relay.test"}, "upterm: not a join target: ssh abc@relay.test. Did you mean upterm join abc@relay.test?\n"},
		{[]string{"ssh", "abc@relay.test", "-p", "2222"}, "upterm: not a join target: ssh abc@relay.test -p 2222. Did you mean upterm join abc@relay.test:2222?\n"},
		{
			[]string{"ssh", "-o", "ProxyCommand=upterm proxy 'wss://abc@relay.test'", "abc@relay.test:443"},
			`upterm: not a join target: ssh -o 'ProxyCommand=upterm proxy '\''wss://abc@relay.test'\''' abc@relay.test:443. Did you mean upterm join wss://abc@relay.test?` + "\n",
		},
	} {
		stderr, code := runRoot(t, append([]string{"join"}, tc.args...)...)
		require.Equal(t, 255, code, "%q", tc.args)
		require.Equal(t, tc.want, stderr, "%q", tc.args)
	}
}

// Flags after a target that stands alone are join's own, as in the help's
// --proxy example. They are supplied flags as much as ones before it: the
// environment doesn't override them, and -i there is as explicit as -i first.
func TestJoinTakesItsFlagsAfterTheTarget(t *testing.T) {
	t.Setenv("UPTERM_PROXY", "http://env.invalid:3128")
	suppliedFlags = map[string]bool{}
	stderr, code, cmd := runRootCmd(t, "join", "abc@relay.test", "--wait", "--proxy", "http://flag.invalid:3128", "-i", "/no/such/key")
	require.Equal(t, 255, code)
	require.Equal(t, "upterm: upterm join needs a terminal.\n", stderr) // past the target, in a pipe
	require.True(t, suppliedFlags["wait"])
	require.True(t, identitiesOnlyRequested())
	proxy, err := cmd.Flags().GetString("proxy")
	require.NoError(t, err)
	require.Equal(t, "http://flag.invalid:3128", proxy)

	// --help after the target is help, not a join.
	stderr, code = runRoot(t, "join", "abc@relay.test", "--help")
	require.Equal(t, 0, code)
	require.Empty(t, stderr)
}

// A flag join doesn't have, or no target at all, is a failure to join: one
// line of its own, and 255.
func TestJoinFlagErrorsAreOneLine(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--bogus", "abc@relay.test"}, "upterm: unknown flag: --bogus\n"},
		{[]string{"abc@relay.test", "-p", "2222"}, "upterm: unknown shorthand flag: 'p' in -p\n"},
		{nil, "upterm: requires at least 1 arg(s), only received 0\n"},
	} {
		stderr, code := runRoot(t, append([]string{"join"}, tc.args...)...)
		require.Equal(t, 255, code, "%q", tc.args)
		require.Equal(t, tc.want, stderr, "%q", tc.args)
	}
}

// runRoot runs Root() with args, stdin and stdout pipes, and returns what it
// wrote to stderr and the status main would exit with. The configuration
// and state directories are the test's own, so the developer's config file
// sets no flag.
func runRoot(t *testing.T, args ...string) (string, int) {
	t.Helper()
	stderr, code, _ := runRootCmd(t, args...)
	return stderr, code
}

// runRootCmd is runRoot, and the command that ran.
func runRootCmd(t *testing.T, args ...string) (string, int, *cobra.Command) {
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
	return <-collected, exitStatus(err), cmd
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
// a first join's waits answer Enter and ~.
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
			confirm := newRelayKeys(host.KnownHosts{File: file, Stdout: io.Discard}, tc.skip, nil, nil).confirmFor(relay)
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
	keys := newRelayKeys(kh, false, nil, nil)

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
// does, and never a changed one.
func TestSkipHostKeyCheckStillRefusesAChangedKey(t *testing.T) {
	pinned, presented := newPublicKey(t), newPublicKey(t)
	file := writeKnownHosts(t, knownhosts.Line([]string{"relay.test:22"}, pinned))
	before, err := os.ReadFile(file)
	require.NoError(t, err)
	var announced bytes.Buffer
	keys := newRelayKeys(host.KnownHosts{File: file, Stdout: &announced}, true, nil, nil)

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
	keys := newRelayKeys(host.KnownHosts{File: file, Stdout: st.writer()}, true, nil, nil)

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
	keys := newRelayKeys(host.KnownHosts{File: filepath.Join(t.TempDir(), "known_hosts"), Stdout: &out}, false, strings.NewReader("no\n"), noFlush)
	confirm := keys.confirmFor("relay.test:22")
	require.NotNil(t, confirm)

	require.ErrorIs(t, keys.check("relay.test:22", relayAddr, key), join.ErrHostKeyUnknown)
	accepted, err := confirm(context.Background(), "relay.test:22", key)
	require.NoError(t, err)
	require.False(t, accepted)
	require.Contains(t, out.String(), "'relay.test (192.0.2.7)'")
}

// cancelOnRead is a guest who presses Ctrl-C, which ends ctx, rather than
// answering: its first read cancels, and then waits on r.
type cancelOnRead struct {
	cancel context.CancelFunc
	r      io.Reader
}

func (c cancelOnRead) Read(p []byte) (int, error) {
	c.cancel()
	return c.r.Read(p)
}

// The guest's Enter, echoed, ends the line the relay-key question leaves
// open. A question that ends without an answer, at a Ctrl-C or the end of
// input, has its line ended for it, so that what follows, the run's last
// line, starts a line of its own.
func TestAnUnansweredRelayKeyQuestionEndsItsLine(t *testing.T) {
	const relay = "relay.test:22"
	const question = "(yes/no/[fingerprint])? "
	key := newPublicKey(t)
	ask := func(ctx context.Context, in io.Reader) string {
		var b bytes.Buffer
		st := newStatus(&b, true, mustTarget(t), false)
		keys := newRelayKeys(host.KnownHosts{File: filepath.Join(t.TempDir(), "known_hosts"), Stdout: st.promptOut(nil)}, false, in, noFlush)
		require.ErrorIs(t, keys.check(relay, relayAddr, key), join.ErrHostKeyUnknown)
		_, _ = keys.confirmFor(relay)(ctx, relay, key)
		st.last("upterm: stopped")
		return b.String()
	}

	// Answered: the echo of the guest's Enter, which this test doesn't
	// write, is what ends the line, so nothing is added.
	out := ask(context.Background(), strings.NewReader("no\n"))
	require.True(t, strings.HasSuffix(out, question+"upterm: stopped\r\n"), "%q", out)

	out = ask(context.Background(), strings.NewReader(""))
	require.True(t, strings.HasSuffix(out, question+"\nupterm: stopped\r\n"), "%q", out)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	never, unblock := io.Pipe()
	t.Cleanup(func() { _ = unblock.Close() })
	out = ask(ctx, cancelOnRead{cancel, never})
	require.True(t, strings.HasSuffix(out, question+"\nupterm: stopped\r\n"), "%q", out)
}
