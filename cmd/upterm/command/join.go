package command

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/relaydial"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/join"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

// joinFlags are upterm join's flags, kept on the command rather than in
// package variables.
type joinFlags struct {
	privateKeys      []string
	knownHosts       string
	skipHostKeyCheck bool
	proxy            string
	escapeChar       string
	wait             bool

	// Set by resolveTarget, join's Args.
	target join.Target
	typed  string // the target as the guest typed it
}

func joinCmd() *cobra.Command {
	var f joinFlags
	cmd := &cobra.Command{
		Use:   "join [flags] TARGET",
		Short: "Join a session as a guest, and rejoin it after a drop",
		Long: `Join a session as a guest, and rejoin it whenever the connection drops.
TARGET is the connect string on the host's ➤ Join: line.

In a session, ~. at the start of a line leaves (or --escape-char), and on
Unix ~^Z suspends upterm join; fg resumes it. While it waits to rejoin,
Enter retries at once and Ctrl-C stops.

upterm join doesn't read ~/.ssh/config: per-host IdentityFile, User and
ProxyJump don't apply, the target can't be a host alias, and FIDO keys work
only through the agent. Use -i, or plain ssh, for those.

A forced command (upterm host --force-command) starts again on each rejoin;
nothing the previous one did is undone.

Exits with the session's status when one arrives, 0 when you leave (~.), 130
when stopped, and 255 when it can't join.`,
		Example: `  # Join a session, with the connect string the host shares:
  upterm join ssh://ID@uptermd.upterm.dev

  # The same; a target without a scheme is ssh:
  upterm join ID@uptermd.upterm.dev

  # Join over a WebSocket, through an HTTP proxy:
  upterm join wss://ID@uptermd.upterm.dev --proxy http://proxy.example.com:3128

  # Wait for a host that hasn't connected yet, with no 30 s limit:
  upterm join --wait ID@uptermd.upterm.dev`,
		Args: f.resolveTarget,
		RunE: f.run,
		// Config errors, which PersistentPreRunE finds before RunE, as well
		// as the failures joinFailure and the join outcomes carry (D2a).
		Annotations: map[string]string{failureCodeAnnotation: strconv.Itoa(exitJoinFailed)},
	}
	// Every failure, a flag's or a missing target's before RunE too, is told
	// on one line of upterm join's own, and returns only its status, for
	// which Exit prints nothing more.
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return joinFailure("upterm: " + err.Error())
	})

	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("error getting user home directory", "error", err)
		os.Exit(1)
	}
	flags := cmd.Flags()
	// join's flags stop at the first argument that isn't one, so that an
	// unquoted paste of one of the ssh commands upterm prints for guests,
	// its -p and -o included, reaches resolveTarget whole, which can then
	// suggest the join target it reaches. resolveTarget still reads join's
	// flags after a target that stands alone.
	flags.SetInterspersed(false)
	flags.StringSliceVarP(&f.privateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "Identity files. Supplying this makes the list the whole set, like OpenSSH's IdentitiesOnly: each file must load, and a .pub selects that key in the SSH agent, as upterm host -i does. By default, the agent's keys are offered first, then the listed files that exist and the agent doesn't hold, and a generated key when there are neither.")
	flags.StringVar(&f.knownHosts, "known-hosts", defaultKnownHost(homeDir), "Known keys of relays. An unknown relay key is shown for confirmation, as ssh does.")
	// Keep help and generated docs portable without changing the runtime
	// defaults, as upterm host does.
	flags.Lookup("private-key").DefValue = "[~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}]"
	flags.Lookup("known-hosts").DefValue = "~/.ssh/known_hosts"
	flags.BoolVar(&f.skipHostKeyCheck, "skip-host-key-check", false, "Accept an unknown relay key and record it without asking (similar to SSH's StrictHostKeyChecking=accept-new). A changed key is still refused.")
	flags.StringVar(&f.proxy, "proxy", "", "HTTP proxy to reach the relay through (e.g. http://proxy.example.com:3128). Works with ssh, ws and wss targets. Without it, ws and wss use HTTPS_PROXY/HTTP_PROXY, and ssh goes direct.")
	flags.StringVar(&f.escapeChar, "escape-char", "~", "Escape character for leaving (ESC-CHAR followed by . at the start of a line) or suspending (ESC-CHAR followed by ^Z, Unix only), or 'none' to disable.")
	flags.BoolVar(&f.wait, "wait", false, "On the first join, wait for a host as a rejoin does, with no 30 s limit.")
	return cmd
}

// resolveTarget is join's Args. It finds the target, and any of join's flags
// typed after it, before root's PersistentPreRunE reads which flags were
// supplied, so that those count as much as flags before it.
//
// An unquoted paste of an ssh command arrives as several arguments, and is
// read as the one text it was. One of the ssh commands upterm prints for
// guests is the target it reaches, which is then the target as typed, so
// that a line suggesting -i repeats the target rather than the command. Any
// other ssh command is refused, since join would ignore its options. A
// refused text whose first argument is a target by itself and a later one
// starts with "-" is that target and join's flags after it: upterm join
// ID@host --wait.
func (f *joinFlags) resolveTarget(c *cobra.Command, args []string) error {
	if err := cobra.MinimumNArgs(1)(c, args); err != nil {
		return joinFailure("upterm: " + err.Error())
	}
	typed := pastedText(args)
	target, err := join.ParseTarget(typed)
	if err == nil {
		f.target, f.typed = target, typed
		return nil
	}
	var bad *join.TargetError
	if errors.As(err, &bad) && bad.Suggestion != "" {
		// A suggestion parses as a target (join.TargetError).
		if target, err := join.ParseTarget(bad.Suggestion); err == nil {
			f.target, f.typed = target, bad.Suggestion
			return nil
		}
	}
	isFlag := func(arg string) bool { return strings.HasPrefix(arg, "-") }
	if first, ferr := join.ParseTarget(args[0]); ferr == nil && slices.ContainsFunc(args[1:], isFlag) {
		flags := c.Flags()
		if err := flags.Parse(args[1:]); err != nil {
			return joinFailure("upterm: " + err.Error())
		}
		// Cobra looked for --help before the target only.
		if help, _ := flags.GetBool("help"); help {
			return pflag.ErrHelp
		}
		if flags.NArg() == 0 {
			f.target, f.typed = first, args[0]
			return nil
		}
	}
	return joinFailure(notATargetLine(typed))
}

// pastedText is args as the one text a paste of a command was: joined with
// spaces, each quoted as a shell needs to read it back as the same argument.
// So the words the guest's shell split are the words the target parser
// reads: the ws form's ProxyCommand is one argument that holds spaces and
// quotes, which joined as it is would read as three words.
func pastedText(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	const plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"
	words := make([]string, len(args))
	for i, arg := range args {
		words[i] = arg
		if arg == "" || strings.ContainsFunc(arg, func(r rune) bool { return !strings.ContainsRune(plain, r) }) {
			words[i] = quoteShellArg(arg)
		}
	}
	return strings.Join(words, " ")
}

func (f *joinFlags) run(c *cobra.Command, _ []string) error {
	target, typed := f.target, f.typed
	lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, resolveTerm("", os.Getenv("TERM")))
	if lt.pty == nil || !lt.rawMode {
		return joinFailure(needsATerminal)
	}
	escape, err := parseEscapeChar(f.escapeChar)
	if err != nil {
		return joinFailure("upterm: " + err.Error())
	}
	proxy, err := parseProxyURL(f.proxy)
	if err != nil {
		return joinFailure("upterm: " + err.Error())
	}

	ctx, cancel := notifyDetachSignals(c.Context())
	defer cancel()
	st := statusOn(os.Stderr, target, f.wait)
	passphrase, keys := f.prompts(st, os.Stdin, os.Stdout, connectionIsProxied(target.URL().String(), proxy))

	// In cooked mode, before the relay is dialled: Ctrl-C here is SIGINT,
	// which ends ctx.
	identity, err := host.NewGuestIdentity(ctx, host.GuestIdentityOptions{
		// From any origin, as upterm host reads it: a list named in the
		// environment or the config file is as explicit as -i.
		IdentitiesOnly: identitiesOnlyRequested(),
		Files:          f.privateKeys,
		AgentSocket:    os.Getenv("SSH_AUTH_SOCK"),
		Passphrase:     passphrase.prompt,
		OnSkip:         func(file string, err error) { _, _ = fmt.Fprintln(st.writer(), skipLine(file, err)) },
		OnAgentSkip:    func(err error) { _, _ = fmt.Fprintln(st.writer(), agentSkipLine(err)) },
	})
	if err != nil {
		out := join.Outcome{Kind: join.Failed, Err: err}
		if ctx.Err() != nil {
			out = join.Outcome{Kind: join.Stopped}
		}
		line, code := renderOutcome(out, target, join.KeySource{}, typed)
		_, _ = fmt.Fprintln(st.writer(), line)
		return ExitCodeError{Code: code}
	}

	logger := slog.New(slog.DiscardHandler)
	if l := uptermctx.Logger(c.Context()); l != nil {
		logger = l.Logger
	}
	raw := &rawTerminal{f: os.Stdin, owned: tty.Owned}
	terminal := &attach.Terminal{
		Stdout:  os.Stdout,
		Pty:     lt.pty,
		Resizes: watchResize(ctx, os.Stdout),
		Escape:  escape,
		Logger:  logger,
	}
	if suspendSupported && suspendAvailable() {
		terminal.Suspend = func() (termsize.Size, bool) { return suspendLocalTerminal(raw, os.Stdout, stopSelf) }
	}

	out := join.Run(ctx, join.Config{
		Target: target,
		Dial: func(ctx context.Context) (net.Conn, error) {
			// The address is the check's business, and join gives it the
			// target's host:port.
			conn, _, err := relaydial.Dial(ctx, target.URL(), target.User, true, proxy)
			return conn, err
		},
		Identity:       join.Identity{Signers: identity.Signers, Source: identity.Source()},
		CheckHostKey:   keys.check,
		ConfirmHostKey: keys.confirmFor(target.Host),
		Terminal:       terminal,
		Size:           func() termsize.Size { return terminalSize(os.Stdout) },
		Input:          os.Stdin,
		TakeTerminal: func() error {
			if err := takeTerminal(raw); err != nil {
				return err
			}
			st.raw(true)
			return nil
		},
		Events: st.event,
		Wait:   f.wait,
	})
	line, code := renderOutcome(out, target, identity.Source(), typed)
	finishJoin(raw.restore, st, line)
	if code == 0 {
		return nil
	}
	return ExitCodeError{Code: code}
}

// prompts are upterm join's two questions, a key's passphrase and whether
// to trust an unknown relay key, the second asked through the relay-key
// seams it comes with. Each is asked where joinStatus.promptOut says, and
// answered on stdin, once what was typed there before it is dropped.
func (f *joinFlags) prompts(st *joinStatus, stdin *os.File, stdout io.Writer, proxied bool) (passphrasePrompt, *relayKeys) {
	out := st.promptOut(stdout)
	flush := func() error { return flushInput(stdin) }
	kh := host.KnownHosts{File: f.knownHosts, Stdout: out, Proxied: proxied}
	if f.skipHostKeyCheck {
		// Nothing is asked. Recording a new key says so on a line of the
		// status's, which can come once the terminal is raw.
		kh.Stdout = st.writer()
	}
	passphrase := passphrasePrompt{in: stdin, out: out, echoOff: echoOff(stdin), flush: flush, crlf: lineEndsCRLF}
	return passphrase, newRelayKeys(kh, f.skipHostKeyCheck, stdin, flush)
}

// joinFailure is a failure before anything else has been written: its line
// on stderr, and 255.
func joinFailure(line string) error {
	_, _ = fmt.Fprintln(os.Stderr, line)
	return ExitCodeError{Code: exitJoinFailed}
}

// finishJoin is what upterm join does once join.Run has returned: the
// guest's terminal put back as it was, then the run's last line. Nothing here
// may wait on the status without a bound. A status line that a stop
// abandoned may still hold it, writing to a terminal that stopped taking
// output (join.Config.Events), and SIGINT and SIGTERM are caught, so only
// kill -9 would end the wait. last waits within its bound.
func finishJoin(restore func(), st *joinStatus, line string) {
	restore()
	st.last(line)
}

// terminalSize is f's size, or the default size when it can't be measured.
func terminalSize(f *os.File) termsize.Size {
	size, err := tty.Size(f)
	if err != nil {
		return termsize.Default
	}
	return size
}

// takeTerminal is TakeTerminal's work on the guest's terminal: raw mode, and
// then whatever was typed before it dropped. Keys typed while the
// terminal was cooked, before the first join, belong to no session, and
// would otherwise be the first that one read.
func takeTerminal(raw *rawTerminal) error {
	if err := raw.enter(); err != nil {
		return fmt.Errorf("unable to set terminal to raw mode: %w", err)
	}
	if err := flushInput(raw.f); err != nil {
		return fmt.Errorf("unable to drop the keys typed before joining: %w", err)
	}
	return nil
}

// relayKeys is the relay-key seams on known_hosts: CheckHostKey, and
// ConfirmHostKey when a prompt is possible.
type relayKeys struct {
	kh   host.KnownHosts
	skip bool      // --skip-host-key-check: record an unknown key without asking
	in   io.Reader // where the confirmation's answer is read
	// flush drops what was typed on in before the question.
	flush func() error

	mu sync.Mutex
	// remote is the address CheckHostKey was last given, which the
	// confirmation shows: ConfirmHostKey isn't given one.
	remote net.Addr
}

func newRelayKeys(kh host.KnownHosts, skip bool, in io.Reader, flush func() error) *relayKeys {
	return &relayKeys{kh: kh, skip: skip, in: in, flush: flush}
}

// hostKeyRefusal is KnownHosts.Check's refusal as join's seam reports it:
// the host package's text, unchanged, since the changed-key warning is what
// the guest is shown, and a match for both its sentinel and join's.
type hostKeyRefusal struct {
	err error // KnownHosts.Check's
	as  error // join.ErrHostKeyUnknown or join.ErrHostKeyChanged
}

func (e *hostKeyRefusal) Error() string   { return e.err.Error() }
func (e *hostKeyRefusal) Unwrap() []error { return []error{e.err, e.as} }

// check is join.Config.CheckHostKey. It never asks anyone: an unknown key is
// join.ErrHostKeyUnknown, for join to ask about if it still may, and with
// --skip-host-key-check is recorded instead, as OpenSSH's accept-new does. A
// changed key is join.ErrHostKeyChanged either way. Anything else, a
// revoked key or a known_hosts that doesn't parse, is as KnownHosts.Check
// says, and stops the join too.
func (r *relayKeys) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	r.mu.Lock()
	r.remote = remote
	r.mu.Unlock()

	err := r.kh.Check(hostname, remote, key)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, host.ErrUnknownHostKey):
		if r.skip {
			return r.kh.Record(hostname, key, true)
		}
		return &hostKeyRefusal{err: err, as: join.ErrHostKeyUnknown}
	case errors.Is(err, host.ErrHostKeyChanged):
		return &hostKeyRefusal{err: err, as: join.ErrHostKeyChanged}
	}
	return err
}

// confirmFor is join.Config.ConfirmHostKey for a relay at hostname: confirm
// when known_hosts could find the relay's key unknown, and nil when it can't,
// or nothing is to be asked. join holds the guest's keys back until the
// first handshake only while a prompt is possible, so that a first join's
// waits answer Enter and ~. whenever they can.
func (r *relayKeys) confirmFor(hostname string) func(ctx context.Context, hostname string, key ssh.PublicKey) (bool, error) {
	if r.skip || !r.couldBeUnknown(hostname) {
		return nil
	}
	return r.confirm
}

// couldBeUnknown reports whether no known_hosts line matches hostname. It
// asks Check about a key made up here, which no line names, so that
// knownhosts' own matching answers, hashed and wildcard lines included: a
// key no line matches is unknown, and one where a line matches the host,
// plain or @cert-authority, is changed.
func (r *relayKeys) couldBeUnknown(hostname string) bool {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		// Asking stays possible, which is the default for a new relay.
		return true
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		return true
	}
	// Check reads the remote's address, so it can't be nil; knownhosts
	// matches on hostname whenever there is one.
	return errors.Is(r.kh.Check(hostname, &net.TCPAddr{}, key), host.ErrUnknownHostKey)
}

// confirm asks the guest whether to trust key. What was typed before the
// question, while the agent was listed or the relay dialled, is dropped
// first, as OpenSSH's prompts drop it, so that a line typed ahead can't
// answer it. The guest's Enter, echoed, ends the line the question leaves
// open; a question that ends without an answer, at a Ctrl-C or the end of
// input, has its line ended here, so that what follows starts a line of
// its own.
func (r *relayKeys) confirm(ctx context.Context, hostname string, key ssh.PublicKey) (bool, error) {
	r.mu.Lock()
	remote := r.remote
	r.mu.Unlock()
	if remote == nil {
		remote = unknownAddr{}
	}
	// Confirm asks nothing once ctx has ended.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := r.flush(); err != nil {
		return false, fmt.Errorf("unable to drop the keys typed before the question: %w", err)
	}
	accepted, err := r.kh.Confirm(ctx, r.in, hostname, remote, key)
	if err != nil && (ctx.Err() != nil || errors.Is(err, io.EOF)) {
		_, _ = io.WriteString(r.kh.Stdout, "\n")
	}
	return accepted, err
}

// unknownAddr stands for a relay address CheckHostKey wasn't given, which
// join, asking only about a key CheckHostKey found unknown, never leaves it.
type unknownAddr struct{}

func (unknownAddr) Network() string { return "tcp" }
func (unknownAddr) String() string  { return "unknown" }

// passphrasePrompt is GuestIdentityOptions.Passphrase, a prompt on the
// guest's terminal.
type passphrasePrompt struct {
	in  io.Reader
	out io.Writer
	// echoOff turns the terminal's echo off, and returns what turns it back
	// on: see join_echo_unix.go and join_echo_windows.go.
	echoOff func() (restore func(), err error)
	// flush drops what was typed on in before the prompt.
	flush func() error
	// crlf is the Windows console's line end: its line input hands a line
	// over with the Enter as "\r\n", so '\r' is dropped and '\n' ends the
	// line, which leaves nothing of it for the next read. Elsewhere either
	// ends the line (see lineEndsCRLF).
	crlf bool
}

// prompt asks for file's passphrase and reads one line with echo off. It
// owns the terminal's modes: it turns echo off itself before anything is
// read, and back on, on its own goroutine, however it returns; so a cancel
// can't race a change of mode. term.ReadPassword changes them inside the
// read it blocks in, which is why it isn't used. What was typed before the
// prompt, while the agent was listed, say, is dropped before the first
// read, as OpenSSH's readpassphrase drops it, so that a line typed ahead
// isn't taken for the passphrase. Another goroutine does nothing but read
// in a byte at a time, one when asked, so no read is pending once the line
// is complete, and nothing typed after it is taken.
//
// Once ctx ends, prompt returns ctx's error at once. A read in flight then
// is abandoned with the process, which a cancelled prompt is ending: a
// terminal read can't be interrupted.
func (p passphrasePrompt) prompt(ctx context.Context, file string) ([]byte, error) {
	_, _ = fmt.Fprintf(p.out, "Enter passphrase for key '%s': ", file)
	// The guest's Enter wasn't echoed, so the line is ended here, however
	// the prompt ends.
	defer func() { _, _ = io.WriteString(p.out, "\n") }()

	restore, err := p.echoOff()
	if err != nil {
		return nil, err
	}
	defer restore()
	if err := p.flush(); err != nil {
		return nil, fmt.Errorf("unable to drop the keys typed before the prompt: %w", err)
	}

	type read struct {
		b   byte
		err error
	}
	asks := make(chan struct{})
	reads := make(chan read, 1)
	defer close(asks)
	go func() {
		b := make([]byte, 1)
		for range asks {
			n, err := p.in.Read(b)
			for n == 0 && err == nil {
				n, err = p.in.Read(b)
			}
			if n == 1 {
				// An error that came with the byte comes again with the next read.
				err = nil
			}
			reads <- read{b[0], err}
		}
	}()

	var line []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case asks <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case r := <-reads:
			switch {
			case r.err != nil && errors.Is(r.err, io.EOF) && len(line) > 0:
				return line, nil
			case r.err != nil:
				return nil, r.err
			case r.b == '\r' && p.crlf:
				continue
			case r.b == '\r' || r.b == '\n':
				return line, nil
			}
			line = append(line, r.b)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
