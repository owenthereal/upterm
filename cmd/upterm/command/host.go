package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	// Imported by non-test code on purpose: testing.Testing() is the
	// designed way to ask whether this binary is a test binary, and since
	// Go 1.13 importing the package registers no flags.
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gen2brain/beeep"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/icon"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/internal/version"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// UserDiscardedError represents a user's intentional choice to discard the session
type UserDiscardedError struct{}

func (e UserDiscardedError) Error() string {
	return "session discarded by user"
}

// Unwrap makes a discard an abandoned startup rather than a failed one.
//
// displaySession returns this from SessionCreatedCallback, and Host records
// every error from there as startup_failed unless it wraps ErrSessionAbandoned.
// Nothing failed here: the operator was shown the session and said no, and a
// record saying otherwise sends whoever reads it looking for a fault that
// never happened.
func (e UserDiscardedError) Unwrap() error {
	return host.ErrSessionAbandoned
}

// UserInterruptedError represents a user's Ctrl+C interruption
type UserInterruptedError struct{}

func (e UserInterruptedError) Error() string {
	return "interrupted by user"
}

// Unwrap makes an interruption an abandoned startup rather than a failed
// one, for the same reason UserDiscardedError.Unwrap does: nothing failed,
// the operator hit Ctrl+C at the prompt instead of answering it.
func (e UserInterruptedError) Unwrap() error {
	return host.ErrSessionAbandoned
}

// SilentError wraps an error that has already been displayed to the user.
// main.go checks for this type to avoid duplicate logging.
type SilentError struct {
	Err error
}

func (e SilentError) Error() string {
	return e.Err.Error()
}

func (e SilentError) Unwrap() error {
	return e.Err
}

var (
	flagServer                  string
	flagForceCommand            string
	flagPrivateKeys             []string
	flagKnownHostsFilename      string
	flagAuthorizedKeys          string
	flagAuthorizedUsers         []string
	flagCodebergUsers           []string
	flagGitHubUsers             []string
	flagGitLabUsers             []string
	flagSourceHutUsers          []string
	flagReadOnly                bool
	flagAccept                  bool
	flagSkipHostKeyCheck        bool
	flagProxy                   string
	flagNoSFTP                  bool
	flagAllowLocalTCPForwarding bool
	flagPtySize                 string
	flagTerm                    string
	flagName                    string
	flagDetach                  bool
	flagHostOutput              string
	// flagHostEscapeChar carries its flag's default here as well as in the
	// registration below, so parseEscapeChar has a value to accept when the
	// var is read without hostCmd having run — which is every unit test that
	// calls parseHostOptions.
	flagHostEscapeChar = "~"
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host a terminal session",
		Long: `Host a terminal session via a reverse SSH tunnel to the Upterm server.

The session links the host and client IO to a command's IO. Authentication with the
Upterm server uses, in this order:
  1. SSH agent keys, when an agent is running and holds any
  2. Private key files: ~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}
  3. Auto-generated ephemeral key, when neither is available

Supplying --private-key makes the named list the whole set instead; see its help.

To authorize client connections, use --authorized-keys to specify an authorized_keys file
containing client public keys.

The session runs in a process of its own. This terminal is a client of it:
type ~. at the start of a line (or --escape-char) to leave the session
running, reattach with 'upterm attach NAME', and end it with
'upterm session stop NAME'. With --detach nothing is attached: the session
starts in the background and this command prints how to reach it.`,
		Example: `  # Host a terminal session running $SHELL, attaching client's IO to the host's:
  upterm host

  # Accept client connections automatically without prompts:
  upterm host --accept

  # Host a terminal session allowing only specified public key(s) to connect:
  upterm host --authorized-keys PATH_TO_AUTHORIZED_KEY_FILE

  # Authorize a user by fetching their public keys from a code-hosting service:
  upterm host --authorized-user github:username

  # Host a session executing a custom command:
  upterm host -- docker run --rm -ti ubuntu bash

  # Host a 'tmux new -t pair-programming' session, forcing clients to join with 'tmux attach -t pair-programming':
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Allow clients to use local TCP forwarding (ssh -L) through the hosted session:
  upterm host --allow-local-tcp-forwarding

  # Use a different Uptermd server, hosting a session via WebSocket:
  upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND

  # Start a session in the background and print how to reach it:
  upterm host --detach --accept --github-user alice

  # The same, as JSON for a script:
  upterm host --detach --accept --github-user alice -o json`,
		PreRunE: validateShareRequiredFlags,
		RunE:    shareRunE,
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("error getting user home directory", "error", err)
		os.Exit(1)
	}

	cmd.PersistentFlags().StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "Specify the upterm server address (required). Supported protocols: ssh, ws, wss.")
	cmd.PersistentFlags().StringVarP(&flagForceCommand, "force-command", "f", "", "Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "Identity files for authenticating with the upterm server. Supplying this makes the list the whole set, like OpenSSH's IdentitiesOnly: each file must load, a .pub selects that key in the SSH agent, and other agent keys are not offered. By default, the agent's keys are used when it has any, then the listed files that exist, then a generated key.")
	cmd.PersistentFlags().StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(homeDir), "Specify a file containing known keys for remote hosts (required).")
	// Keep help and generated docs portable without changing the runtime defaults.
	cmd.PersistentFlags().Lookup("private-key").DefValue = "[~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}]"
	cmd.PersistentFlags().Lookup("known-hosts").DefValue = "~/.ssh/known_hosts"

	cmd.PersistentFlags().StringVar(&flagAuthorizedKeys, "authorized-keys", "", "Specify a authorize_keys file listing authorized public keys for connection.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagCodebergUsers, "codeberg-user", "Authorize specified Codeberg users by allowing their public keys to connect.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagGitHubUsers, "github-user", "Authorize specified GitHub users by allowing their public keys to connect. Configure GitHub CLI environment variables as needed; see https://cli.github.com/manual/gh_help_environment for details.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagGitLabUsers, "gitlab-user", "Authorize specified GitLab users by allowing their public keys to connect.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagSourceHutUsers, "srht-user", "Authorize specified SourceHut users by allowing their public keys to connect.")
	cmd.PersistentFlags().BoolVar(&flagAccept, "accept", false, "Automatically accept client connections without prompts.")
	cmd.PersistentFlags().BoolVarP(&flagReadOnly, "read-only", "r", false, "Host a read-only session, preventing client interaction. Also restricts SFTP to download-only.")
	cmd.PersistentFlags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")
	cmd.PersistentFlags().BoolVar(&flagSkipHostKeyCheck, "skip-host-key-check", false, "Automatically accept unknown server host keys and add them to known_hosts (similar to SSH's StrictHostKeyChecking=accept-new). This bypasses host key verification for new connections.")
	cmd.PersistentFlags().StringVar(&flagProxy, "proxy", "", "HTTP proxy to connect to the server through (e.g. http://proxy.example.com:3128). Works with ssh, ws, and wss servers. Without it, ws and wss connections use HTTPS_PROXY/HTTP_PROXY and ssh connections go direct.")
	cmd.PersistentFlags().BoolVar(&flagNoSFTP, "no-sftp", false, "Disable file transfer via SFTP/SCP. By default, clients can transfer files with the same access as the terminal session.")
	cmd.PersistentFlags().BoolVar(&flagAllowLocalTCPForwarding, "allow-local-tcp-forwarding", false, "Allow clients to use SSH local TCP forwarding (ssh -L) through the hosted session, reaching TCP destinations visible to the host.")
	cmd.PersistentFlags().StringVar(&flagPtySize, "pty-size", "", "Pin the session's terminal size as COLSxROWS (e.g. 132x43). Client resize requests are then ignored. Defaults to the attached terminal's size, or 80x24 when there is none.")
	cmd.PersistentFlags().StringVar(&flagTerm, "term", "", "Set TERM for the hosted command. Defaults to the inherited TERM, or "+defaultTerm+" when TERM is unset or "+dumbTerm+".")
	cmd.PersistentFlags().StringVar(&flagName, "name", "", "Name this session. Determines the socket paths, so it can be looked up with 'upterm session info NAME'. Defaults to COMMAND-XXXX.")
	cmd.PersistentFlags().BoolVar(&flagDetach, "detach", false, "Start the session in the background and exit once it is running. Requires --accept. Attach a terminal later with 'upterm attach NAME'; stop it with 'upterm session stop NAME'.")
	cmd.PersistentFlags().StringVarP(&flagHostOutput, "output", "o", "", "With --detach, print the started session as JSON (the same shape as 'upterm session info NAME -o json').")
	cmd.PersistentFlags().StringVar(&flagHostEscapeChar, "escape-char", "~", "Escape character for detaching this terminal from the session (ESC-CHAR followed by . at the start of a line), or 'none' to disable. No effect where the session runs in this process (Windows, until spawning lands there): the only terminal there is the session's own.")

	// The provider list comes from host.ProviderList so --help, the generated
	// docs and the parser's own error messages cannot disagree about which
	// services are supported.
	registerAuthUserFlag(cmd.PersistentFlags(), &flagAuthorizedUsers, "authorized-user",
		"Authorize users by fetching their public keys from a code-hosting service. Repeatable. "+
			"Providers: "+host.ProviderList()+". "+
			"Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave")

	// Superseded by --authorized-user. Kept working and hidden rather than
	// deprecated: action-upterm wraps these flags and users pin it at @v1, so a
	// deprecation notice would appear in logs they cannot act on.
	for _, lf := range legacyUserFlags {
		// Only errors on an unknown flag name, all of which are registered above.
		_ = cmd.PersistentFlags().MarkHidden(lf.flag)
	}

	return cmd
}

// defaultTerm is what the hosted command is given when nothing else says. A
// command on a pty with TERM unset renders as if it had no cursor addressing
// at all, so something has to be chosen; this is what every terminal upterm is
// likely to be driven from supports.
const defaultTerm = "xterm-256color"

// dumbTerm is the terminfo entry for a terminal that can do nothing: no cursor
// addressing, no clearing, no scrolling regions. Inherited into a pty it is
// worse than no answer, because a command that asks the database believes it.
const dumbTerm = "dumb"

// resolveTerm picks the TERM the hosted command runs under: the flag, then
// whatever this process inherited, then defaultTerm.
//
// Deliberately not a question about stdout. This used to fall back to
// defaultTerm whenever stdout was not a terminal, which threw away a perfectly
// good inherited TERM for `upterm host ... | tee log` run from a real
// terminal — the one case where the inherited value is certainly right. The
// command is given a pty upterm allocates either way, so what stdout happens
// to be says nothing about what TERM it should see.
//
// An inherited dumbTerm counts as nothing inherited. It is what a CI runner,
// a cron job or an editor's shell pane exports, and the session upterm hosts
// is a pty with a real terminal on the other end of it — passing "dumb"
// through would leave a full-screen command rendering as line noise for a
// guest whose terminal could have shown it. The flag is not filtered: a user
// who types --term dumb is answering the question, not failing to.
func resolveTerm(flag, inherited string) string {
	if flag != "" {
		return flag
	}
	if inherited != "" && inherited != dumbTerm {
		return inherited
	}
	return defaultTerm
}

func resolveSessionName(explicit string, command []string) string {
	if explicit != "" {
		return explicit
	}
	return sessiondir.GenerateName(command)
}

// maxGeneratedNameAttempts bounds the retry below. A generated name is a
// command plus four random hex digits, so a collision is already unlikely and
// two in a row is a signal that something other than luck is wrong — a name
// being recreated as fast as it is claimed, say. Retrying forever would turn
// that into a spin instead of an error.
const maxGeneratedNameAttempts = 5

// runWithGeneratedNameRetry hosts a session under a name, drawing a new name
// when a generated one turns out to be taken.
//
// The distinction is intent. A name the user typed is the answer to their
// question, so a collision is theirs to hear about; hosting under some other
// name would be answering a question they did not ask, and `upterm session
// info` would then not find what they went looking for. A generated name
// carries no intent at all — it is upterm's own dice roll — and losing that
// roll is not a reason to refuse to host.
//
// A nil logger means the package default rather than silence.
func runWithGeneratedNameRetry(logger *slog.Logger, explicit string, command []string, run func(name string) error) error {
	if logger == nil {
		logger = slog.Default()
	}

	var err error
	for attempt := 0; attempt < maxGeneratedNameAttempts; attempt++ {
		name := resolveSessionName(explicit, command)
		err = run(name)
		if err == nil {
			return nil
		}
		if explicit != "" || !errors.Is(err, sessiondir.ErrNameInUse) {
			return err
		}
		// The last collision is the one the user is told about, so it is not
		// followed by a redraw and there is nothing here to announce.
		if attempt+1 == maxGeneratedNameAttempts {
			break
		}
		// Every redraw, because a redraw is upterm hosting under a name other
		// than the one it drew first and nothing else on any path records
		// that. Without it, an operator whose session is not where the name
		// they remember says it should be has no trail at all.
		logger.Info("session name is taken, drawing another", "name", name)
	}
	return err
}

// validateSessionNameFlag rejects an unusable --name before anything is
// started, so the user sees one clear error rather than a failure partway
// through startup.
func validateSessionNameFlag(name string) error {
	if name == "" {
		return nil
	}
	if err := sessiondir.ValidateName(name); err != nil {
		return err
	}
	// A legal name can still be unusable, because the admin socket path is the
	// name plus a runtime root the user did not pick. Checked here so the
	// limit is reported before the session starts rather than by a bind that
	// fails once the tunnel is already up.
	return sessiondir.CheckSocketPath(utils.UptermRuntimeDir(), name)
}

func validateShareRequiredFlags(c *cobra.Command, args []string) error {
	var result error

	if flagReadOnly && flagAllowLocalTCPForwarding {
		result = multierror.Append(result, fmt.Errorf("--read-only and --allow-local-tcp-forwarding cannot be used together: a read-only session must not permit network pivoting through the host"))
	}

	if err := validateSessionNameFlag(flagName); err != nil {
		result = multierror.Append(result, err)
	}

	if flagDetach && !flagAccept {
		result = multierror.Append(result, fmt.Errorf("--detach requires --accept: a session nobody is watching cannot be confirmed interactively"))
	}
	if flagHostOutput != "" && !flagDetach {
		result = multierror.Append(result, fmt.Errorf("--output requires --detach"))
	}
	if flagHostOutput != "" && flagHostOutput != "json" {
		result = multierror.Append(result, fmt.Errorf("invalid output format %q: must be 'json'", flagHostOutput))
	}

	if flagServer == "" {
		result = multierror.Append(result, fmt.Errorf("missing flag --server"))
	} else {
		u, err := url.Parse(flagServer)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("error parsing server URL: %w", err))
		}

		if u != nil {
			if u.Scheme != "ssh" && u.Scheme != "ws" && u.Scheme != "wss" {
				result = multierror.Append(result, fmt.Errorf("unsupported server protocol %s", u.Scheme))
			}

			if u.Scheme == "ssh" {
				_, _, err := net.SplitHostPort(u.Host)
				if err != nil {
					result = multierror.Append(result, err)
				}
			}

			// set default ports for ws or wss: known_hosts keys the server as
			// host:port, so the URL must carry one. ws.NewWSConn drops it again
			// from the dial URL so the Host header stays "host", not "host:443".
			if u.Scheme == "ws" && u.Port() == "" {
				u.Host = u.Host + ":80"
				flagServer = u.String()
			}
			if u.Scheme == "wss" && u.Port() == "" {
				u.Host = u.Host + ":443"
				flagServer = u.String()
			}
		}
	}

	return result
}

// confirmationTerminalError says whether the confirmation prompt could be
// answered on this stdin and stdout, so that shareRunE can refuse before a
// name is claimed or a tunnel raised.
//
// The prompt is a Bubble Tea program: it draws on stdout and reads the answer
// from stdin, so both have to be terminals. Looking at stdout alone let
// `upterm host </dev/null` through to claim its name, establish the reverse
// tunnel and start the prompt before finding there was nothing to read the
// answer from. With --accept there is no prompt and nothing to check.
func confirmationTerminalError(accept bool, stdin, stdout *os.File) error {
	if accept {
		return nil
	}
	if term.IsTerminal(int(stdin.Fd())) && term.IsTerminal(int(stdout.Fd())) {
		return nil
	}
	return errors.New("interactive confirmation requires a terminal on stdin and stdout")
}

// hostOptions is everything shareRunE derives from flags and arguments
// without touching the network: both the process that starts a session and
// the daemon it spawns compute it, from the same argv, and get the same
// answer.
type hostOptions struct {
	command      []string
	forceCommand []string
	proxyURL     *url.URL
	refs         []host.UserRef
	ptySize      termsize.Size
	term         string
	escape       byte
}

func parseHostOptions(args []string) (hostOptions, error) {
	var opts hostOptions
	var err error
	if opts.proxyURL, err = parseProxyURL(flagProxy); err != nil {
		return opts, err
	}
	opts.command = args
	if len(opts.command) == 0 {
		if opts.command, err = shlex.Split(getDefaultShell()); err != nil {
			return opts, err
		}
		if len(opts.command) == 0 {
			return opts, fmt.Errorf("no command is specified")
		}
	}
	if flagForceCommand != "" {
		if opts.forceCommand, err = shlex.Split(flagForceCommand); err != nil {
			return opts, fmt.Errorf("error parsing command %s: %w", flagForceCommand, err)
		}
	}
	if opts.refs, err = collectUserRefs(); err != nil {
		return opts, err
	}
	if flagPtySize != "" {
		if opts.ptySize, err = termsize.Parse(flagPtySize); err != nil {
			return opts, err
		}
	}
	opts.term = resolveTerm(flagTerm, os.Getenv("TERM"))
	if opts.escape, err = parseEscapeChar(flagHostEscapeChar); err != nil {
		return opts, err
	}
	return opts, nil
}

// resolveAuthorizedKeys reads the authorized keys file and fetches every
// referenced user's keys, and refuses to start unrestricted when a
// restriction was asked for.
func resolveAuthorizedKeys(ctx context.Context, opts hostOptions, logger *slog.Logger) ([]*host.AuthorizedKey, error) {
	var authorizedKeys []*host.AuthorizedKey
	if flagAuthorizedKeys != "" {
		// Not wrapped: AuthorizedKeysFromFile already names both the action and
		// the file, so a wrap here reads "error reading authorized keys: error
		// reading authorized keys file /typo: ...".
		aks, err := host.AuthorizedKeysFromFile(flagAuthorizedKeys)
		if err != nil {
			return nil, err
		}
		authorizedKeys = append(authorizedKeys, aks)
	}
	if len(opts.refs) > 0 {
		userKeys, err := host.AuthorizedKeysFromUserRefs(ctx, opts.refs, opts.proxyURL, logger)
		if err != nil {
			return nil, fmt.Errorf("error reading user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, userKeys...)
	}
	// An empty authorized-key set means "allow anyone with the session token"
	// downstream. If the user asked for a restriction, never fall back to that.
	if authorizationRequested() && countKeys(authorizedKeys) == 0 {
		return nil, fmt.Errorf("authorization was requested but no public keys were resolved; refusing to start a session that would accept any client")
	}
	return authorizedKeys, nil
}

func shareRunE(c *cobra.Command, args []string) error {
	// Set here rather than on the command, because where it is set is what
	// divides the two kinds of failure. Cobra raises unknown flags and bad
	// flag combinations (validateShareRequiredFlags, a PreRunE) before this
	// line, and usage is the right answer to those. Everything below it is a
	// session that did not happen or a command that exited — and the hosted
	// command's own exit status is the most common of them, which printed
	// thirty lines of flags after `exit 2` as if the user had mistyped
	// something.
	c.SilenceUsage = true

	logger := uptermctx.Logger(c.Context())
	if logger == nil {
		return fmt.Errorf("logger not available")
	}

	// The daemon, if that is what this process is. Decided before anything
	// touches stdin or stdout: a daemon has neither.
	conn, daemonName, err := bootstrapConn()
	if err != nil {
		return err
	}
	if conn != nil {
		opts, err := parseHostOptions(args)
		if err != nil {
			return err
		}
		return mapUserAction(c, runDaemonProcess(c.Context(), logger.Logger, opts, conn, daemonName,
			func(ctx context.Context, h *host.Host) error { return h.Run(ctx) }))
	}

	// Refuse before anything is claimed or connected: a session that reaches
	// the prompt and cannot be answered is an orphan holding a name.
	if err := confirmationTerminalError(flagAccept, os.Stdin, os.Stdout); err != nil {
		c.SilenceUsage = true
		c.SilenceErrors = true
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "To run in non-interactive environments (CI, scripts, etc.), use --accept:")
		fmt.Fprintln(os.Stderr, "  upterm host --accept [command]")
		return SilentError{Err: err}
	}

	opts, err := parseHostOptions(args)
	if err != nil {
		return err
	}
	if !spawnSupported {
		if flagDetach {
			return errors.New("--detach is not supported on this platform yet")
		}
		return runInProcessHost(c, logger.Logger, opts)
	}
	return runHostParent(c, logger.Logger, opts)
}

// hostSpawn is how runHostParent starts the daemon.
//
// A var because spawnDaemon re-executes this process with this process's own
// argv, which is upterm's argv in the binary and the test runner's under `go
// test`: a test that drives `upterm host` through Root().Execute() and
// reached spawnDaemon would start a second copy of the test binary, running
// the whole suite again, once per spawn. So the tests that drive the command
// in-process point this at a daemon in a goroutine of their own process, and
// exercise the same exchange over a pipe.
//
// Its default is guardedSpawn rather than spawnDaemon itself, so that the
// refusal is production code that covers every test package rather than one
// package's TestMain.
var hostSpawn spawnFunc = guardedSpawn

// guardedSpawn is spawnDaemon with the fork bomb taken out of reach.
//
// The daemon is this executable re-executed with os.Args, and in a test
// binary that argv is the test runner's: a test that reached the real spawn
// would run the whole suite in a child, which reaches the spawn again, once
// per test that does, until the machine stops. That has happened, twice.
// Tests drive `upterm host` through runHostInProcess, which swaps this for an
// in-process daemon on the far end of a pipe; the one test that needs the
// real transport calls spawnDaemon directly. Every other reach for the spawn
// from a test binary is a mistake, and is refused here rather than in any one
// package's TestMain, which cannot protect a package that does not have one.
func guardedSpawn(so spawnOptions) (net.Conn, *os.Process, error) {
	if testing.Testing() {
		return nil, nil, errors.New("refusing to spawn the daemon from a test binary: drive upterm host through runHostInProcess")
	}
	return spawnDaemon(so)
}

// runHostParent is upterm host on a platform that spawns: the daemon is a
// child, this process is its operator's terminal.
func runHostParent(c *cobra.Command, logger *slog.Logger, opts hostOptions) error {
	display := displaySession
	if flagDetach && flagHostOutput == "json" {
		// stdout is the JSON; the banner would be noise in it.
		display = func(context.Context, *api.GetSessionResponse, string) error { return nil }
	}
	var attachClient clientFunc
	if !flagDetach {
		attachClient = func(ctx context.Context, socket string, keys []ssh.PublicKey) (attach.Result, error) {
			lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, opts.term)
			return attachLocalTerminal(ctx, socket, keys, lt, opts.escape, os.Stdin, os.Stdout, logger)
		}
	}
	err := runWithGeneratedNameRetry(logger, flagName, opts.command, func(name string) error {
		s := &spawnedSession{
			name:         name,
			detach:       flagDetach,
			jsonOut:      flagHostOutput == "json",
			logPath:      utils.UptermLogFilePath(),
			stdin:        os.Stdin,
			stdout:       os.Stdout,
			stderr:       os.Stderr,
			readSecret:   terminalSecretReader(os.Stdin, os.Stderr),
			spawn:        hostSpawn,
			display:      display,
			attachClient: attachClient,
			logger:       logger,
		}
		return s.run(c.Context())
	})

	err = mapUserAction(c, err)
	var ec ExitCodeError
	if errors.As(err, &ec) && ec.Err == nil {
		// The line that explains it was printed already; the status is for
		// a script.
		c.SilenceErrors = true
	}
	return err
}

// terminalSecretReader reads a passphrase from stdin without echo, or is
// nil when stdin is not a terminal — a secret cannot be read from a pipe
// without echoing it somewhere.
func terminalSecretReader(stdin, stderr *os.File) func(string) ([]byte, error) {
	if !term.IsTerminal(int(stdin.Fd())) {
		return nil
	}
	return func(string) ([]byte, error) {
		defer func() { _, _ = fmt.Fprintln(stderr) }()
		return term.ReadPassword(int(stdin.Fd()))
	}
}

// runInProcessHost runs the daemon in this process and attaches this
// process's terminal to it. It is what upterm host was in stage 2, and what
// it still is where spawning is not supported.
func runInProcessHost(c *cobra.Command, logger *slog.Logger, opts hostOptions) error {
	authorizedKeys, err := resolveAuthorizedKeys(c.Context(), opts, logger)
	if err != nil {
		return err
	}

	signers, cleanup, err := host.Signers(flagPrivateKeys, identitiesOnlyRequested())
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Generated here rather than left to Run: this process attaches its own
	// terminal to the door the daemon presents, and needs the public half to
	// pin it.
	hostKey, err := host.NewHostKey()
	if err != nil {
		return fmt.Errorf("error generating host key: %w", err)
	}

	var hkcb ssh.HostKeyCallback
	if flagSkipHostKeyCheck {
		hkcb, err = host.NewAutoAcceptingHostKeyCallback(os.Stdout, flagKnownHostsFilename)
	} else {
		hkcb, err = host.NewPromptingHostKeyCallback(os.Stdin, os.Stdout, flagKnownHostsFilename, connectionIsProxied(flagServer, opts.proxyURL))
	}
	if err != nil {
		return err
	}

	// Set up SFTP permission checker based on --accept flag
	var sftpPermissionChecker sftp.PermissionChecker
	if flagAccept {
		sftpPermissionChecker = &AutoAllowPermissionChecker{}
	} else {
		sftpPermissionChecker = &DialogPermissionChecker{}
	}

	// A fresh Host per attempt, because every field that names the session —
	// Name and the banner the callback prints — belongs to the name this
	// attempt drew, and because Run fills fields in on the Host it is given.
	err = runWithGeneratedNameRetry(logger, flagName, opts.command, func(name string) error {
		h := &host.Host{
			Host:              flagServer,
			Name:              name,
			Command:           opts.command,
			ForceCommand:      opts.forceCommand,
			Signers:           signers,
			HostKey:           hostKey,
			HostKeyCallback:   hkcb,
			AuthorizedKeys:    authorizedKeys,
			KeepAliveDuration: 50 * time.Second, // nlb is 350 sec & heroku router is 55 sec
			ProxyURL:          opts.proxyURL,
			SessionCreatedCallback: func(ctx context.Context, s *api.GetSessionResponse) error {
				return displaySession(ctx, s, name)
			},
			ClientJoinedCallback:    clientJoinedCallback,
			ClientLeftCallback:      clientLeftCallback,
			Logger:                  logger,
			ReadOnly:                flagReadOnly,
			AllowLocalTCPForwarding: flagAllowLocalTCPForwarding,
			PtySize:                 opts.ptySize,
			PinPtySize:              flagPtySize != "",
			Term:                    opts.term,
			SFTPDisabled:            flagNoSFTP,
			SFTPPermissionChecker:   sftpPermissionChecker,
			// The local terminal attaches before the command starts, so a
			// command that exits at once cannot beat it to the output.
			AwaitInitialClient: true,
			// The daemon has no terminal; this process does.
			VersionWarningCallback: func(r *version.CompatibilityResult) {
				host.DisplayVersionWarning(os.Stdout, logger, r)
			},
		}

		return runLocalSession(c.Context(), name, os.Stderr, logger,
			func(ctx context.Context, onAttachSocket func(string), onCommandStarted func()) error {
				h.AttachListeningCallback = onAttachSocket
				h.CommandStartedCallback = onCommandStarted
				return h.Run(ctx)
			},
			func(ctx context.Context, socket string) (attach.Result, error) {
				lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, opts.term)
				// The daemon's own host key, not a re-read of the record: this
				// is the process presenting the door, so it has the key
				// directly.
				keys := []ssh.PublicKey{hostKey.PublicKey()}
				// Not opts.escape: this process is the daemon, so a ~. here
				// would detach the only terminal a foreground process has.
				return attachLocalTerminal(ctx, socket, keys, lt, 0, os.Stdin, os.Stdout, logger)
			})
	})

	return mapUserAction(c, err)
}

// mapUserAction turns a UserDiscardedError or UserInterruptedError from a
// run attempt into the exit shareRunE reports, on either path: a decline is
// a clean exit (nothing printed, status 0), and an interruption silences
// both usage and error display before being returned — a session the
// operator declined or interrupted at the prompt is not a fault, and must
// not read as one in the daemon's log or the foreground's stderr. Anything
// else is returned unchanged.
func mapUserAction(c *cobra.Command, err error) error {
	var userDiscardedErr UserDiscardedError
	if errors.As(err, &userDiscardedErr) {
		return nil // Clean exit for user discard (exit code 0)
	}

	var userInterruptedErr UserInterruptedError
	if errors.As(err, &userInterruptedErr) {
		// Set both flags to prevent help menu and error display
		c.SilenceUsage = true
		c.SilenceErrors = true
		return userInterruptedErr
	}

	return err
}

// notify raises a desktop notification. A var so a test can see what the
// callbacks below decided to send, rather than pop a real notification on
// whoever is running the suite.
var notify = beeep.Notify

func clientJoinedCallback(c *api.Client) {
	// The host's own terminal is a client of the session now, and notifying
	// the operator that they have joined their own session is noise.
	if !shouldNotifyClient(c) {
		return
	}
	_ = notify("Upterm Client Joined", notifyBody(c), icon.Upterm)
}

func clientLeftCallback(c *api.Client) {
	if !shouldNotifyClient(c) {
		return
	}
	_ = notify("Upterm Client Left", notifyBody(c), icon.Upterm)
}

func notifyBody(c *api.Client) string {
	return clientDesc(c.Kind, c.Addr, c.Version, c.PublicKeyFingerprint)
}

// bannerFlushTimeout bounds how long startup waits for the banner to reach a
// stdout that is not a terminal: long enough for a reader that is merely slow
// to get going, short enough that nobody waiting for a session to come up
// wonders whether it has hung.
const bannerFlushTimeout = 2 * time.Second

// printBanner prints the session banner without letting whoever reads stdout
// decide whether the session starts.
//
// It runs from SessionCreatedCallback, before the admin socket is bound and
// before the command is started, so a write that blocks here blocks all of
// that: the record stays at starting, the name stays held, and an operator's
// pipeline ends up waiting on a process that is waiting on the pipeline. A
// pipe nobody drains is enough to do it — the banner passes a pipe buffer with
// a long enough command line — and a write already in the kernel is not
// something the session's cancellation can reach.
//
// So off a terminal the banner goes through a sink whose Write never blocks,
// and startup waits bannerFlushTimeout for delivery and no longer. On a
// terminal it is printed as before: a terminal drains itself, and the
// synchronous write keeps the banner ahead of everything the session prints
// after it.
//
// The version warning host.Run prints is deliberately left synchronous. It
// runs just before this callback, so it is the first thing written to an empty
// pipe, and a few hundred bytes is smaller than any pipe buffer.
//
// logger may be nil, which is the package default rather than silence: a
// banner nobody received is the kind of thing an operator is looking for when
// they come here.
func printBanner(logger *slog.Logger, detail tui.SessionDetail) {
	if logger == nil {
		logger = slog.Default()
	}

	if tui.IsTTY() {
		tui.PrintSessionDetail(detail)
		return
	}

	sink := uio.NewAsyncWriter(os.Stdout, uio.DefaultGuestBufferSize, func(err error) {
		// Warn, not debug: the banner carries the command a guest has to run
		// to join, and a session whose banner never arrived reads, to whoever
		// was waiting for it, as a session that never started.
		logger.Warn("session banner dropped", "error", err)
	})
	// The error is the sink's own to report: a fresh sink can only fail here by
	// overflowing, and overflowing calls the callback above.
	_, _ = io.WriteString(sink, tui.FormatSessionDetail(detail))

	ctx, cancel := context.WithTimeout(context.Background(), bannerFlushTimeout)
	defer cancel()
	if err := sink.Flush(ctx); err != nil {
		// Left open on purpose. Close discards whatever is still pending, and
		// the drain goroutine delivers the rest once the reader comes back,
		// exactly as the command's own stdout sink does. At worst it parks in
		// that write holding the banner and nothing else, and ends when the
		// pipe drains, the reader closes it, or the process exits.
		logger.Debug("session banner is still draining; starting the session anyway", "error", err, "timeout", bannerFlushTimeout)
		return
	}
	_ = sink.Close()
}

func displaySession(ctx context.Context, session *api.GetSessionResponse, name string) error {
	// Build session detail (includes SCP commands if SFTP is enabled)
	detail, err := buildSessionDetail(session)
	if err != nil {
		return fmt.Errorf("failed to build session detail: %w", err)
	}
	detail.Name = name

	// With --accept, just print session info and continue (no interactive confirmation needed)
	if flagAccept {
		// The logger root.go put in the context: it writes to upterm's log
		// file, which is where an operator goes to find out what became of a
		// startup. Nil until some caller sets one up, which printBanner reads
		// as the package default.
		var logger *slog.Logger
		if l := uptermctx.Logger(ctx); l != nil {
			logger = l.Logger
		}
		printBanner(logger, detail)
		return nil
	}

	// Run interactive TUI for confirmation (TTY is guaranteed by early check in shareRunE)
	model := tui.NewHostSessionModel(detail, false)
	p := tea.NewProgram(model, tea.WithContext(ctx))

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("session confirmation failed: %w", err)
	}

	// Extract result from the model
	sessionModel, ok := finalModel.(tui.HostSessionModel)
	if !ok {
		return fmt.Errorf("unexpected model type: got %T, want tui.HostSessionModel", finalModel)
	}

	// Handle the result
	switch sessionModel.Result() {
	case tui.HostSessionConfirmAccepted:
		return nil
	case tui.HostSessionConfirmRejected:
		return UserDiscardedError{}
	case tui.HostSessionConfirmInterrupted:
		return UserInterruptedError{}
	default:
		return fmt.Errorf("unknown confirmation result: %d", sessionModel.Result())
	}
}

func defaultPrivateKeys(homeDir string) []string {
	var pks []string
	for _, f := range []string{
		"id_ed25519",
		"id_ed25519_sk",
		"id_ecdsa",
		"id_ecdsa_sk",
		"id_dsa",
		"id_rsa",
	} {
		pk := filepath.Join(homeDir, ".ssh", f)
		if _, err := os.Stat(pk); os.IsNotExist(err) {
			continue
		}

		pks = append(pks, pk)
	}

	return pks
}

func defaultKnownHost(homeDir string) string {
	return filepath.Join(homeDir, ".ssh", "known_hosts")
}

// legacyUserFlags maps the hidden per-provider flags onto the reference
// grammar. It is the single source of truth for those flag names: the
// MarkHidden loop in hostCmd and authorizationRequested's fail-closed check
// both iterate it, because a name hand-copied into either of those and then
// misspelled would drop a requested restriction rather than fail visibly.
var legacyUserFlags = []struct {
	flag     string
	provider string
	values   *[]string
}{
	{"codeberg-user", "codeberg", &flagCodebergUsers},
	{"github-user", "github", &flagGitHubUsers},
	{"gitlab-user", "gitlab", &flagGitLabUsers},
	{"srht-user", "srht", &flagSourceHutUsers},
}

func collectUserRefs() ([]host.UserRef, error) {
	raw := append([]string{}, flagAuthorizedUsers...)
	for _, lf := range legacyUserFlags {
		for _, user := range *lf.values {
			raw = append(raw, lf.provider+":"+user)
		}
	}

	var (
		refs []host.UserRef
		errs error
	)
	for _, s := range raw {
		ref, err := host.ParseUserRef(s)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		refs = append(refs, ref)
	}
	if errs != nil {
		return nil, errs
	}
	return refs, nil
}

// authorizationRequested reports whether the user asked to restrict who may
// join, from any configuration origin.
func authorizationRequested() bool {
	for _, name := range []string{"authorized-keys", "authorized-user"} {
		if suppliedFlags[name] {
			return true
		}
	}
	// Derived, never re-listed: a legacy flag missing from this check reaches
	// the tunnel with no restriction at all.
	for _, lf := range legacyUserFlags {
		if suppliedFlags[lf.flag] {
			return true
		}
	}
	return false
}

// identitiesOnlyRequested reports whether the user named their identities,
// from any configuration origin. A named list is the whole set: see
// host.Signers.
func identitiesOnlyRequested() bool {
	return suppliedFlags["private-key"]
}

func countKeys(aks []*host.AuthorizedKey) int {
	var n int
	for _, ak := range aks {
		if ak != nil {
			n += len(ak.PublicKeys)
		}
	}
	return n
}
