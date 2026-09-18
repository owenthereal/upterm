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
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gen2brain/beeep"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/icon"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host a terminal session",
		Long: `Host a terminal session via a reverse SSH tunnel to the Upterm server.

The session links the host and client IO to a command's IO. Authentication with the
Upterm server uses private keys in this order:
  1. Private key files: ~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}
  2. SSH Agent keys
  3. Auto-generated ephemeral key (if no keys found)

To authorize client connections, use --authorized-keys to specify an authorized_keys file
containing client public keys.`,
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
  upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND`,
		PreRunE: validateShareRequiredFlags,
		RunE:    shareRunE,
	}

	registerHostFlags(cmd.PersistentFlags())

	return cmd
}

// registerHostFlags registers the flags that describe a hosted session on fs.
//
// Shared rather than duplicated because `upterm ci` hosts the very same
// session as `upterm host` and differs only in who is told about it. A second
// copy of these registrations would be a second set of defaults, and the
// failure mode of a drifted copy is silent: a --known-hosts or an
// --authorized-user that means something slightly different depending on which
// command the user typed.
func registerHostFlags(fs *pflag.FlagSet) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Error("error getting user home directory", "error", err)
		os.Exit(1)
	}

	fs.StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "Specify the upterm server address (required). Supported protocols: ssh, ws, wss.")
	fs.StringVarP(&flagForceCommand, "force-command", "f", "", "Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.")
	fs.StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "Specify private key files for public key authentication with the upterm server (required). Only existing files are included by default.")
	fs.StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(homeDir), "Specify a file containing known keys for remote hosts (required).")
	// Keep help and generated docs portable without changing the runtime defaults.
	fs.Lookup("private-key").DefValue = "[~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}]"
	fs.Lookup("known-hosts").DefValue = "~/.ssh/known_hosts"

	fs.StringVar(&flagAuthorizedKeys, "authorized-keys", "", "Specify a authorize_keys file listing authorized public keys for connection.")
	registerAuthUserFlag(fs, &flagCodebergUsers, "codeberg-user", "Authorize specified Codeberg users by allowing their public keys to connect.")
	registerAuthUserFlag(fs, &flagGitHubUsers, "github-user", "Authorize specified GitHub users by allowing their public keys to connect. Configure GitHub CLI environment variables as needed; see https://cli.github.com/manual/gh_help_environment for details.")
	registerAuthUserFlag(fs, &flagGitLabUsers, "gitlab-user", "Authorize specified GitLab users by allowing their public keys to connect.")
	registerAuthUserFlag(fs, &flagSourceHutUsers, "srht-user", "Authorize specified SourceHut users by allowing their public keys to connect.")
	fs.BoolVar(&flagAccept, "accept", false, "Automatically accept client connections without prompts.")
	fs.BoolVarP(&flagReadOnly, "read-only", "r", false, "Host a read-only session, preventing client interaction. Also restricts SFTP to download-only.")
	fs.BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")
	fs.BoolVar(&flagSkipHostKeyCheck, "skip-host-key-check", false, "Automatically accept unknown server host keys and add them to known_hosts (similar to SSH's StrictHostKeyChecking=accept-new). This bypasses host key verification for new connections.")
	fs.StringVar(&flagProxy, "proxy", "", "HTTP proxy to connect to the server through (e.g. http://proxy.example.com:3128). Works with ssh, ws, and wss servers. Without it, ws and wss connections use HTTPS_PROXY/HTTP_PROXY and ssh connections go direct.")
	fs.BoolVar(&flagNoSFTP, "no-sftp", false, "Disable file transfer via SFTP/SCP. By default, clients can transfer files with the same access as the terminal session.")
	fs.BoolVar(&flagAllowLocalTCPForwarding, "allow-local-tcp-forwarding", false, "Allow clients to use SSH local TCP forwarding (ssh -L) through the hosted session, reaching TCP destinations visible to the host.")
	fs.StringVar(&flagPtySize, "pty-size", "", "Pin the session's terminal size as COLSxROWS (e.g. 132x43). Client resize requests are then ignored. Defaults to the host terminal's size, or 80x24 when there is none.")
	fs.StringVar(&flagTerm, "term", "", "Set TERM for the hosted command. Defaults to the inherited TERM, or "+defaultTerm+" when TERM is unset or "+dumbTerm+".")
	fs.StringVar(&flagName, "name", "", "Name this session. Determines the socket paths, so it can be looked up with 'upterm session info NAME'. Defaults to COMMAND-XXXX.")

	// The provider list comes from host.ProviderList so --help, the generated
	// docs and the parser's own error messages cannot disagree about which
	// services are supported.
	registerAuthUserFlag(fs, &flagAuthorizedUsers, "authorized-user",
		"Authorize users by fetching their public keys from a code-hosting service. Repeatable. "+
			"Providers: "+host.ProviderList()+". "+
			"Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave")

	// Superseded by --authorized-user. Kept working and hidden rather than
	// deprecated: action-upterm wraps these flags and users pin it at @v1, so a
	// deprecation notice would appear in logs they cannot act on.
	for _, lf := range legacyUserFlags {
		// Only errors on an unknown flag name, all of which are registered above.
		_ = fs.MarkHidden(lf.flag)
	}
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

func shareRunE(c *cobra.Command, args []string) error {
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

	return runHostSession(c, args, sessionOptions{
		SessionCreated: displaySession,
		ClientJoined:   clientJoinedCallback,
		ClientLeft:     clientLeftCallback,
	})
}

// sessionOptions is what one command wants of the session it hosts, beyond
// the flags both commands share: where the session's own output goes, and how
// to react to its lifecycle. `upterm host` shows that lifecycle to the
// operator at the terminal; `upterm ci` reports it to the CI system running
// the job. Everything else about hosting is the same for both and lives in
// runHostSession, so that the two commands cannot drift on which keys
// authorize a client or how a server URL is reached.
type sessionOptions struct {
	// Stdout is where the hosted command's output is mirrored. nil means
	// os.Stdout, which is what a terminal session wants: the operator watches
	// the session they are hosting. `upterm ci` points it elsewhere, because
	// there the mirror is a build log that may be public.
	Stdout *os.File

	// SessionCreated runs once the session is up and before the hosted command
	// starts. An error from it abandons the session — that is how the
	// interactive confirmation declines — so a hook that only reports must
	// swallow its own failures rather than take a joinable session down over a
	// report it could not deliver.
	SessionCreated func(ctx context.Context, s *api.GetSessionResponse, name string) error
	ClientJoined   func(*api.Client)
	ClientLeft     func(*api.Client)
}

// runHostSession hosts a session from the already-parsed host flags, under the
// calling command's own options.
func runHostSession(c *cobra.Command, args []string, opts sessionOptions) error {
	proxyURL, err := parseProxyURL(flagProxy)
	if err != nil {
		return err
	}

	if len(args) == 0 {
		shellCmd := getDefaultShell()
		args, err = shlex.Split(shellCmd)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			return fmt.Errorf("no command is specified")
		}
	}

	var forceCommand []string
	if flagForceCommand != "" {
		forceCommand, err = shlex.Split(flagForceCommand)
		if err != nil {
			return fmt.Errorf("error parsing command %s: %w", flagForceCommand, err)
		}
	}

	logger := uptermctx.Logger(c.Context())
	if logger == nil {
		return fmt.Errorf("logger not available")
	}

	refs, err := collectUserRefs()
	if err != nil {
		return err
	}

	var authorizedKeys []*host.AuthorizedKey
	if flagAuthorizedKeys != "" {
		// Not wrapped: AuthorizedKeysFromFile already names both the action and
		// the file, so a wrap here reads "error reading authorized keys: error
		// reading authorized keys file /typo: ...".
		aks, err := host.AuthorizedKeysFromFile(flagAuthorizedKeys)
		if err != nil {
			return err
		}
		authorizedKeys = append(authorizedKeys, aks)
	}

	if len(refs) > 0 {
		userKeys, err := host.AuthorizedKeysFromUserRefs(c.Context(), refs, proxyURL, logger.Logger)
		if err != nil {
			return fmt.Errorf("error reading user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, userKeys...)
	}

	// An empty authorized-key set means "allow anyone with the session token"
	// downstream. If the user asked for a restriction, never fall back to that.
	if authorizationRequested() && countKeys(authorizedKeys) == 0 {
		return fmt.Errorf("authorization was requested but no public keys were resolved; refusing to start a session that would accept any client")
	}

	signers, cleanup, err := host.Signers(flagPrivateKeys)
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	var hkcb ssh.HostKeyCallback
	if flagSkipHostKeyCheck {
		hkcb, err = host.NewAutoAcceptingHostKeyCallback(os.Stdout, flagKnownHostsFilename)
	} else {
		hkcb, err = host.NewPromptingHostKeyCallback(os.Stdin, os.Stdout, flagKnownHostsFilename, connectionIsProxied(flagServer, proxyURL))
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

	var ptySize termsize.Size
	if flagPtySize != "" {
		ptySize, err = termsize.Parse(flagPtySize)
		if err != nil {
			return err
		}
	}

	term := resolveTerm(flagTerm, os.Getenv("TERM"))

	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	// A fresh Host per attempt, because every field that names the session —
	// Name and the banner the callback prints — belongs to the name this
	// attempt drew, and because Run fills fields in on the Host it is given.
	err = runWithGeneratedNameRetry(logger.Logger, flagName, args, func(name string) error {
		h := &host.Host{
			Host:              flagServer,
			Name:              name,
			Command:           args,
			ForceCommand:      forceCommand,
			Signers:           signers,
			HostKeyCallback:   hkcb,
			AuthorizedKeys:    authorizedKeys,
			KeepAliveDuration: 50 * time.Second, // nlb is 350 sec & heroku router is 55 sec
			ProxyURL:          proxyURL,
			SessionCreatedCallback: func(ctx context.Context, s *api.GetSessionResponse) error {
				return opts.SessionCreated(ctx, s, name)
			},
			ClientJoinedCallback:    opts.ClientJoined,
			ClientLeftCallback:      opts.ClientLeft,
			Stdin:                   os.Stdin,
			Stdout:                  stdout,
			Logger:                  logger.Logger,
			ReadOnly:                flagReadOnly,
			AllowLocalTCPForwarding: flagAllowLocalTCPForwarding,
			PtySize:                 ptySize,
			PinPtySize:              flagPtySize != "",
			Term:                    term,
			SFTPDisabled:            flagNoSFTP,
			SFTPPermissionChecker:   sftpPermissionChecker,
		}

		return h.Run(c.Context())
	})

	// Handle user actions specially - no help menu
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

func clientJoinedCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Joined", notifyBody(c), icon.Upterm)
}

func clientLeftCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Left", notifyBody(c), icon.Upterm)
}

func notifyBody(c *api.Client) string {
	return clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint)
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
	// Set by `upterm ci` from its --limit-access-to-* flags, which are bools
	// and lists rather than a supplied/not-supplied question: see
	// ciAuthorizationRequested.
	if ciAuthorizationRequested {
		return true
	}

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

func countKeys(aks []*host.AuthorizedKey) int {
	var n int
	for _, ak := range aks {
		if ak != nil {
			n += len(ak.PublicKeys)
		}
	}
	return n
}
