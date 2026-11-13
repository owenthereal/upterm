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
	"strings"
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
	"github.com/owenthereal/upterm/icon"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
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

// What the accept prompt exits with when it ends on a signal: 128 plus
// the signal, as if the signal had ended the process, which is also how the
// relay-key prompt ends.
const (
	exitInterrupted = 130 // SIGINT, or Ctrl-C at the prompt
	exitTerminated  = 143 // SIGTERM
)

// UserTerminatedError is the accept prompt ending without an answer: SIGTERM
// quits the program bubbletea runs it in, with no error.
type UserTerminatedError struct{}

func (e UserTerminatedError) Error() string {
	return "terminated at the prompt"
}

// Unwrap makes a termination an abandoned startup rather than a failed one,
// for the same reason UserInterruptedError.Unwrap does: the session was never
// accepted, so nothing failed.
func (e UserTerminatedError) Unwrap() error {
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

var (
	flagServer                  string
	flagForceCommand            string
	flagLoginCommand            string
	flagAllowExec, flagNoExec   bool
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
	flagAllowSFTP, flagNoSFTP   bool
	flagAllowForwarding         forwardingGrant
	flagAllowLocalTCPForwarding bool
	flagNoForwarding            bool
	flagFullAccess              bool
	flagPtySize                 string
	flagTerm                    string
	flagName                    string
	flagDetach                  bool
	flagHostOutput              string
	flagJoinTimeout             time.Duration
	// flagHostEscapeChar carries its flag's default here as well as in the
	// registration below, so parseEscapeChar has a value to accept when the
	// var is read without hostCmd having run — which is every unit test that
	// calls parseHostOptions.
	flagHostEscapeChar = "~"
)

// forwardingGrant is --allow-forwarding's value: the forwards guests may open
// without approval. Empty grants none.
type forwardingGrant string

const (
	// forwardLoopback is forwards to this machine's literal loopback
	// addresses, 127.0.0.0/8 and ::1.
	forwardLoopback forwardingGrant = "loopback"
	// forwardAny is forwards to anything this machine can reach.
	forwardAny forwardingGrant = "any"
)

func (g *forwardingGrant) Set(s string) error {
	switch v := forwardingGrant(s); v {
	case forwardLoopback, forwardAny:
		*g = v
		return nil
	}
	return errors.New("must be loopback or any")
}

func (g *forwardingGrant) String() string { return string(*g) }

// Type is the placeholder --help shows for the value.
func (g *forwardingGrant) Type() string { return "loopback|any" }

func hostCmd() *cobra.Command { return hostCmdWith(nil) }

// hostCmdWith is upterm host, with ext's HostFlags, and ext's Prepare before
// the run when it has one.
func hostCmdWith(ext *Extension) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host [flags] [-- COMMAND [ARGS...]]",
		Short: "Host a terminal session",
		Long: `Host a terminal session: run COMMAND, or $SHELL without one, and share it
through a relay, so that guests can join it from their own terminals with
upterm join or plain ssh.

upterm prints the session, with the commands guests join it with, and asks
before starting it; --accept starts it without asking, plus --allow-sftp. The
relay is --server, and upterm authenticates to it with the first of these it
has:
  1. The SSH agent's keys, when an agent is running and holds any
  2. Otherwise, the private key files that load: ~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}
  3. Otherwise, a generated key

Supplying --private-key makes the named list the whole set instead; see its
help.

Who can join: anyone with the session's connect string, unless
--authorized-keys (an authorized_keys file) or --authorized-user names the
keys a guest must have.

What guests can do: type into the session, or only watch it with
--read-only. A guest's plain ssh shares this terminal, or runs the program
--login-command names instead. Anything more needs a grant:
  commands     ssh SESSION CMD, VS Code, herdr --remote, run as you
               (--allow-exec, --no-exec)
  files        scp and sftp, with your access (--allow-sftp, --no-sftp)
  forwarding   ssh -L 8080:127.0.0.1:8080, to this machine's loopback
               addresses (--allow-forwarding=loopback, --no-forwarding)
--allow-X lets guests do X without asking, --no-X never lets them, and with
neither, upterm asks in your terminal. --full-access allows all three, for
the keys --authorized-user or --authorized-keys names. Forwards anywhere else
are refused unless --allow-forwarding=any, which lets guests reach anything
this machine can, without asking. --read-only also turns off commands,
uploads and forwarding.

The session runs in a process of its own, and this terminal is attached to
it. NAME is the session's name, which upterm prints (--name chooses it).

` + attachedKeysHelp + `

With --detach nothing is attached: the session starts in the background, and
upterm prints how to reach it. It still asks before starting it, on this
terminal; with no terminal to ask in, --detach needs --accept.

Exit status: the command's own status when it exits; 1 when upterm fails, or
the session is stopped or ends by a signal (whatever the command returns
while it is torn down); 254 when this terminal is disconnected; 130 for
Ctrl-C at a prompt, 143 for a SIGTERM there; 0 after declining at the prompt
or detaching (~.). A command's own 1 or 254 reads the same. With --detach: 0
once the session has started, 1 when it can't start; upterm session wait NAME
reports the command's status.`,
		Example: `  # Host $SHELL; upterm prints how guests join it:
  upterm host

  # Host a command:
  upterm host -- docker run --rm -ti ubuntu bash

  # Let only the keys alice has on GitHub join:
  upterm host --authorized-user github:alice

  # Let only the keys in an authorized_keys file join:
  upterm host --authorized-keys ~/.ssh/guests_authorized_keys

  # Start without asking, and let guests transfer files without approval:
  upterm host --accept

  # Host 'tmux new -t pair-programming', and give each guest
  # 'tmux attach -t pair-programming' instead of the session itself:
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Let guests forward TCP ports (ssh -L) to what this machine can reach:
  upterm host --allow-forwarding=any

  # Host on another relay, over a WebSocket:
  upterm host --server wss://relay.example.com

  # Start a session in the background and print how to reach it:
  upterm host --detach --accept --authorized-user github:alice

  # The same, as JSON for a script:
  upterm host --detach --accept --authorized-user github:alice -o json

  # A door to this machine for alice's keys alone, in the background: plain
  # ssh opens Herdr, and alice can also run commands, transfer files and
  # forward to this machine's loopback ports:
  upterm host --detach --name home --full-access --authorized-user github:alice --login-command herdr

  # On a CI runner, with nobody there to ask: a session alice can open in
  # VS Code (Remote-SSH), which runs its server and forwards to its port:
  upterm host --detach --accept --authorized-user github:alice --allow-exec --allow-forwarding=loopback`,
		PreRunE: hostPreRunE(ext),
		RunE: func(c *cobra.Command, args []string) error {
			return shareRunE(c, ext, args)
		},
	}

	cmd.PersistentFlags().StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "Relay to host the session on: ssh://HOST[:PORT], ws://HOST[:PORT] or wss://HOST[:PORT]. Without a port, ssh uses 22, ws 80 and wss 443.")
	cmd.PersistentFlags().StringVarP(&flagForceCommand, "force-command", "f", "", "Run this host-chosen command for guest shell and exec requests, with a private PTY when requested and pipes otherwise. --no-exec and --read-only still deny explicit exec. Mutually exclusive with --login-command.")
	cmd.PersistentFlags().StringVar(&flagLoginCommand, "login-command", "", "Run this host-chosen command for guest shell requests, without exec approval. Mutually exclusive with --force-command; explicit guest exec still needs approval.")
	cmd.PersistentFlags().BoolVar(&flagAllowExec, "allow-exec", false, "Let guests run commands (ssh SESSION CMD, VS Code, herdr --remote) without approval. Each runs as you, and its stdin can carry further code.")
	cmd.PersistentFlags().BoolVar(&flagNoExec, "no-exec", false, "Deny explicit guest exec requests, including forced exec. Host-chosen login and forced shell commands still run.")

	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(), "Identity files to authenticate to the relay with. "+identitiesOnlyHelp+" By default it offers the agent's keys alone when the agent holds any, and otherwise the listed files that load, or a generated key when none do.")
	cmd.PersistentFlags().StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(), knownHostsHelp)
	// Keep help and generated docs portable without changing the runtime defaults.
	cmd.PersistentFlags().Lookup("private-key").DefValue = "[~/.ssh/id_{ed25519,ed25519_sk,ecdsa,ecdsa_sk,dsa,rsa}]"
	cmd.PersistentFlags().Lookup("known-hosts").DefValue = "~/.ssh/known_hosts"

	cmd.PersistentFlags().StringVar(&flagAuthorizedKeys, "authorized-keys", "", "An authorized_keys file: only guests with a key it lists, or that --authorized-user names, can join.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagCodebergUsers, "codeberg-user", "Authorize specified Codeberg users by allowing their public keys to connect.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagGitHubUsers, "github-user", "Authorize specified GitHub users by allowing their public keys to connect. Configure GitHub CLI environment variables as needed; see https://cli.github.com/manual/gh_help_environment for details.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagGitLabUsers, "gitlab-user", "Authorize specified GitLab users by allowing their public keys to connect.")
	registerAuthUserFlag(cmd.PersistentFlags(), &flagSourceHutUsers, "srht-user", "Authorize specified SourceHut users by allowing their public keys to connect.")
	cmd.PersistentFlags().BoolVar(&flagAccept, "accept", false, "Start the session without asking, plus --allow-sftp.")
	cmd.PersistentFlags().BoolVarP(&flagReadOnly, "read-only", "r", false, "Let guests only watch: they can't type into the session, run commands or forward ports, and can only download files.")
	cmd.PersistentFlags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide guests' IP addresses from upterm's output, and from forced commands' SSH_CONNECTION and SSH_CLIENT. "+hideClientIPDefaultHelp)
	cmd.PersistentFlags().BoolVar(&flagSkipHostKeyCheck, "skip-host-key-check", false, skipHostKeyCheckHelp)
	cmd.PersistentFlags().StringVar(&flagProxy, "proxy", "", proxyHelp)
	cmd.PersistentFlags().BoolVar(&flagAllowSFTP, "allow-sftp", false, "Let guests transfer files (scp, sftp) without approval, with your access; downloads only with --read-only.")
	cmd.PersistentFlags().BoolVar(&flagNoSFTP, "no-sftp", false, "Turn off file transfer (sftp and scp) for guests.")
	// Var keeps whatever the variable holds, so it is reset here as the
	// other registrations reset theirs.
	flagAllowForwarding = ""
	cmd.PersistentFlags().Var(&flagAllowForwarding, "allow-forwarding", "Let guests forward ports (ssh -L) without approval: loopback, to this machine's literal 127.0.0.0/8 and ::1 addresses; any, to anything this machine can reach.")
	_ = cmd.RegisterFlagCompletionFunc("allow-forwarding", completeValues(string(forwardLoopback), string(forwardAny)))
	cmd.PersistentFlags().BoolVar(&flagAllowLocalTCPForwarding, "allow-local-tcp-forwarding", false, "--allow-forwarding=any, by its earlier name.")
	cmd.PersistentFlags().BoolVar(&flagNoForwarding, "no-forwarding", false, "Deny guest TCP forwarding, including pregranted and approved destinations.")
	cmd.PersistentFlags().BoolVar(&flagFullAccess, "full-access", false, "Let authorized guests do what an SSH login to your account can, without asking: run commands (ssh SESSION CMD, VS Code, herdr --remote), transfer files (scp, sftp), and forward ports to this machine's loopback addresses (ssh -L 8080:127.0.0.1:8080). Requires --authorized-user or --authorized-keys.")
	cmd.PersistentFlags().StringVar(&flagPtySize, "pty-size", "", "Pin the session's terminal size as COLSxROWS (e.g. 132x43); resize requests are then ignored. Defaults to the attached terminal's size, or 80x24 when there is none.")
	cmd.PersistentFlags().StringVar(&flagTerm, "term", "", "Set TERM for the hosted command. Defaults to the inherited TERM, or "+defaultTerm+" when TERM is unset or "+dumbTerm+".")
	cmd.PersistentFlags().StringVar(&flagName, "name", "", "Name the session, for upterm attach and the session commands to find it by. Defaults to the command's name and four hex digits, e.g. bash-1f3a.")
	cmd.PersistentFlags().DurationVar(&flagJoinTimeout, "join-timeout", 0, "End the session if no guest has joined within this long (e.g. 10m). 0 waits forever. A guest who joins disarms it permanently, so a guest who joins and then leaves does not re-arm it. Change it later with 'upterm session set NAME --join-timeout'.")
	cmd.PersistentFlags().BoolVar(&flagDetach, "detach", false, "Start the session in the background and exit once it is running. On a terminal, upterm asks before starting it, as it does without --detach; with no terminal to ask in, pass --accept. Attach a terminal later with 'upterm attach NAME'; stop it with 'upterm session stop NAME'.")
	cmd.PersistentFlags().StringVarP(&flagHostOutput, "output", "o", "", "With --detach, print the started session as JSON: a superset of the fields 'upterm session info NAME -o json' reports at launch, with sshCommand and joinCommand present even when its status says guests can't join.")
	_ = cmd.RegisterFlagCompletionFunc("output", completeValues("json"))
	cmd.PersistentFlags().StringVar(&flagHostEscapeChar, "escape-char", "~", escapeCharHelp)

	// One run's choices, not standing configuration. --join-timeout stays
	// bound to env and config: CI sets it there.
	perRun(cmd.PersistentFlags(), "name", "detach", "output", "login-command", "allow-exec", "allow-sftp", "no-exec", "allow-forwarding", "no-forwarding", "full-access")

	// --allow-forwarding=any's released name, kept working, and as the config
	// key it was, for the scripts and files that say it. Hidden, and said to
	// be deprecated by validateShareRequiredFlags, only where the command line
	// gives it: pflag's MarkDeprecated would say so for the config key too,
	// which has no other spelling, since --allow-forwarding is the command
	// line's only.
	_ = cmd.PersistentFlags().MarkHidden("allow-local-tcp-forwarding")

	// The provider list comes from host.ProviderList so --help, the generated
	// docs and the parser's own error messages cannot disagree about which
	// services are supported.
	registerAuthUserFlag(cmd.PersistentFlags(), &flagAuthorizedUsers, "authorized-user",
		"Let a user join with the public keys a code-hosting service lists for them, fetched through --proxy when it is set. Repeatable. "+
			"Providers: "+host.ProviderList()+". "+
			"Examples: github:alice, github:bob@ghe.example.com, gitea:carol@git.example.com, https://git.example.com/dave")

	// The help lists the flags by what they decide; the rest are under the
	// last heading.
	const (
		whoCanJoin = "Who can join"
		guestsDo   = "What guests can do"
		background = "Running in the background"
		relay      = "Relay"
		other      = "Other flags"
	)
	groupFlags(cmd, whoCanJoin, guestsDo, background, relay, other)
	flags := cmd.PersistentFlags()
	flagGroup(flags, whoCanJoin, "authorized-keys", "authorized-user")
	flagGroup(flags, guestsDo, "allow-exec", "allow-sftp", "allow-forwarding", "full-access",
		"no-exec", "no-sftp", "no-forwarding", "read-only", "login-command", "force-command")
	flagGroup(flags, background, "detach", "accept", "name", "output", "join-timeout")
	flagGroup(flags, relay, "server", "proxy", "private-key", "known-hosts", "skip-host-key-check")

	// Superseded by --authorized-user. Kept working and hidden rather than
	// deprecated: action-upterm wraps these flags and users pin it at @v1, so a
	// deprecation notice would appear in logs they cannot act on.
	for _, lf := range legacyUserFlags {
		// Only errors on an unknown flag name, all of which are registered above.
		_ = cmd.PersistentFlags().MarkHidden(lf.flag)
	}

	addHostFlags(cmd, ext)

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

func resolveSessionName(explicit string, newName func() string) string {
	if explicit != "" {
		return explicit
	}
	return newName()
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
	return runWithNameRetry(logger, explicit, func() string { return drawName(command) }, run)
}

// drawName draws a session name for command. A var so a test can see whether
// a name was drawn.
var drawName = sessiondir.GenerateName

// runWithNameRetry is runWithGeneratedNameRetry with the source of generated
// names as an argument, so a test can spell out the draws instead of taking
// them from crypto/rand.
//
// Without the seam, a test that asks for three draws is also betting on three
// real ones being distinct, and sessiondir's four hex digits collide about
// once in 22,000 such runs — a property of the generator, not of the retry the
// test is about, and one that has already been read as a regression (#574).
func runWithNameRetry(logger *slog.Logger, explicit string, newName func() string, run func(name string) error) error {
	return runWithNormalizedNames(logger, explicit, newName, nil, run)
}

// runWithNormalizedNames is runWithNameRetry with each name drawn passed
// through normalize, when it is set, whose result must be a valid session
// name: its error ends the run, as it is, as an invalid result's does. An
// explicit name is the caller's to normalize.
func runWithNormalizedNames(logger *slog.Logger, explicit string, newName func() string, normalize func(string) (string, error), run func(name string) error) error {
	if logger == nil {
		logger = slog.Default()
	}

	var err error
	for attempt := 0; attempt < maxGeneratedNameAttempts; attempt++ {
		name := resolveSessionName(explicit, newName)
		if explicit == "" && normalize != nil {
			if name, err = normalize(name); err != nil {
				return verbatimError{text: safeText(err.Error())}
			}
			if err := sessiondir.ValidateName(name); err != nil {
				return err
			}
		}
		err = run(name)
		if err == nil {
			return nil
		}
		// Taken here, or where the run was placed: either way the name drawn
		// is the one at fault.
		if explicit != "" || (!errors.Is(err, sessiondir.ErrNameInUse) && !errors.Is(err, host.ErrNameTaken)) {
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

// nameInUseError is the error for a name a running session holds; its message
// says to attach to that session or pick another --name. It unwraps to
// sessiondir.ErrNameInUse, which runWithGeneratedNameRetry redraws on for a
// generated name (an explicit --name is reported as is).
type nameInUseError struct {
	name string
}

func (e nameInUseError) Error() string {
	return fmt.Sprintf("a running session is already named %s; attach with upterm attach %s, or pick another --name", e.name, e.name)
}

func (nameInUseError) Unwrap() error { return sessiondir.ErrNameInUse }

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

// validateJoinTimeout, validateReadOnlyForwarding and validateServer are the
// checks host makes on its flags' values before it runs. config edit calls
// them on the values the config file sets, so a file it accepts is one host
// accepts.
func validateJoinTimeout(d time.Duration) error {
	if d < 0 {
		return errors.New("--join-timeout cannot be negative; use 0 to wait forever")
	}
	return nil
}

func validateReadOnlyForwarding(readOnly, forwarding bool) error {
	if readOnly && forwarding {
		return errors.New("--read-only and --allow-local-tcp-forwarding cannot be used together: a read-only session must not permit network pivoting through the host")
	}
	return nil
}

// grantConflict is a guest grant and a denial of the same thing, which wins.
type grantConflict struct {
	grant, denial   string // the flags' names
	granted, denied bool
	what            string // what the denial denies
}

func grantConflicts() []grantConflict {
	forwards := flagAllowForwarding != ""
	return []grantConflict{
		{"allow-exec", "no-exec", flagAllowExec, flagNoExec, "guest commands"},
		{"allow-exec", "read-only", flagAllowExec, flagReadOnly, "guest commands"},
		{"allow-sftp", "no-sftp", flagAllowSFTP, flagNoSFTP, "file transfers"},
		{"allow-forwarding", "no-forwarding", forwards, flagNoForwarding, "port forwarding"},
		{"allow-forwarding", "read-only", forwards, flagReadOnly, "port forwarding"},
		{"allow-local-tcp-forwarding", "no-forwarding", flagAllowLocalTCPForwarding, flagNoForwarding, "port forwarding"},
		{"allow-local-tcp-forwarding", "read-only", flagAllowLocalTCPForwarding, flagReadOnly, "port forwarding"},
		{"full-access", "no-exec", flagFullAccess, flagNoExec, "guest commands"},
		{"full-access", "no-sftp", flagFullAccess, flagNoSFTP, "file transfers"},
		{"full-access", "no-forwarding", flagFullAccess, flagNoForwarding, "port forwarding"},
		{"full-access", "read-only", flagFullAccess, flagReadOnly, "guest commands"},
	}
}

// validateGrants checks each guest grant against a denial of the same thing.
// Both on the command line, the command contradicts itself: an error. With
// one from the environment or the config file, which origin says, the denial
// wins and the session starts, with a warning naming where that side came
// from; but --full-access asks for all of what it grants, so a denial of any
// of it refuses the run wherever it came from. With neither on the command
// line the file contradicts itself, which is the error config edit reports
// for it: only read-only and allow-local-tcp-forwarding are both keys.
//
// --full-access is a shell as you, so it also needs an allowlist.
//
// allow-local-tcp-forwarding from the environment or the config file lets
// guests forward anywhere, which a command line asking for loopback forwards
// alone doesn't narrow; that is a warning too.
func validateGrants(origin func(name string) string) (errs []error, warnings []string) {
	if flagFullAccess && !authorizationRequested() {
		errs = append(errs, errors.New("--full-access needs --authorized-user or --authorized-keys: without one, anyone with the session ID would get a shell as you"))
	}
	for _, c := range grantConflicts() {
		if !c.granted || !c.denied {
			continue
		}
		grantFrom, denialFrom := origin(c.grant), origin(c.denial)
		grant, denial := grantSide(c.grant, grantFrom), grantSide(c.denial, denialFrom)
		switch {
		case grantFrom == "" && (denialFrom == "" || c.grant == "full-access"):
			errs = append(errs, fmt.Errorf("%s and %s contradict each other; pick one", grant, denial))
		case grantFrom == "" || denialFrom == "":
			warnings = append(warnings, fmt.Sprintf("upterm: %s has no effect: %s denies %s", grant, denial, c.what))
		}
	}
	if origin("read-only") != "" && origin("allow-local-tcp-forwarding") != "" {
		if err := validateReadOnlyForwarding(flagReadOnly, flagAllowLocalTCPForwarding); err != nil {
			errs = append(errs, err)
		}
	}
	// Nothing to say where forwarding is off anyway, where the command line
	// asks for forwards anywhere itself, or where it gives
	// allow-local-tcp-forwarding a value of its own.
	if from := origin("allow-local-tcp-forwarding"); from != "" && flagAllowLocalTCPForwarding && !flagNoForwarding && !flagReadOnly {
		widens := grantSide("allow-local-tcp-forwarding", from) + " lets guests forward to any destination"
		switch {
		case flagAllowForwarding == forwardLoopback:
			warnings = append(warnings, "upterm: --allow-forwarding=loopback has no effect: "+widens)
		case flagFullAccess && flagAllowForwarding == "":
			warnings = append(warnings, "upterm: --full-access doesn't keep forwarding to loopback addresses: "+widens)
		}
	}
	return errs, warnings
}

// grantSide is one side of a grant conflict as upterm says it: the flag, or
// the key or variable with where its value came from.
func grantSide(name, from string) string {
	if from == "" {
		return "--" + name
	}
	return name + " (from " + from + ")"
}

// flagOrigin is where this run's value of the flag name came from: "" for
// the command line, else the environment variable or the config file that
// set it, the variable when both did, as it is the one that wins. A flag
// nothing set reads as the command line's: it holds its default.
func flagOrigin(name string) string {
	if commandLineFlags[name] || !suppliedFlags[name] {
		return ""
	}
	if os.Getenv(envVarName(name)) != "" {
		return envVarName(name)
	}
	return utils.UptermConfigFilePath()
}

// validateServer checks a server address: ssh, ws or wss, and a host for ssh.
func validateServer(raw string) error {
	if raw == "" {
		return errors.New("missing flag --server")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("error parsing server URL: %w", err)
	}

	switch u.Scheme {
	case "ssh":
		// An address with a port but no host, such as ssh://:2222, has an
		// empty hostname, which dials this machine.
		if u.Hostname() == "" {
			return errors.New("missing host in address")
		}
	case "ws", "wss":
	default:
		return fmt.Errorf("unsupported server protocol %s", u.Scheme)
	}
	return nil
}

// withDefaultPort is a server address with its scheme's port when it has
// none (ssh 22, ws 80, wss 443): known_hosts keys the server as host:port, so
// the URL must carry one. ws.NewWSConn drops it again from the dial URL so the
// Host header stays "host", not "host:443".
func withDefaultPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Port() != "" {
		return raw
	}
	var port string
	switch u.Scheme {
	case "ssh":
		port = "22"
	case "ws":
		port = "80"
	case "wss":
		port = "443"
	default:
		return raw
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	return u.String()
}

func validateShareRequiredFlags(c *cobra.Command, args []string) error {
	return validateHostFlags(c, false)
}

// hostRun is what upterm host's pre-run decided about the run, for its run:
// the extension's answer and the options it was asked with.
type hostRun struct {
	prepared Prepared
	options  HostOptions
}

// hostRunKey holds the run's *hostRun in the command's context.
type hostRunKey struct{}

// hostRunFrom is the run's *hostRun, or nil when no extension's Prepare was
// asked about it.
func hostRunFrom(ctx context.Context) *hostRun {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(hostRunKey{}).(*hostRun)
	return r
}

// delegated reports whether r is a delegated run.
func (r *hostRun) delegated() bool { return r != nil && r.prepared.Delegated }

// hostPreRunE is upterm host's pre-run. In the process an operator runs it
// in, ext's Prepare, if it has one, is asked about the run first, before
// anything else upterm host checks or does, and its NormalizeName is applied
// to --name. Then the flags are checked, as validateShareRequiredFlags checks
// them, except that a delegated run's --server and default --known-hosts
// aren't: the run doesn't use them. A delegated run's session process skips
// the same checks; one whose handoff couldn't be read checks nothing, so
// that its run can say why. An ordinary run's session process checks the
// name its parent handed it, which may be --name normalized.
func hostPreRunE(ext *Extension) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		if isDaemonProcess() {
			if daemonHandoff != nil && daemonHandoff.err != nil {
				return nil
			}
			if name := os.Getenv(daemonNameEnv); daemonHandoff == nil && flagName != "" && name != "" {
				flagName = name
			}
			return validateHostFlags(c, daemonHandoff != nil)
		}
		if ext == nil || ext.Prepare == nil {
			return validateHostFlags(c, false)
		}
		opts, err := buildHostOptions(c)
		if err != nil {
			return err
		}
		p, err := ext.Prepare(c.Context(), opts)
		if err != nil {
			return verbatimError{text: safeText(err.Error())}
		}
		if p.Delegated && ext.Broker == nil {
			return errNoBroker
		}
		if opts.NameGiven && p.NormalizeName != nil {
			name, err := p.NormalizeName(flagName)
			if err != nil {
				return verbatimError{text: safeText(err.Error())}
			}
			// Checked as a drawn one is: an empty one would have a name
			// drawn in its place.
			if err := sessiondir.ValidateName(name); err != nil {
				return err
			}
			flagName = name
		}
		c.SetContext(context.WithValue(c.Context(), hostRunKey{}, &hostRun{prepared: p, options: opts}))
		return validateHostFlags(c, p.Delegated)
	}
}

// buildHostOptions is this run of upterm host, c, as an extension's Prepare
// is told it: each flag's value and where it came from, the authorized_keys
// file read, and the users the user flags name, parsed but not looked up.
func buildHostOptions(c *cobra.Command) (HostOptions, error) {
	opts := HostOptions{
		Name: flagName,
		// An empty --name names nothing: upterm draws the name, as it does
		// with no --name.
		NameGiven: commandLineFlags["name"] && flagName != "",
		Flags:     make(map[string]FlagValue),
		Extension: make(map[string]FlagValue),
	}
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		fv := FlagValue{Value: f.Value.String(), Source: flagSourceOf(f.Name)}
		if isExtensionFlag(f) {
			opts.Extension[f.Name] = fv
			return
		}
		// A proxy's URL can hold its credentials.
		if f.Name == "proxy" {
			fv.Value = ""
		}
		opts.Flags[f.Name] = fv
	})
	if flagAuthorizedKeys != "" {
		file, err := readAuthorizedKeyFile(flagAuthorizedKeys)
		if err != nil {
			return HostOptions{}, err
		}
		opts.AuthorizedKeys = []AuthorizedKeyFile{file}
	}
	var errs error
	for _, flag := range userSpecs() {
		for _, s := range flag.specs {
			ref, err := host.ParseUserRef(s)
			if err != nil {
				errs = multierror.Append(errs, err)
				continue
			}
			opts.UserRefs = append(opts.UserRefs, UserRef{Flag: "--" + flag.flag, Ref: ref})
		}
	}
	if errs != nil {
		return HostOptions{}, errs
	}
	return opts, nil
}

// flagSourceOf is where this run's value of the flag name came from: the
// command line, else its UPTERM_ variable, else the config file, else its
// default.
func flagSourceOf(name string) FlagSource {
	switch {
	case commandLineFlags[name]:
		return SourceCommandLine
	case !suppliedFlags[name]:
		return SourceDefault
	case envSupplied(name):
		return SourceEnv
	}
	return SourceConfig
}

// validateHostFlags checks upterm host's flags before it runs. A delegated
// run's relay is its placement's, so --server and the default --known-hosts
// aren't checked for one.
func validateHostFlags(c *cobra.Command, delegated bool) error {
	var result error
	if err := validateJoinTimeout(flagJoinTimeout); err != nil {
		result = multierror.Append(result, err)
	}

	grantErrs, warnings := validateGrants(flagOrigin)
	for _, err := range grantErrs {
		result = multierror.Append(result, err)
	}
	// Only where it was typed, and only as the grant: its key and variable,
	// and =false, which turns their grant off, have no other spelling.
	if commandLineFlags["allow-local-tcp-forwarding"] && flagAllowLocalTCPForwarding {
		warnings = append([]string{"upterm: --allow-local-tcp-forwarding is deprecated; use --allow-forwarding=any"}, warnings...)
	}
	// The parent's only: the daemon makes the same checks on the same argv,
	// env and config, and its stderr is the log.
	if !isDaemonProcess() {
		stderr := io.Writer(os.Stderr)
		if c != nil {
			stderr = c.ErrOrStderr()
		}
		for _, line := range warnings {
			_, _ = fmt.Fprintln(stderr, line)
		}
	}

	if err := validateSessionNameFlag(flagName); err != nil {
		result = multierror.Append(result, err)
	}

	if flagHostOutput != "" && !flagDetach {
		result = multierror.Append(result, fmt.Errorf("--output requires --detach"))
	}
	if flagHostOutput != "" && flagHostOutput != "json" {
		result = multierror.Append(result, fmt.Errorf("invalid output format %q: must be 'json'", flagHostOutput))
	}

	if !delegated {
		if err := validateServer(flagServer); err != nil {
			result = multierror.Append(result, err)
		} else {
			flagServer = withDefaultPort(flagServer)
		}

		if err := homeDefaultError(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if _, err := parseGuestCommands(c); err != nil {
		result = multierror.Append(result, err)
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
//
// --detach asks too, here, before it goes to the background: going there
// is no answer to the question. Without a terminal it needs --accept, which
// grants file transfers as well, and the refusal says so.
func confirmationTerminalError(accept, detach bool, stdin, stdout *os.File) error {
	if accept {
		return nil
	}
	if term.IsTerminal(int(stdin.Fd())) && term.IsTerminal(int(stdout.Fd())) {
		return nil
	}
	if detach {
		return errors.New("--detach needs --accept when there is no terminal to ask in (it also lets guests transfer files without asking)")
	}
	return errors.New("upterm host needs a terminal to ask before starting; pass --accept to start without asking")
}

// hostOptions is everything shareRunE derives from flags and arguments
// without touching the network: both the process that starts a session and
// the daemon it spawns compute it, from the same argv, and get the same
// answer.
type hostOptions struct {
	joinTimeout  time.Duration
	command      []string
	forceCommand []string
	loginCommand []string
	commandDir   string
	proxyURL     *url.URL
	refs         []host.UserRef
	ptySize      termsize.Size
	term         string
	escape       byte
	// authorizationRequested says the run asked to restrict who may join,
	// from any origin, and nameGenerated that no --name named it.
	authorizationRequested bool
	nameGenerated          bool
	// delegated says the run is a delegated one, whose placement says where
	// it registers and which relay keys it trusts there.
	delegated bool
}

func parseHostOptions(args []string) (hostOptions, error) {
	return parseHostOptionsFor(args, false)
}

// parseHostOptionsFor is parseHostOptions for a run that is delegated or
// not. A delegated run dials no proxy, so --proxy isn't read for one.
func parseHostOptionsFor(args []string, delegated bool) (hostOptions, error) {
	opts := hostOptions{delegated: delegated}
	var err error
	opts.commandDir, err = filepath.Abs("")
	if err != nil {
		return opts, err
	}
	if !delegated {
		if opts.proxyURL, err = parseProxyURL(flagProxy); err != nil {
			return opts, err
		}
	}
	opts.authorizationRequested = authorizationRequested()
	opts.nameGenerated = flagName == ""
	opts.joinTimeout = flagJoinTimeout
	opts.command = args
	if len(opts.command) == 0 {
		if opts.command, err = shlex.Split(getDefaultShell()); err != nil {
			return opts, err
		}
		if len(opts.command) == 0 {
			return opts, fmt.Errorf("no command is specified")
		}
	}
	if opts.loginCommand, err = parseGuestCommands(nil); err != nil {
		return opts, err
	}
	if opts.forceCommand, err = parseForceCommand(flagForceCommand); err != nil {
		return opts, err
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

// parseForceCommand splits --force-command into the command it names; empty
// names none.
func parseForceCommand(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	command, err := shlex.Split(s)
	if err != nil {
		return nil, fmt.Errorf("error parsing command %s: %w", s, err)
	}
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return nil, fmt.Errorf("command must name an executable")
	}
	return command, nil
}

func parseGuestCommands(cmd *cobra.Command) ([]string, error) {
	if flagLoginCommand != "" && flagForceCommand != "" {
		return nil, errors.New("--login-command and --force-command are mutually exclusive")
	}
	if cmd != nil {
		for _, name := range []string{"login-command", "force-command"} {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				flag = cmd.PersistentFlags().Lookup(name)
			}
			if flag != nil && flag.Changed && strings.TrimSpace(flag.Value.String()) == "" {
				return nil, fmt.Errorf("--%s must name an executable", name)
			}
		}
	}
	if _, err := parseForceCommand(flagForceCommand); err != nil {
		return nil, err
	}
	return parseForceCommand(flagLoginCommand)
}

// resolveAuthorizedKeys reads the authorized keys file and fetches every
// referenced user's keys, and refuses to start unrestricted when a
// restriction was asked for.
func resolveAuthorizedKeys(ctx context.Context, opts hostOptions, logger *slog.Logger) ([]*host.AuthorizedKey, error) {
	return resolveAuthorizedKeysFrom(ctx, flagAuthorizedKeys, authorizationRequested(), opts, logger)
}

// resolveAuthorizedKeysFrom is resolveAuthorizedKeys for the authorized_keys
// file path, "" for none, in a run that requested a restriction or not.
func resolveAuthorizedKeysFrom(ctx context.Context, path string, requested bool, opts hostOptions, logger *slog.Logger) ([]*host.AuthorizedKey, error) {
	var authorizedKeys []*host.AuthorizedKey
	if path != "" {
		// Not wrapped: AuthorizedKeysFromFile already names both the action and
		// the file, so a wrap here reads "error reading authorized keys: error
		// reading authorized keys file /typo: ...".
		aks, err := host.AuthorizedKeysFromFile(path)
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
	if requested && countKeys(authorizedKeys) == 0 {
		return nil, fmt.Errorf("authorization was requested but no public keys were resolved; refusing to start a session that would accept any client")
	}
	return authorizedKeys, nil
}

func shareRunE(c *cobra.Command, ext *Extension, args []string) error {
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
		return mapUserAction(c, runDaemon(c.Context(), logger.Logger, ext, daemonHandoff, args, conn, daemonName))
	}

	// Refuse before anything is claimed or connected: a session that reaches
	// the prompt and cannot be answered is an orphan holding a name.
	if err := confirmationTerminalError(flagAccept, flagDetach, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "upterm: "+err.Error())
		return SilentError{Err: err}
	}

	run := hostRunFrom(c.Context())
	opts, err := parseHostOptionsFor(args, run.delegated())
	if err != nil {
		return err
	}
	return runHostParent(c, logger.Logger, opts, run)
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
func runHostParent(c *cobra.Command, logger *slog.Logger, opts hostOptions, run *hostRun) error {
	// A delegated run's session process is handed the settings this one
	// resolved, the same for every name it tries; an ordinary run's reads
	// its own.
	var (
		settings  HostSettings
		normalize func(string) (string, error)
	)
	if run.delegated() {
		settings = hostSettingsFromFlags()
		settings.Proxy = ""
	}
	if run != nil {
		normalize = run.prepared.NormalizeName
	}
	display := displaySession
	if flagDetach && flagHostOutput == "json" && flagAccept {
		// stdout is the JSON, and nobody is asked: the banner would be noise
		// in it. Without --accept the banner is what the question is about,
		// and the JSON follows the answer.
		display = func(context.Context, *api.GetSessionResponse, string) error { return nil }
	}
	var (
		attachClient clientFunc
		hint         string
	)
	if !flagDetach {
		attachClient = func(ctx context.Context, socket string, keys []ssh.PublicKey, src statusSource) (attach.Result, error) {
			lt := classifyTerminal(os.Stdin, os.Stdout, tty.Owned, opts.term)
			return attachLocalTerminal(ctx, socket, keys, lt, opts.escape, src, os.Stdin, os.Stdout, logger)
		}
		// The terminal is classified the way the client classifies it, so
		// the hint names keys only where the client will act on them.
		hint = hostKeyHint(classifyTerminal(os.Stdin, os.Stdout, tty.Owned, opts.term), opts.escape, os.Getenv("SSH_TTY") != "")
	}
	warning := logWarningFor(c.Context())
	err := runWithNormalizedNames(logger, flagName, func() string { return drawName(opts.command) }, normalize, func(name string) error {
		var handoff string
		if run.delegated() {
			var err error
			if handoff, err = encodeHandoff(Handoff{Name: name, Settings: settings, Options: run.options, Payload: run.prepared.Payload}, exactValues(c)); err != nil {
				return err
			}
		}
		s := &spawnedSession{
			handoff:      handoff,
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
			keyHint:      hint,
			hintOut:      hintOut(os.Stderr, os.Stdout),
			logger:       logger,
			logWarning:   warning,
		}
		return s.run(c.Context())
	})

	// A bare ExitCodeError is the hosted command's status: the line that
	// explains it was printed already, and Exit prints nothing for it.
	return mapUserAction(c, err)
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

// mapUserAction turns a UserDiscardedError, UserInterruptedError or
// UserTerminatedError from a run attempt into the exit shareRunE reports, on
// either path: a decline is a clean exit (nothing printed, status 0), and an
// interruption or termination is Reported with status 130 or 143, so that
// Exit prints nothing for it — a session the operator declined or interrupted
// at the prompt is not a fault, and must not read as one in the daemon's log
// or the foreground's stderr. Anything else is returned unchanged.
func mapUserAction(_ *cobra.Command, err error) error {
	var userDiscardedErr UserDiscardedError
	if errors.As(err, &userDiscardedErr) {
		return nil // Clean exit for user discard (exit code 0)
	}

	var userInterruptedErr UserInterruptedError
	if errors.As(err, &userInterruptedErr) {
		return Reported{Err: ExitCodeError{Code: exitInterrupted, Err: userInterruptedErr}}
	}

	var userTerminatedErr UserTerminatedError
	if errors.As(err, &userTerminatedErr) {
		return Reported{Err: ExitCodeError{Code: exitTerminated, Err: userTerminatedErr}}
	}

	return err
}

// notify raises a desktop notification. A var so a test can see what the
// notifiers below decided to send, rather than pop a real notification on
// whoever is running the suite.
var notify = beeep.Notify

// notification is the title and body of one desktop notification.
type notification struct{ Title, Body string }

// guestNotifier raises the desktop notifications for guests joining and
// leaving the session it names. An operator may have several sessions
// running, so each notification says which one it is about. hide hides
// guests' addresses in them, as --hide-client-ip does.
type guestNotifier struct {
	name string
	hide bool
}

func (n guestNotifier) joined(c *api.Client) {
	// The host's own terminal is a client of the session now, and notifying
	// the operator that they have joined their own session is noise.
	if !shouldNotifyClient(c) {
		return
	}
	_ = notify("A guest joined "+n.name, clientDescHiding(c, n.hide), icon.Upterm)
}

func (n guestNotifier) left(c *api.Client) {
	if !shouldNotifyClient(c) {
		return
	}
	_ = notify("A guest left "+n.name, clientDescHiding(c, n.hide), icon.Upterm)
}

// tunnelNotification is the notification for a change in the session's
// connection to the relay. Each text claims only what the event confirms:
// that upterm is retrying, only when the relay can reconnect, and that the
// connect string changed, only when the session came back at another node.
func tunnelNotification(name string, e host.TunnelEvent) notification {
	switch {
	case !e.Up && e.CanReconnect:
		return notification{name + " lost the relay", "Guests can't join while the relay is disconnected; upterm is retrying."}
	case !e.Up:
		return notification{name + " lost the relay", "This relay can't reconnect it; guests can't join until you restart the session."}
	case e.RouteChanged:
		return notification{name + " is back on the relay", "Its connect string changed; upterm session info " + name + " shows the new one."}
	default:
		return notification{name + " is back on the relay", "Guests can join again with the same command."}
	}
}

// tunnelNotifier raises the notification for each change in the connection
// to the relay of the session name.
func tunnelNotifier(name string) func(host.TunnelEvent) {
	return func(e host.TunnelEvent) {
		n := tunnelNotification(name, e)
		_ = notify(n.Title, n.Body, icon.Upterm)
	}
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
// The warnings said ahead of the banner are not written here: the daemon
// sends them to the parent before it reports the session created, and the
// parent prints them on stderr, one line each, in the order they arrive.
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
	// --detach leaves this terminal as soon as the session runs, and a door
	// is reached from elsewhere: its banner says how, with what upterm
	// session ssh-config prints. Where it would print none, as for a relay's
	// SSH user or address sshConfigFor won't write, the section is left out.
	if flagDetach && doorShaped(session) {
		if text, err := sshConfigText(session, name); err == nil {
			detail.SSHConfig = text
		}
	}
	// A delegated session's banner is its record's: its guest address, who
	// decides its guests, how they reach it, and what its authority says
	// about it. A record that can't be read in time, or doesn't confirm the
	// session, has none of that to show, so the banner is titled with the
	// session's name and offers no way in, and the session starts all the
	// same: `session info` says the rest once the record can be read.
	if isDelegated(session, nil) {
		d := bannerDelegation(ctx, session, name)
		detail = withDelegation(detail, d, d != nil)
	}

	// The logger root.go put in the context: it writes to upterm's log
	// file, which is where an operator goes to find out what became of a
	// startup. Nil until some caller sets one up, which printBanner reads
	// as the package default.
	var logger *slog.Logger
	if l := uptermctx.Logger(ctx); l != nil {
		logger = l.Logger
	}
	// Printed once, whether or not anyone is asked: the prompt below
	// redraws its own line and nothing above it, so the banner is not
	// repainted under it on every redraw, and what it prints stays in the
	// scrollback as --accept's does.
	printBanner(logger, detail)

	// With --accept, nobody is asked.
	if flagAccept {
		return nil
	}

	// Run interactive TUI for confirmation (TTY is guaranteed by early check in shareRunE)
	model := tui.NewHostSessionModel(false)
	p := tea.NewProgram(model, tea.WithContext(ctx))

	return confirmationOutcome(p.Run())
}

// bannerReadTimeout bounds the record read behind a delegated session's
// banner, as statusHintTimeout bounds --detach's: a registry slow to answer
// costs the banner its delegation, not the start. A variable so that a test
// can wait less on a registry it holds.
var bannerReadTimeout = statusHintTimeout

// bannerDelegation is the delegation the record of name holds for the
// delegated session sess describes, read within bannerReadTimeout: nil when
// it can't be read, or doesn't confirm sess by its routing ID, which no other
// run has, and its guest address. The daemon that sent sess holds the name
// while it waits on this display.
func bannerDelegation(ctx context.Context, sess *api.GetSessionResponse, name string) *sessiondir.Delegation {
	ctx, cancel := context.WithTimeout(ctx, bannerReadTimeout)
	defer cancel()
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	if err != nil || !held || rec == nil || rec.Delegation == nil || rec.Delegation.RoutingID != sess.GetSessionId() ||
		!confirmsDelegation(sess, rec.Delegation) {
		return nil
	}
	return rec.Delegation
}

// confirmationOutcome is what displaySession makes of how the prompt ended:
// the final model and the error Program.Run returned.
//
// A prompt that ended without an answer never starts the session. SIGINT is
// an error wrapping tea.ErrInterrupted, which is the operator's Ctrl-C all the
// same; SIGTERM is no error at all, only a model still undecided.
func confirmationOutcome(finalModel tea.Model, err error) error {
	if errors.Is(err, tea.ErrInterrupted) {
		return UserInterruptedError{}
	}
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
	case tui.HostSessionConfirmUndecided:
		return UserTerminatedError{}
	default:
		return fmt.Errorf("unknown confirmation result: %d", sessionModel.Result())
	}
}

// homeDefault returns HOME-based defaults, or "" and the reason when HOME
// is unavailable. Construction never exits.
func homeDefault(rel ...string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{home}, rel...)...), nil
}

// homeDefaultError fails a run of host or join that relies on the default
// --known-hosts, not supplied from any origin, when there is no home
// directory to find it in. -i's default needs none: see
// defaultPrivateKeys.
func homeDefaultError() error {
	if suppliedFlags["known-hosts"] {
		return nil
	}
	if _, err := homeDefault(); err != nil {
		return fmt.Errorf("can't find your home directory for the default --known-hosts: %w; pass --known-hosts", err)
	}
	return nil
}

// defaultPrivateKeys is the files that exist of OpenSSH's default
// identities. With no home directory there are none, as in a home with no
// keys: the agent's keys and a generated one are used as ever.
func defaultPrivateKeys() []string {
	sshDir, err := homeDefault(".ssh")
	if err != nil {
		return nil
	}
	var pks []string
	for _, f := range []string{
		"id_ed25519",
		"id_ed25519_sk",
		"id_ecdsa",
		"id_ecdsa_sk",
		"id_dsa",
		"id_rsa",
	} {
		pk := filepath.Join(sshDir, f)
		if _, err := os.Stat(pk); os.IsNotExist(err) {
			continue
		}

		pks = append(pks, pk)
	}

	return pks
}

// defaultKnownHost is ~/.ssh/known_hosts, or "" with no home directory.
func defaultKnownHost() string {
	kh, _ := homeDefault(".ssh", "known_hosts")
	return kh
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

// userFlagSpecs is the users one flag names, as host.ParseUserRef reads them.
type userFlagSpecs struct {
	flag  string
	specs []string
}

// userSpecs is each user flag with the users it holds: --authorized-user, then
// the legacy per-service flags, whose values are users of one service.
func userSpecs() []userFlagSpecs {
	specs := []userFlagSpecs{{"authorized-user", flagAuthorizedUsers}}
	for _, lf := range legacyUserFlags {
		var users []string
		for _, user := range *lf.values {
			users = append(users, lf.provider+":"+user)
		}
		specs = append(specs, userFlagSpecs{lf.flag, users})
	}
	return specs
}

func collectUserRefs() ([]host.UserRef, error) {
	var (
		refs []host.UserRef
		errs error
	)
	for _, flag := range userSpecs() {
		for _, s := range flag.specs {
			ref, err := host.ParseUserRef(s)
			if err != nil {
				errs = multierror.Append(errs, err)
				continue
			}
			refs = append(refs, ref)
		}
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
