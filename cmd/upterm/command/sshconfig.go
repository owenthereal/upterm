package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func sshConfigCmd() *cobra.Command {
	var alias string
	cmd := &cobra.Command{
		Use:   "ssh-config NAME|ID",
		Short: "Print the ssh config that reaches a session",
		Long: `Print what ssh needs to reach a session by a name of your own, so that plain
ssh, scp, sftp and VS Code (Remote-SSH) connect to it as to any other host: a
Host block for ~/.ssh/config, and the relay's key for ~/.ssh/known_hosts.

Put the Host block in ~/.ssh/config on each device you connect from. Its User
is the session's SSH user, which changes whenever the session restarts, and
on a relay that routes by node, also when the session comes back on another
node: run this again then, and replace the block. The Host is the session's
name, or --alias.

Add the known_hosts lines to ~/.ssh/known_hosts on each device, once. They
are the relay key this session's host trusted when it connected. When the
host accepted that key on first use, with no line in its known_hosts to check
it against, a comment above it says so: compare its fingerprint with the one
the relay's operator publishes before you add it. With no comment above it, a
line already in the host's known_hosts matched the key, which makes it only
as good as that line.

The two parts go in different files: the known_hosts lines aren't ssh
config, so don't append the whole output to ~/.ssh/config.

` + nameOrIDHelp + `

'upterm session info NAME -o json' has the same block as sshConfig, and the
known_hosts lines as knownHosts, beside how the host came to trust the key
(relayKeyTrust).

Exits 4 when no session has the name, and 1 for any other failure.`,
		Example: `  # Print the ssh config for the session named home:
  upterm session ssh-config home

  # The same session, by its session ID:
  upterm session ssh-config d3k5fia7m4us73ehblug

  # Name it laptop-home in ~/.ssh/config, for 'ssh laptop-home':
  upterm session ssh-config home --alias laptop-home`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessionNames,
		RunE: func(c *cobra.Command, args []string) error {
			return sshConfigRunE(c.Context(), args[0], alias)
		},
	}

	// Only the command line sets it: a name for one session in a config file
	// would name every session the same.
	cmd.Flags().StringVar(&alias, "alias", "", "The name to give the session in ~/.ssh/config, for ssh ALIAS (default: the session's name)")
	_ = cmd.Flags().SetAnnotation("alias", annotationCLIOnly, []string{"true"})

	return cmd
}

// aliasRe is what a Host block's alias may be, --alias's included: one word
// ssh takes as a host's name, not as an option or a pattern.
var aliasRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func sshConfigRunE(ctx context.Context, arg, alias string) error {
	// Checked before anything is read, so an alias ssh can't take fails the
	// same whether or not the session exists.
	if alias != "" && !aliasRe.MatchString(alias) {
		return fmt.Errorf("invalid --alias %q: use letters, digits, '.', '_' and '-', starting with a letter or digit", alias)
	}

	// One deadline for the whole lookup, as `session info` has.
	ctx, cancel := context.WithTimeout(ctx, sessionQueryTimeout)
	defer cancel()

	r, err := resolveSession(ctx, arg)
	if err != nil {
		return err
	}
	info, live, err := lookup(ctx, r)
	if err != nil {
		return err
	}
	if live == nil {
		return unreachable(r, info)
	}
	// A delegated session whose record and daemon disagree has no way in
	// that both confirm, the daemon's own Host block included.
	if info.delegated && info.delegation == nil {
		return fmt.Errorf("session %s's record and its process give different guest addresses, so upterm won't write an ssh config for it", arg)
	}

	if alias == "" {
		alias = r.Name
	}
	text, err := sshConfigText(live, alias)
	// The session as it was asked for, and neither the user, which is the
	// relay's to choose, nor the relay's address.
	switch {
	case errors.Is(err, errUnwritableUser):
		return fmt.Errorf("the relay gave session %s an SSH user that upterm won't write into an ssh config", arg)
	case errors.Is(err, errUnwritableRelay):
		return fmt.Errorf("the relay address for session %s has characters that upterm won't write into an ssh config", arg)
	case err != nil:
		return err
	}
	_, err = io.WriteString(os.Stdout, text)
	return err
}

// unreachable is why lookup found no session guests can connect to now: it
// has ended, its record says it isn't joinable, or its admin socket didn't
// answer for it.
func unreachable(r resolved, info sessionInfo) error {
	name := r.named(r.Name)
	switch {
	case info.Status == statusEnded:
		return fmt.Errorf("session %s has ended", name)
	case !joinable(info.Status):
		return fmt.Errorf("session %s is %s, so guests can't connect to it now; 'upterm session info %s' says why", name, info.Status, r.Name)
	}
	return errors.New(isntAnswering(name, &sessiondir.Record{Pid: info.Pid}))
}

// sshConfigText is what `session ssh-config` prints, and the --detach banner
// of a door shows: sess's Host block for ~/.ssh/config, as alias, and the pin
// of its relay for ~/.ssh/known_hosts, each under a comment naming its file.
func sshConfigText(sess *api.GetSessionResponse, alias string) (string, error) {
	block, err := sshConfigFor(sess, alias)
	if err != nil {
		return "", err
	}
	pin, ok := relayPin(sess)
	if !ok {
		pin = unreportedPin
	}
	return "# ~/.ssh/config\n" + block + "\n# ~/.ssh/known_hosts, once per device\n" + pin + "\n", nil
}

// sshUserRe is what a Host block's User may be: letters, digits and
// ._~+=:-, which hold the session IDs upterm relays give and an embedded
// relay's ID and node, the node in URL-safe base64 with its '=' padding. None
// of them ends the line, quotes, or starts a comment or a token; configValue
// quotes the '='.
var sshUserRe = regexp.MustCompile(`^[A-Za-z0-9._~+=:-]+$`)

// proxyURLRe is what the URL in a Host block's ProxyCommand may be: no '%',
// which ssh would read as a token, and only characters that stay as they are
// inside double quotes, both in a POSIX shell and in the Windows argument
// parsing Windows OpenSSH starts a ProxyCommand with, where a single quote is
// any other character. That leaves out '$', '`', '\', '!', both quote marks
// and whitespace, among everything else.
var proxyURLRe = regexp.MustCompile(`^[A-Za-z0-9._~+=:@/\[\]-]+$`)

// errUnwritableUser, errUnwritableAlias and errUnwritableRelay are why
// sshConfigFor wrote no block. None repeats the value it refused.
var (
	errUnwritableUser  = errors.New("the relay gave the session an SSH user that upterm won't write into an ssh config")
	errUnwritableAlias = errors.New("the name the session would have in an ssh config isn't one upterm writes there")
	errUnwritableRelay = errors.New("the session's relay address has characters that upterm won't write into an ssh config")
)

// sshConfigFor is the Host block of ~/.ssh/config that reaches the session
// sess describes, as alias: the relay's host, the user the relay routes the
// session by (the ssh line's), the port when it isn't ssh's own, and for a ws
// or wss relay the ProxyCommand that carries ssh over it. ssh looks the relay
// up in known_hosts by that host and port, so they match the pin, which is
// keyed by the host and port the host dialled. No newline follows the last
// line.
//
// The user is the relay's, and so is the alias when a daemon that gives no
// name has its session named by its ID. A block is written only when
// sshUserRe takes the user and aliasRe the alias, so that neither can add
// lines of its own to the config it is pasted into, or make ssh refuse it,
// and for a ws or wss relay only when proxyURLRe takes the URL its
// ProxyCommand hands upterm proxy, so that the URL arrives as it is, on
// Windows as elsewhere.
func sshConfigFor(sess *api.GetSessionResponse, alias string) (string, error) {
	u, scheme, _, port, err := parseURL(sess.GetHost())
	if err != nil {
		return "", err
	}
	if scheme != "ssh" && scheme != "ws" && scheme != "wss" {
		return "", fmt.Errorf("the session's relay %s is not one ssh can reach", sess.GetHost())
	}
	if !aliasRe.MatchString(alias) {
		return "", errUnwritableAlias
	}
	user := sshUser(sess)
	if !sshUserRe.MatchString(user) {
		return "", errUnwritableUser
	}
	var target string
	if scheme != "ssh" {
		target = proxyURL(*u, user)
		if !proxyURLRe.MatchString(target) {
			return "", errUnwritableRelay
		}
	}
	lines := []string{
		"Host " + alias,
		// ssh expands percent tokens in HostName, so an address's zone keeps
		// its '%' only doubled.
		"  HostName " + strings.ReplaceAll(u.Hostname(), "%", "%%"),
		"  User " + configValue(user),
	}
	if port != "22" {
		lines = append(lines, "  Port "+port)
	}
	if scheme != "ssh" {
		// Double quotes, which quote on Windows too, where a single quote is
		// any other character. proxyURLRe left nothing in them to expand, a
		// '%' included, so none is doubled.
		lines = append(lines, `  ProxyCommand upterm proxy "`+target+`"`)
	}
	return strings.Join(lines, "\n"), nil
}

// configValue is v as an ssh_config value: in double quotes when it holds a
// space or an '=', which ssh_config's grammar reads as separators. The user an
// embedded relay routes by is base64, which '=' pads.
func configValue(v string) string {
	if strings.ContainsAny(v, "= \t") {
		return `"` + v + `"`
	}
	return v
}

// The comments that say how the host came to trust a relay key, for a key no
// line already in its known_hosts matched. Each ends where the key's
// fingerprint follows.
const (
	promptedPin = "# The host's known_hosts didn't have this key when it first connected; the\n" +
		"# host accepted it when upterm asked. Before you add it, compare its\n" +
		"# fingerprint with the one the relay's operator publishes:"
	autoAcceptedPin = "# The host's known_hosts didn't have this key when it first connected; the\n" +
		"# host accepted it without asking (--skip-host-key-check). Before you add it,\n" +
		"# compare its fingerprint with the one the relay's operator publishes:"
	// For a way to trust a key this version doesn't know, which it must not
	// read as known.
	unknownTrustPin = "# The host doesn't say how it came to trust this key. Before you add it,\n" +
		"# compare its fingerprint with the one the relay's operator publishes:"
)

// unreportedPin stands in for the pin of a session whose host doesn't say
// which relay key it trusted: one whose upterm is from before it said, or whose
// host key check upterm didn't build.
const unreportedPin = "# The upterm running this session doesn't say which relay key it trusted.\n" +
	"# Add the key the relay's operator publishes."

// relayPin is the known_hosts text for the relay key sess's host trusted: the
// line that trusts it, after a comment that says so when the host accepted it
// on first use, and so with nothing to check it against. False when the host
// doesn't say which key it trusted, or says it in anything but one
// known_hosts line.
func relayPin(sess *api.GetSessionResponse) (string, bool) {
	line := sess.GetRelayKnownHosts()
	if strings.ContainsAny(line, "\r\n") {
		return "", false
	}
	_, _, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil {
		return "", false
	}
	var caveat string
	switch sess.GetRelayKeyTrust() {
	case host.RelayKeyKnown:
		return line, true
	case host.RelayKeyPrompted:
		caveat = promptedPin
	case host.RelayKeyAutoAccepted:
		caveat = autoAcceptedPin
	default:
		caveat = unknownTrustPin
	}
	return caveat + "\n#   " + utils.FingerprintSHA256(key) + "\n" + line, true
}

// doorShaped reports whether sess is a door: a session guests reach with
// tools of their own, as well as by joining its terminal, which a login or
// forced command says, and so does anything granted them without asking.
func doorShaped(sess *api.GetSessionResponse) bool {
	switch {
	case len(sess.GetLoginCommand()) > 0, len(sess.GetForceCommand()) > 0:
	case sess.GetExecution() == "granted":
	case sess.GetTcpForwarding() == "loopback", sess.GetTcpForwarding() == "all":
	case sess.FileTransferApprovalRequired != nil && !sess.GetFileTransferApprovalRequired() &&
		sess.FileTransfer != nil && sess.GetFileTransfer() != "off":
	default:
		return false
	}
	return true
}
