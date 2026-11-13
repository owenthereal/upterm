package command

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/icon"
	"github.com/owenthereal/upterm/internal/termtext"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

// runDaemon is shareRunE when this process is the daemon: the argv it was
// re-executed with, parsed here, and then the session.
//
// The parse lives here rather than in the caller so that its failure is
// reported the way every later one is. A daemon that returned a parse error
// without saying anything left its parent watching the connection close,
// which the parent reports as the daemon having gone away -- true, and
// useless. It is unreachable in practice, since the parent parsed the same
// argv before it spawned anything, but the shape of a failure should not
// depend on that: the one message a daemon owes its parent is the reason.
//
// A delegated run, d, is hosted as its handoff says, and placed by the Broker
// ext's factory makes from it. A handoff that couldn't be read, and the
// factory's error, are told the parent as they are.
func runDaemon(ctx context.Context, logger *slog.Logger, ext *Extension, d *daemonHandoffState, args []string, conn net.Conn, name string) error {
	run := func(ctx context.Context, h *host.Host) error { return h.Run(ctx) }
	if d == nil {
		opts, err := parseHostOptions(args)
		if err != nil {
			reportDaemonFailure(conn, bootstrap.Failure{Text: failureText(err)})
			return err
		}
		return runDaemonProcess(ctx, logger, opts, conn, name, run)
	}
	if d.err != nil {
		reportDaemonFailure(conn, verbatimFailure(d.err))
		return d.err
	}
	opts, err := parseHostOptionsFor(args, true)
	if err != nil {
		reportDaemonFailure(conn, bootstrap.Failure{Text: failureText(err)})
		return err
	}
	// The parent refuses such a run before it starts this process; this is
	// for a handoff that reached a build with no Broker some other way.
	if ext == nil || ext.Broker == nil {
		reportDaemonFailure(conn, bootstrap.Failure{Text: failureText(errNoBroker)})
		return errNoBroker
	}
	newBroker := func(ctx context.Context) (host.Broker, error) { return ext.Broker(ctx, d.h) }
	return runDaemonWith(ctx, logger, d.h.Settings, newBroker, opts, conn, name, run)
}

// errNoBroker is a delegated run in a build whose extension has no Broker to
// place it.
var errNoBroker = errors.New("this upterm can't host a delegated run")

// verbatimFailure is err told the parent as it is, made safe for a terminal.
func verbatimFailure(err error) bootstrap.Failure {
	return bootstrap.Failure{Text: safeText(err.Error()), Verbatim: true}
}

// verbatimBroker is a Broker whose Place errors are told the parent as they
// are: a name taken where the run was placed as a *host.NameTakenError, and
// any other error as a verbatimError.
type verbatimBroker struct{ host.Broker }

func (b verbatimBroker) Place(ctx context.Context, run host.Run) (host.Placement, error) {
	p, err := b.Broker.Place(ctx, run)
	var taken *host.NameTakenError
	if err != nil && !errors.As(err, &taken) {
		err = verbatimError{text: err.Error()}
	}
	return p, err
}

// reportDaemonFailure tells the parent why this daemon is not starting, f,
// for a failure that happens before runDaemonProcess has taken the
// connection over, and closes as soon as the message is on the wire.
//
// The Child is armed, as every Child is, but with no onParentGone to call:
// there is no session here to abandon, and the parent leaving first only
// means nobody is left to read the reason. Anyone who later passes a
// callback here should know that the arming is real and it is the nil
// callback that makes the departure a no-op.
func reportDaemonFailure(conn net.Conn, f bootstrap.Failure) {
	child := bootstrap.NewChild(conn, nil)
	defer func() { _ = child.Close() }()
	child.Failed(f)
}

// failureText is err as the daemon tells its parent, which prints it on
// one line after "session NAME could not start:". The parent gets
// text, which Exit can't split, so each error a multierror collects is
// joined here as Exit would print it, never as its "N errors occurred" list.
func failureText(err error) string {
	return strings.Join(errorLines(err), "; ")
}

// verbatimError is a failure told in words chosen for the operator, which
// the parent prints as they are, line for line, once it has made them safe
// for a terminal. nameTaken says the name is taken where the run was placed,
// which a generated name is redrawn for.
type verbatimError struct {
	text      string
	nameTaken bool
}

func (e verbatimError) Error() string { return e.text }

func (e verbatimError) Unwrap() error {
	if e.nameTaken {
		return host.ErrNameTaken
	}
	return nil
}

// failureOf is why the daemon's session did not start, err, as its parent is
// told: a name taken where the run was placed, or a failure in the
// operator's own words, as text the parent prints as it is, made safe for a
// terminal here; anything else as failureText says it.
func failureOf(err error) bootstrap.Failure {
	f := bootstrap.Failure{
		Text:      failureText(err),
		NameInUse: errors.Is(err, sessiondir.ErrNameInUse),
		Abandoned: errors.Is(err, host.ErrSessionAbandoned),
	}
	var taken *host.NameTakenError
	if errors.As(err, &taken) {
		f.Text, f.Verbatim, f.NameTaken = safeText(taken.Text), true, true
	} else if verbatim := (verbatimError{}); errors.As(err, &verbatim) {
		f.Text, f.Verbatim, f.NameTaken = safeText(verbatim.text), true, verbatim.nameTaken
	}
	return f
}

// safeText is text with its lines kept and nothing in it that can control a
// terminal.
func safeText(text string) string { return string(termtext.Sanitize([]byte(text), false)) }

// runDaemonProcess is upterm host's session logic run as the daemon, with
// the operator's terminal on the far end of conn rather than this process's
// own stdin and stdout.
//
// The context run is given is cancelled with ErrSessionAbandoned as its
// cause if the parent goes away before the command starts; Run reads the
// cause and records startup_abandoned. Once the command has started the
// parent's departure is expected and means nothing.
func runDaemonProcess(ctx context.Context, logger *slog.Logger, opts hostOptions, conn net.Conn, name string, run func(context.Context, *host.Host) error) error {
	return runDaemonWith(ctx, logger, hostSettingsFromFlags(), nil, opts, conn, name, run)
}

// runDaemonWith is runDaemonProcess for a host built from s, and placed by
// the Broker newBroker makes when newBroker isn't nil. newBroker is called
// once the parent's departure is watched for, with a context that ends with
// it, and its error is told the parent as it is.
func runDaemonWith(ctx context.Context, logger *slog.Logger, s HostSettings, newBroker func(context.Context) (host.Broker, error), opts hostOptions, conn net.Conn, name string, run func(context.Context, *host.Host) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	child := bootstrap.NewChild(conn, func() { cancel(host.ErrSessionAbandoned) })
	defer func() { _ = child.Close() }()

	var broker host.Broker
	if newBroker != nil {
		b, err := newBroker(ctx)
		if err != nil {
			child.Failed(verbatimFailure(err))
			return err
		}
		broker = verbatimBroker{b}
	}
	h, err := buildDaemonHost(ctx, s, name, opts, child, logger)
	if err != nil {
		child.Failed(bootstrap.Failure{Text: failureText(err)})
		return err
	}
	h.Broker = broker
	err = run(ctx, h)
	if err != nil {
		f := failureOf(err)
		// A broker's error, and anything else a delegated run fails with, may
		// carry its words: the terminal is given them made safe, as a
		// verbatim failure's are. Only a verbatim failure keeps its lines:
		// any other is printed inside a line of upterm's own, where a line of
		// its own could pass for one of upterm's.
		if h.Broker != nil {
			f.Text = safeText(f.Text)
			if !f.Verbatim {
				f.Text = strings.ReplaceAll(f.Text, "\n", "�")
			}
		}
		child.Failed(f)
	}
	return err
}

// hostSettingsFromFlags is what this run's flags say the host is built from.
func hostSettingsFromFlags() HostSettings {
	return HostSettings{
		Server:                  flagServer,
		KnownHosts:              flagKnownHostsFilename,
		Proxy:                   flagProxy,
		PrivateKeys:             flagPrivateKeys,
		IdentitiesOnly:          identitiesOnlyRequested(),
		SkipHostKeyCheck:        flagSkipHostKeyCheck,
		ForceCommand:            flagForceCommand,
		LoginCommand:            flagLoginCommand,
		Accept:                  flagAccept,
		AllowExec:               flagAllowExec,
		NoExec:                  flagNoExec,
		HideClientIP:            shouldHideClientIP(),
		ReadOnly:                flagReadOnly,
		AllowSFTP:               flagAllowSFTP,
		NoSFTP:                  flagNoSFTP,
		NoForwarding:            flagNoForwarding,
		AllowForwarding:         string(flagAllowForwarding),
		AllowLocalTCPForwarding: flagAllowLocalTCPForwarding,
		FullAccess:              flagFullAccess,
		Detach:                  flagDetach,
		PtySize:                 flagPtySize,
		Term:                    flagTerm,
		EscapeChar:              flagHostEscapeChar,
		JoinTimeout:             flagJoinTimeout,
		AuthorizedKeys:          flagAuthorizedKeys,
	}
}

// buildDaemonHost is the Host the foreground built, from s, with every place
// it touched a terminal wired to the exchange instead. A delegated run's
// placement says which relay it registers with and which keys it trusts
// there, and its authority decides its guests: it resolves no keys, and has
// no host key callback.
func buildDaemonHost(ctx context.Context, s HostSettings, name string, opts hostOptions, child *bootstrap.Child, logger *slog.Logger) (*host.Host, error) {
	if name == "" {
		return nil, errors.New("the daemon was started without a session name")
	}
	var authorizedKeys []*host.AuthorizedKey
	if !opts.delegated {
		var err error
		if authorizedKeys, err = resolveAuthorizedKeysFrom(ctx, s.AuthorizedKeys, opts.authorizationRequested, opts, logger); err != nil {
			return nil, err
		}
	}

	signers, cleanup, err := host.SignersWith(host.SignerOptions{
		PrivateKeys: s.PrivateKeys,
		// Read here, not inherited: the daemon is a re-exec of this argv, so
		// it parses the same flags from the same origins and must read
		// --private-key the same way the foreground does.
		IdentitiesOnly: s.IdentitiesOnly,
		Passphrase: func(file string) ([]byte, error) {
			return child.ReadSecret(fmt.Sprintf("Enter passphrase for key '%s': ", file))
		},
		OnSkip: func(file string, err error) {
			// Not silent, as it was: the session goes on with some other key,
			// and the operator should know which identity it is not using.
			logger.Warn("skipping private key", "file", file, "error", err)
			child.Print(fmt.Sprintf("upterm: warning: skipping private key %s: %v\n", file, err))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error reading private keys: %w", err)
	}
	// Never called: the ssh-agent connection this holds open is meant to
	// outlive buildDaemonHost, for as long as the signers it returned are in
	// use, which is until this process exits — the same point runDaemonProcess's
	// run(ctx, h) returns. The foreground expresses that identical lifetime as
	// a defer cleanup() in shareRunE, one frame up from where it's opened;
	// here the daemon's whole life is this one function call, so there is no
	// frame above it to defer into.
	_ = cleanup

	// A check that remembers how it trusted the relay's key, so the session
	// can tell guests which key to pin, and whether a line already in the
	// known_hosts file matched it.
	var (
		hostKeyCallback ssh.HostKeyCallback
		relayKeyTrusted func() (host.TrustedRelayKey, bool)
	)
	if !opts.delegated {
		var relayKey *host.RelayKeyCheck
		if s.SkipHostKeyCheck {
			relayKey, err = host.NewAutoAcceptingRelayKeyCheck(child.Writer(), s.KnownHosts)
		} else {
			relayKey, err = host.NewPromptingRelayKeyCheck(child.Reader(), child.Writer(), s.KnownHosts, connectionIsProxied(s.Server, opts.proxyURL))
		}
		if err != nil {
			return nil, err
		}
		hostKeyCallback, relayKeyTrusted = relayKey.HostKeyCallback, relayKey.Trusted
	}

	// --full-access is --allow-exec, --allow-sftp and
	// --allow-forwarding=loopback. --accept grants file transfers too, as
	// well as a start nobody is asked about.
	allowExec := s.AllowExec || s.FullAccess
	allowSFTP := s.AllowSFTP || s.FullAccess || s.Accept
	allowLoopback := forwardingGrant(s.AllowForwarding) == forwardLoopback || s.FullAccess

	// Generated here rather than left to Run: the parent pins the door's keys
	// from what Listening reports, and it must be this run's session host
	// key — what the embedded sshd actually presents — not the
	// --private-key signers, which authenticate the tunnel and nothing else.
	hostKey, err := host.NewHostKey()
	if err != nil {
		return nil, fmt.Errorf("error generating host key: %w", err)
	}
	// One key, but the wire field stays plural: it is `repeated string
	// host_keys` in startup.proto, and an older parent reads the list.
	hostKeys := []string{strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(hostKey.PublicKey())), "\n")}

	// The daemon is the one that knows what became of the session, so it is
	// the one that tells the operator, by the session's name.
	guests := guestNotifier{name: name, hide: s.HideClientIP}
	// The session's directory, once claimed: what its authority decided is
	// told as its record names the authority.
	var claimedDir atomic.Pointer[sessiondir.Dir]
	delegation := func() *sessiondir.Delegation {
		if dir := claimedDir.Load(); dir != nil {
			return dir.Record().Delegation
		}
		return nil
	}

	var sessionID string
	// A variable rather than a bare return, so the ready callback can ask the
	// Host it belongs to for its join state.
	var h *host.Host
	h = &host.Host{
		Host:              s.Server,
		Name:              name,
		NameGenerated:     opts.nameGenerated,
		Command:           opts.command,
		JoinTimeout:       opts.joinTimeout,
		ForceCommand:      opts.forceCommand,
		LoginCommand:      opts.loginCommand,
		CommandDir:        opts.commandDir,
		AcceptExec:        allowExec,
		ExecDisabled:      s.NoExec,
		HideClientIP:      s.HideClientIP,
		LogPath:           utils.UptermLogFilePath(),
		Signers:           signers,
		IdentitiesOnly:    s.IdentitiesOnly,
		HostKey:           hostKey,
		HostKeyCallback:   hostKeyCallback,
		RelayKeyTrusted:   relayKeyTrusted,
		AuthorizedKeys:    authorizedKeys,
		AutoAccept:        s.Accept,
		SFTPAutoAccept:    allowSFTP,
		KeepAliveDuration: 50 * time.Second,
		ProxyURL:          opts.proxyURL,
		SessionClaimedCallback: func(dir *sessiondir.Dir) {
			claimedDir.Store(dir)
			logPath := utils.UptermLogFilePath()
			if err := dir.Update(func(r *sessiondir.Record) { r.LogPath = logPath }); err != nil {
				logger.Warn("failed to publish the log path", "error", err)
			}
			rec := dir.Record()
			_ = child.Claimed(&api.Claimed{
				Name: dir.Name(), LaunchId: dir.LaunchID(),
				AdminSocket: dir.AdminSocket(), AttachSocket: dir.AttachSocket(),
				LogPath: logPath, Pid: int32(rec.Pid),
			})
		},
		SessionCreatedCallback: func(ctx context.Context, s *api.GetSessionResponse) error {
			sessionID = s.SessionId
			dec, err := child.SessionCreated(s)
			if err != nil {
				return fmt.Errorf("%w: %v", host.ErrSessionAbandoned, err)
			}
			switch dec {
			case api.Accept_DECLINED:
				return UserDiscardedError{}
			case api.Accept_INTERRUPTED:
				return UserInterruptedError{}
			}
			return nil
		},
		ClientJoinedCallback:       guests.joined,
		ClientLeftCallback:         guests.left,
		TunnelCallback:             tunnelNotifier(name),
		DecisionCallback:           decisionNotifier(name, delegation, logger),
		Logger:                     logger,
		ReadOnly:                   s.ReadOnly,
		AllowLocalTCPForwarding:    forwardingGrant(s.AllowForwarding) == forwardAny || s.AllowLocalTCPForwarding,
		AllowLoopbackTCPForwarding: allowLoopback,
		ForwardingDisabled:         s.NoForwarding,
		PtySize:                    opts.ptySize,
		PinPtySize:                 s.PtySize != "",
		Term:                       opts.term,
		SFTPDisabled:               s.NoSFTP,
		TerminalConsent:            true,
		// Set alongside terminal consent, so that what readers are told is
		// what a guest's transfer will do.
		FileTransferApprovalRequired: !allowSFTP,
		// A foreground parent attaches before the command starts; a detached
		// one has nothing to attach.
		AwaitInitialClient: !s.Detach,
		AttachListeningCallback: func(socket string) {
			_ = child.Listening(socket, hostKeys)
		},
		// Not CommandStartedCallback, which fires one record write earlier:
		// the parent exits the instant it reads started and prints the
		// status this carries, so a script that then asks `upterm session
		// info` must not be answered something else by the record. The
		// record has been written by the time this is called, and the
		// status is what it says — usually ready, and reported as whatever
		// it is rather than assumed.
		SessionReadyCallback: func(status string) {
			// Disarm before saying so: a parent that exits the instant it
			// reads started must not be read as leaving.
			child.Disarm()
			// The join state too, taken after any timeout has started
			// counting, so the parent prints what `session info` would rather
			// than inferring it from the flag.
			_ = child.Started(sessionID, status, h.JoinState())
		},
		// Both are said on the operator's terminal before the banner: Run
		// makes these calls before SessionCreatedCallback, and the parent
		// prints in the order it is told.
		VersionWarningCallback: func(r *version.CompatibilityResult) {
			// Only a relay ahead of this upterm calls for an upgrade here,
			// and only then is it worth asking who installed upterm: bounded,
			// since the banner waits on it.
			var advice string
			if r.Direction == version.RelayNewer {
				advice = upgradeAdviceWithin(logger)
			}
			child.Print(versionWarning(r, advice) + "\n")
		},
		RelayWarningCallback: func(w host.RelayWarning) {
			if line := relayWarningLine(w); line != "" {
				child.Print(line + "\n")
			}
		},
	}
	return h, nil
}

// decisionNotice is the desktop notification for the authority of the
// delegated session name, whose record holds d, stopping or withdrawing it:
// the notice's first sentence as its title, and the rest as its body. The
// sentence ends at the first ". " after the authority's name, which may hold
// full stops of its own.
func decisionNotice(d *sessiondir.Delegation, name string, dec host.Decision) notification {
	firstSentence := func(text string) (title, body string) {
		authority := tui.AuthorityAtStart(d)
		title, body, _ = strings.Cut(strings.TrimPrefix(text, authority), ". ")
		return authority + title, body
	}
	if dec == host.DecisionStopped {
		title, body := firstSentence(tui.StoppedNotice(d))
		return notification{title, body}
	}
	lines := tui.WithdrawnNotice(d, name)
	title, body := firstSentence(lines[0])
	return notification{title, body + "\n" + lines[1]}
}

// decisionNotifier says what the authority decided about the delegated
// session name where its daemon can: in its log, and as a desktop
// notification, on a goroutine of its own, since a desktop may take as long
// as it likes, or forever where there is none. The daemon has no terminal of
// its own; a terminal attached to the session is told as it lets go (see
// delegatedEndLines). delegation reads the session's from its record.
func decisionNotifier(name string, delegation func() *sessiondir.Delegation, logger *slog.Logger) func(host.Decision) {
	return func(dec host.Decision) {
		n := decisionNotice(delegation(), name, dec)
		logger.Warn(n.Title + ". " + n.Body)
		go func() { _ = notify(n.Title, n.Body, icon.Upterm) }()
	}
}

// versionWarning is what upterm host says when the relay's version doesn't
// match its own: which side is ahead, and so who can fix it. advice is how
// to upgrade this upterm, from upgradeAdvice, and is said only when this
// upterm is the one behind.
func versionWarning(r *version.CompatibilityResult, advice string) string {
	switch r.Direction {
	case version.RelayNewer:
		return fmt.Sprintf("upterm: warning: the relay runs uptermd %s and this is upterm %s; %s", r.ServerVersion, r.HostVersion, advice)
	case version.RelayOlder:
		return fmt.Sprintf("upterm: warning: the relay runs uptermd %s, older than this upterm (%s); its operator can upgrade it", r.ServerVersion, r.HostVersion)
	default:
		return "upterm: warning: the relay didn't report a version upterm understands; this is upterm " + r.HostVersion
	}
}

// relayWarningLine is what upterm host says, before the session starts,
// about what its first connection showed of the relay; "" for a kind it has
// no line for.
func relayWarningLine(w host.RelayWarning) string {
	switch w.Kind {
	case host.NoReconnect:
		return "upterm: warning: this relay doesn't support reconnecting; if the connection drops, guests can't reach this session until you restart it"
	case host.CertNotValidForServer:
		return fmt.Sprintf("upterm: warning: the relay's certificate isn't valid for %s, so a reconnect would be refused; use the relay's own hostname in --server", w.Host)
	}
	return ""
}
