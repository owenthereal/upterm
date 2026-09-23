package command

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/host/sftp"
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
func runDaemon(ctx context.Context, logger *slog.Logger, args []string, conn net.Conn, name string) error {
	opts, err := parseHostOptions(args)
	if err != nil {
		reportDaemonFailure(conn, err)
		return err
	}
	return runDaemonProcess(ctx, logger, opts, conn, name,
		func(ctx context.Context, h *host.Host) error { return h.Run(ctx) })
}

// reportDaemonFailure tells the parent why this daemon is not starting, for
// a failure that happens before runDaemonProcess has taken the connection
// over, and closes as soon as the message is on the wire.
//
// The Child is armed, as every Child is, but with no onParentGone to call:
// there is no session here to abandon, and the parent leaving first only
// means nobody is left to read the reason. Anyone who later passes a
// callback here should know that the arming is real and it is the nil
// callback that makes the departure a no-op.
func reportDaemonFailure(conn net.Conn, err error) {
	child := bootstrap.NewChild(conn, nil)
	defer func() { _ = child.Close() }()
	child.Failed(err.Error(), false, false)
}

// runDaemonProcess is upterm host's session logic run as the daemon, with
// the operator's terminal on the far end of conn rather than this process's
// own stdin and stdout.
//
// The context run is given is cancelled with ErrSessionAbandoned as its
// cause if the parent goes away before the command starts; Run reads the
// cause and records startup_abandoned. Once the command has started the
// parent's departure is expected and means nothing.
func runDaemonProcess(ctx context.Context, logger *slog.Logger, opts hostOptions, conn net.Conn, name string, run func(context.Context, *host.Host) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	child := bootstrap.NewChild(conn, func() { cancel(host.ErrSessionAbandoned) })
	defer func() { _ = child.Close() }()

	h, err := buildDaemonHost(ctx, name, opts, child, logger)
	if err != nil {
		child.Failed(err.Error(), false, false)
		return err
	}
	err = run(ctx, h)
	if err != nil {
		child.Failed(err.Error(), errors.Is(err, sessiondir.ErrNameInUse), errors.Is(err, host.ErrSessionAbandoned))
	}
	return err
}

// buildDaemonHost is the Host the foreground built, with every place it
// touched a terminal wired to the exchange instead.
func buildDaemonHost(ctx context.Context, name string, opts hostOptions, child *bootstrap.Child, logger *slog.Logger) (*host.Host, error) {
	if name == "" {
		return nil, errors.New("the daemon was started without a session name")
	}
	authorizedKeys, err := resolveAuthorizedKeys(ctx, opts, logger)
	if err != nil {
		return nil, err
	}

	signers, cleanup, err := host.SignersWith(host.SignerOptions{
		PrivateKeys: flagPrivateKeys,
		// Read here, not inherited: the daemon is a re-exec of this argv, so
		// it parses the same flags from the same origins and must read
		// --private-key the same way the foreground does.
		IdentitiesOnly: identitiesOnlyRequested(),
		Passphrase: func(file string) ([]byte, error) {
			return child.ReadSecret(fmt.Sprintf("Enter passphrase for key '%s': ", file))
		},
		OnSkip: func(file string, err error) {
			// Not silent, as it was: the session goes on with some other key,
			// and the operator should know which identity it is not using.
			logger.Warn("skipping private key", "file", file, "error", err)
			child.Print(fmt.Sprintf("warning: skipping private key %s: %v\n", file, err))
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

	var hkcb ssh.HostKeyCallback
	if flagSkipHostKeyCheck {
		hkcb, err = host.NewAutoAcceptingHostKeyCallback(child.Writer(), flagKnownHostsFilename)
	} else {
		hkcb, err = host.NewPromptingHostKeyCallback(child.Reader(), child.Writer(), flagKnownHostsFilename, connectionIsProxied(flagServer, opts.proxyURL))
	}
	if err != nil {
		return nil, err
	}

	var sftpPermissionChecker sftp.PermissionChecker = &DialogPermissionChecker{}
	if flagAccept {
		sftpPermissionChecker = &AutoAllowPermissionChecker{}
	}

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

	var sessionID string
	return &host.Host{
		Host:              flagServer,
		Name:              name,
		Command:           opts.command,
		JoinTimeout:       opts.joinTimeout,
		ForceCommand:      opts.forceCommand,
		Signers:           signers,
		HostKey:           hostKey,
		HostKeyCallback:   hkcb,
		AuthorizedKeys:    authorizedKeys,
		KeepAliveDuration: 50 * time.Second,
		ProxyURL:          opts.proxyURL,
		SessionClaimedCallback: func(dir *sessiondir.Dir) {
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
		// A foreground parent attaches before the command starts; a detached
		// one has nothing to attach.
		AwaitInitialClient: !flagDetach,
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
			_ = child.Started(sessionID, status)
		},
		VersionWarningCallback: func(r *version.CompatibilityResult) {
			host.DisplayVersionWarning(child.Writer(), logger, r)
		},
	}, nil
}
