package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func NewPromptingHostKeyCallback(stdin io.Reader, stdout io.Writer, knownHostsFilename string) (ssh.HostKeyCallback, error) {
	return newHostKeyCallback(stdin, stdout, knownHostsFilename, false)
}

// NewAutoAcceptingHostKeyCallback creates a host key callback that automatically
// accepts unknown host keys and adds them to the known_hosts file without prompting.
// This is similar to SSH's StrictHostKeyChecking=accept-new behavior:
// - Unknown host keys are automatically accepted and added to known_hosts
// - Known host keys are still validated (preventing MITM attacks on subsequent connections)
func NewAutoAcceptingHostKeyCallback(stdout io.Writer, knownHostsFilename string) (ssh.HostKeyCallback, error) {
	return newHostKeyCallback(nil, stdout, knownHostsFilename, true)
}

func newHostKeyCallback(stdin io.Reader, stdout io.Writer, knownHostsFilename string, autoAccept bool) (ssh.HostKeyCallback, error) {
	if err := createFileIfNotExist(knownHostsFilename); err != nil {
		return nil, err
	}

	cb, err := knownhosts.New(knownHostsFilename)
	if err != nil {
		return nil, err
	}

	hkcb := hostKeyCallback{
		stdin:           stdin,
		stdout:          stdout,
		file:            knownHostsFilename,
		HostKeyCallback: cb,
		autoAccept:      autoAccept,
	}

	return hkcb.checkHostKey, nil
}

const (
	markerCert = "@cert-authority"

	errKeyMismatch = `
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %s key sent by the remote host is
%s.
Please contact your system administrator.
Add correct host key in %s to get rid of this message.
Offending %s key in %s:%d`
	errNoAuthoritiesHostname = "ssh: no authorities for hostname"
)

type hostKeyCallback struct {
	stdin      io.Reader
	stdout     io.Writer
	file       string
	autoAccept bool
	ssh.HostKeyCallback
}

func (cb hostKeyCallback) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := cb.HostKeyCallback(hostname, remote, key); err != nil {
		kerr, ok := err.(*knownhosts.KeyError)
		// Return err if it's neither key error or no authorities hostname error
		if !ok && !strings.HasPrefix(err.Error(), errNoAuthoritiesHostname) {
			return err
		}

		// If keer.Want is non-empty, there was a mismatch, which can signify a MITM attack
		if kerr != nil && len(kerr.Want) != 0 {
			kk := kerr.Want[0] // TODO: take care of multiple key mismatches
			fp := utils.FingerprintSHA256(kk.Key)
			kt := keyType(kk.Key.Type())
			return fmt.Errorf(errKeyMismatch, kt, fp, kk.Filename, kt, kk.Filename, kk.Line)
		}

		// Auto-accept unknown host keys if enabled
		if cb.autoAccept {
			return cb.autoAcceptHostKey(hostname, key)
		}

		return cb.promptForConfirmation(hostname, remote, key)
	}

	return nil
}

func (cb hostKeyCallback) promptForConfirmation(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		key = cert.SignatureKey
	}

	fp := utils.FingerprintSHA256(key)
	_, _ = fmt.Fprintf(cb.stdout, "The authenticity of host '%s (%s)' can't be established.\n", knownhosts.Normalize(hostname), knownhosts.Normalize(remote.String()))
	_, _ = fmt.Fprintf(cb.stdout, "%s key fingerprint is %s.\n", keyType(key.Type()), fp)
	_, _ = fmt.Fprintf(cb.stdout, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	reader := bufio.NewReader(cb.stdin)
	for {
		confirm, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("could not read host-key confirmation from stdin: %w; "+
				"to confirm the %s host key of %s, re-run interactively, "+
				"pre-populate %s with a verified host key, or use --skip-host-key-check to automatically accept new host keys",
				err, keyType(key.Type()), hostname, cb.file)
		}

		confirm = strings.TrimSpace(confirm)

		if confirm == "yes" || confirm == fp {
			return cb.appendHostLine(isCert, hostname, key)
		}

		if confirm == "no" {
			return fmt.Errorf("Host key verification failed")
		}

		_, _ = fmt.Fprintf(cb.stdout, "Please type 'yes', 'no' or the fingerprint: ")
	}
}

func (cb hostKeyCallback) autoAcceptHostKey(hostname string, key ssh.PublicKey) error {
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		key = cert.SignatureKey
	}

	_, _ = fmt.Fprintf(cb.stdout, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", knownhosts.Normalize(hostname), keyType(key.Type()))

	return cb.appendHostLine(isCert, hostname, key)
}

func (cb hostKeyCallback) appendHostLine(isCert bool, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(cb.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	// Only store the hostname, not the IP address.
	// This prevents breakage when server IPs change due to:
	// - Load balancers and auto-scaling
	// - Cloud redeployments
	// - CDN/proxy rotation
	// - IPv6 address rotation
	// The security benefit of storing IPs is minimal in modern infrastructure
	// since we already trust DNS, and MITM attacks would need to compromise
	// both DNS and the host key.
	addr := []string{hostname}

	line := knownhosts.Line(addr, key)

	if isCert {
		line = fmt.Sprintf("%s %s", markerCert, line)
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}

	return nil
}

type Host struct {
	Host                    string
	KeepAliveDuration       time.Duration
	Command                 []string
	ForceCommand            []string
	Signers                 []ssh.Signer
	HostKeyCallback         ssh.HostKeyCallback
	AuthorizedKeys          []*AuthorizedKey
	AdminSocketFile         string
	SessionCreatedCallback  func(context.Context, *api.GetSessionResponse) error
	ClientJoinedCallback    func(*api.Client)
	ClientLeftCallback      func(*api.Client)
	Logger                  *slog.Logger
	ReadOnly                bool
	AllowLocalTCPForwarding bool
	// ProxyURL, when non-nil, routes the connection to the upterm server
	// through an HTTP proxy.
	ProxyURL   *url.URL
	PtySize    termsize.Size
	PinPtySize bool
	Term       string

	// AttachSocketFile is where the local attach door is bound. Like
	// AdminSocketFile, supplying it means the caller manages the path and
	// no name is claimed; left empty with AdminSocketFile set, no attach
	// door is served, which is how an embedder that will never attach a
	// terminal says so. Claimed with the name otherwise.
	AttachSocketFile string
	// AttachListeningCallback is called once the attach socket is bound,
	// before the command starts, with the path a client should dial. With
	// AwaitInitialClient set, this is the moment to attach.
	//
	// Called on Run's own goroutine, before the run.Group exists, so it must
	// not block: everything after it — the command, the guest door, the
	// readiness record — waits behind it.
	AttachListeningCallback func(attachSocket string)
	// CommandStartedCallback is called once the hosted command is running,
	// which with AwaitInitialClient is also the news that a client got
	// through the door. A caller whose own attach failed asks this whether
	// there is a session to leave alone.
	//
	// Called on the server's own goroutine, in front of everything the
	// command's start releases, so it must not block.
	CommandStartedCallback func()
	// VersionWarningCallback is called when the server's version is
	// incompatible with this host's. Nil logs the mismatch and nothing more:
	// the daemon has no terminal to print to.
	VersionWarningCallback func(*version.CompatibilityResult)

	// AwaitInitialClient defers starting the command until the first host
	// client's output subscription is installed, and defers serving guests
	// until the command has started. Foreground use sets it: a command that
	// exits at once — `upterm host -- false` — would otherwise race the local
	// terminal's attach, and lose. Headless use leaves it off.
	AwaitInitialClient bool
	// InitialClientTimeout bounds that wait; zero means
	// internal.DefaultInitialClientTimeout.
	InitialClientTimeout time.Duration

	// SFTP configuration
	SFTPDisabled          bool                   // Disable SFTP subsystem entirely (--no-sftp)
	SFTPPermissionChecker sftp.PermissionChecker // Optional: prompts user for SFTP permissions (nil = auto-allow)

	// Name is the session's local name. It determines the socket paths, so
	// they are known before the server is ever contacted. It is unrelated to
	// the server-assigned session ID in the connect string.
	//
	// Ignored when AdminSocketFile is set: supplying a socket is how a caller
	// says it is managing the paths itself, so Run claims no name and there is
	// nothing for this to name. SessionDir stays nil in that case, and no
	// record is published.
	Name string

	// SessionDir is claimed by Run and readable for as long as Run is
	// running. Run clears it on the way out: the directory is released by
	// then, a released Dir may not be touched again, and leaving it here
	// would be leaving a handle to a name that now belongs to whoever claimed
	// it next. Nil when AdminSocketFile was supplied, which is how tests
	// drive Host without taking a name.
	SessionDir *sessiondir.Dir
}

// ErrSessionAbandoned marks a session given up before its command started, as
// opposed to one that failed to start. A SessionCreatedCallback error that
// wraps it is recorded as startup_abandoned rather than startup_failed.
//
// Declining the interactive confirmation is the case it exists for: the
// operator was shown the session and said no, nothing went wrong, and a
// record saying otherwise sends whoever reads it looking for a fault that
// never happened.
var ErrSessionAbandoned = errors.New("session abandoned before the command started")

// ErrNoInitialClient is what a host told to await its initial client returns
// when nobody attached in time. Nothing ran, so it is recorded as
// startup_abandoned rather than a failure.
var ErrNoInitialClient = internal.ErrNoInitialClient

// ClaimTimeout bounds how long Run waits for the session registry when it
// takes a name.
//
// Claim waits on two lock files, either of which can be held by a process that
// is stopped rather than slow — a wait no amount of patience resolves. The
// caller's context is not a bound in practice: the CLI runs Run on
// context.Background(), so without this a stuck registry hangs `upterm host`
// at startup forever while every read path already gives up after
// sessionQueryTimeout. Ten seconds matches those read paths, since they wait
// on the same locks.
//
// A var, not a const, so an embedder on a slower filesystem and a test that
// wants to observe the timeout can both move it.
var ClaimTimeout = 10 * time.Second

// Run hosts one session and returns when it ends.
//
// It may be called again afterwards: everything Run claims, it gives back
// before returning, including the two fields it fills in on the Host itself.
// A caller that supplied AdminSocketFile keeps it across runs, since managing
// the path is what supplying it means.
func (c *Host) Run(ctx context.Context) error {
	// First, before anything here can write a byte. Whatever a
	// SessionCreatedCallback prints, and whatever a VersionWarningCallback
	// prints, goes out well before the signal actor is assembled, and for an
	// embedder whose reader has gone away a single one of those writes is
	// fatal. See InstallSignalPolicy; calling it again from setupSignalHandler
	// is free.
	InstallSignalPolicy()

	u, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("error parsing host url: %s", err)
	}

	var aks []ssh.PublicKey
	for _, ak := range c.AuthorizedKeys {
		aks = append(aks, ak.PublicKeys...)
	}

	// Whether this run took the name, as opposed to being handed a socket to
	// use. Only the run that claimed it may give it back.
	var claimedDir bool

	if c.AdminSocketFile == "" {
		runtimeDir, err := utils.CreateUptermRuntimeDir()
		if err != nil {
			return err
		}

		// Bounded by ClaimTimeout rather than by ctx, which for the CLI never
		// ends. Cancelled as soon as Claim returns: the claim it produces
		// outlives this call and must not be tied to a context that is about
		// to expire.
		claimCtx, cancelClaim := context.WithTimeout(ctx, ClaimTimeout)
		dir, err := sessiondir.Claim(claimCtx, sessiondir.ClaimOptions{
			RuntimeRoot:  runtimeDir,
			StateRoot:    utils.UptermStateDir(),
			Name:         c.Name,
			Command:      c.Command,
			ForceCommand: c.ForceCommand,
		})
		cancelClaim()
		if err != nil {
			return err
		}
		c.SessionDir = dir
		c.AdminSocketFile = dir.AdminSocket()
		c.AttachSocketFile = dir.AttachSocket()
		claimedDir = true
	}

	var (
		sessionID   string
		runReason   = sessiondir.ReasonStartupFailed
		runExitCode *int
		runSignal   string
	)

	// shutdownRequested records that *we* initiated the teardown — a signal or
	// a cancelled context — as distinct from the wait status that results.
	//
	// This distinction is load-bearing. Cancelling a running command makes our
	// own teardown kill it, so the wait reports a signal on Unix and an
	// ordinary non-zero exit on Windows. Classifying off the wait status alone
	// would report "signaled" or "exited 137" for something the operator asked
	// for, on a platform-dependent basis.
	var shutdownRequested atomic.Bool

	if c.SessionDir != nil {
		dir := c.SessionDir
		// c.Logger, not the enriched logger built below: this is registered
		// before that one exists, deliberately, so that it also covers the
		// early returns between here and there.
		logger := c.Logger
		// Registered here so it runs however Run exits, including the early
		// returns below. It closes over the variables rather than their values,
		// which is why they are declared above rather than beside it.
		defer func() {
			releaseCtx, cancelRelease := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancelRelease()

			// Neither failure can be returned — Run's error belongs to the
			// session, not to its bookkeeping — and neither may be silent.
			// A record that was not published means `session info` reports the
			// wrong outcome for this run, and a directory that was not released
			// means the name stays taken until something reaps it. Both are
			// invisible from outside the process without a line here.
			//
			// A cancellation before the command starts is still a stop. The
			// signal actor that sets shutdownRequested is registered only
			// after SessionCreatedCallback returns, so a caller that cancels
			// during Establish, or while the callback is waiting, gets
			// ctx.Err() back through returns that report startup_failed --
			// for a session that was told to stop. Decided here, on the
			// publish itself, so that every early return is covered.
			// startup_abandoned still wins: an interactive decline whose
			// embedder also cancels is still a decline. The one corner this
			// accepts is a genuine startup failure that coincides with a
			// cancellation, reported as stopped, which is what the caller
			// asked for.
			if runReason == sessiondir.ReasonStartupFailed && ctx.Err() != nil {
				runReason = sessiondir.ReasonStopped
			}
			if err := dir.Update(func(r *sessiondir.Record) {
				r.SessionID = sessionID
				r.FinishedAt = time.Now().UTC()
				advanceStatus(r, sessiondir.StatusEnding)
				r.Reason = runReason
				r.ExitCode = runExitCode
				r.Signal = runSignal
			}); err != nil {
				logger.Warn("failed to publish final session record", "error", err)
			}
			if err := dir.Release(releaseCtx); err != nil {
				logger.Warn("failed to release session directory", "error", err)
			}

			// Run's own bookkeeping, undone. Left in place, a second Run on
			// this Host would skip the claim above and spend the whole session
			// updating and finally releasing a Dir that is already released —
			// and the name is free the instant Release returns, so those
			// writes would land on a successor's record and that release would
			// delete a live successor's runtime directory. The socket path is
			// only cleared if this run was the one that derived it; a caller
			// that supplied its own keeps it.
			c.SessionDir = nil
			if claimedDir {
				c.AdminSocketFile = ""
				c.AttachSocketFile = ""
			}
		}()
	}

	logger := c.Logger.With("server", u.String())
	logger.Info("Establishing reverse tunnel")
	rt := internal.ReverseTunnel{
		Host:              u,
		Signers:           c.Signers,
		HostKeyCallback:   c.HostKeyCallback,
		AuthorizedKeys:    aks,
		KeepAliveDuration: c.KeepAliveDuration,
		ProxyURL:          c.ProxyURL,
		Logger:            logger.With("component", "reverse-tunnel"),
	}
	// Deferred before Establish, not after: Close is nil-safe on a partially
	// established tunnel, and a dial that succeeds but then fails inside
	// Establish -- at createSession or Listen -- must still close the SSH
	// client rather than leak it.
	defer rt.Close()
	sessResp, err := rt.Establish(ctx)
	if err != nil {
		// Log the error before returning to ensure it's captured in logs
		// This is especially important when running in detached/background mode
		logger.Error("Failed to establish reverse tunnel", "error", err)
		return err
	}

	// Check server version compatibility after establishing connection
	serverVersion := string(rt.ServerVersion())
	logger.Debug("detected server version", "server_version", serverVersion)

	// Check for version compatibility. The log is where it always goes: a
	// daemon has no terminal of its own, and whoever does — the CLI — says so
	// with a callback.
	if result := version.CheckCompatibility(serverVersion); !result.Compatible {
		logger.Warn("server version mismatch", "message", result.Message,
			"host_version", result.HostVersion, "server_version", result.ServerVersion)
		if c.VersionWarningCallback != nil {
			c.VersionWarningCallback(result)
		}
	}

	logger = logger.With("session", sessResp.SessionID)
	logger.Info("Established reverse tunnel")

	// The ID, but not readiness: the session is registered and nothing more.
	// Nothing has accepted it, the admin socket is unbound and the command
	// does not exist yet.
	sessionID = sessResp.SessionID

	session := &api.GetSessionResponse{
		SessionId:      sessResp.SessionID,
		Host:           u.String(),
		NodeAddr:       sessResp.NodeAddr,
		SshUser:        sessResp.SshUser,
		Command:        c.Command,
		ForceCommand:   c.ForceCommand,
		AuthorizedKeys: toApiAuthorizedKeys(c.AuthorizedKeys),
		SftpDisabled:   c.SFTPDisabled,
	}

	if c.SessionCreatedCallback != nil {
		if err := c.SessionCreatedCallback(ctx, session); err != nil {
			// runReason is startup_failed at this point, which is right for a
			// callback that broke and wrong for one that declined on the
			// operator's behalf. Nothing failed in that case, and the record
			// is all a later reader has to tell the two apart by.
			if errors.Is(err, ErrSessionAbandoned) {
				runReason = sessiondir.ReasonStartupAbandoned
			}
			return err
		}
	}

	clientRepo := internal.NewClientRepo()
	eventEmitter := emitter.New(1)

	logger = logger.With("cmd", c.Command, "force_cmd", c.ForceCommand)

	// Readiness is a claim about facts, so it waits for the facts to report
	// themselves: the admin socket bound and the command started. Registering
	// the actors that do those things establishes neither.
	adminReady := make(chan struct{})
	cmdReady := make(chan struct{})
	// sync.Once on each, since a callback that fires twice must not panic on a
	// double close.
	var adminOnce, cmdOnce sync.Once

	// Bound here, not inside the group. A bind failure is a startup failure and
	// has to be reported as one: inside the group it raced the command's start,
	// and whichever actor lost the race decided the classification — the same
	// unusable socket path was published as startup_failed on one run and
	// signaled on the next. Returning the error here also hands the deferred
	// writer above the reason it already assumes at this point.
	//
	// adminReady therefore closes before the group exists. The ready actor
	// still waits on both channels: which of the two facts is established
	// first is not something readiness should depend on.
	adminServer := internal.AdminServer{
		Session:     session,
		ClientRepo:  clientRepo,
		OnListening: func() { adminOnce.Do(func() { close(adminReady) }) },
	}
	if err := adminServer.Listen(c.AdminSocketFile); err != nil {
		logger.Error("Failed to bind the admin socket", "socket", c.AdminSocketFile, "error", err)
		return err
	}

	// The local terminal's door, bound the way the admin socket is: no chmod,
	// because the 0700 session directory is the boundary. Here rather than
	// inside the group for the same reason the admin bind is — a bind failure
	// is a startup failure and must be reported as one, not raced against the
	// command's start.
	var attachLn net.Listener
	if c.AttachSocketFile != "" {
		attachLn, err = net.Listen("unix", c.AttachSocketFile)
		if err != nil {
			logger.Error("Failed to bind the attach socket", "socket", c.AttachSocketFile, "error", err)
			_ = adminServer.Shutdown(ctx)
			return err
		}
		// Published as soon as the socket a client could dial exists, so that
		// every record whose attach socket is dialable also carries the keys
		// `upterm attach` needs to pin it. Guarded on len(c.Signers): tests
		// construct hosts without any, and the field is left empty rather
		// than published as nothing.
		if c.SessionDir != nil && len(c.Signers) > 0 {
			hostKeys := make([]string, 0, len(c.Signers))
			for _, s := range c.Signers {
				hostKeys = append(hostKeys, strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(s.PublicKey())), "\n"))
			}
			// Not swallowed: a record that never receives the keys names a
			// socket `upterm attach` will refuse to dial, so a session that
			// is otherwise fine becomes unattachable for its whole life.
			// Not fatal either — the session itself is unaffected, and the
			// guests it exists for are served over the tunnel — so it is
			// said once, here, rather than ending a working session.
			if err := c.SessionDir.Update(func(r *sessiondir.Record) {
				r.HostKeys = hostKeys
			}); err != nil {
				logger.Error("Failed to publish the host keys; upterm attach will refuse this session",
					"record", c.SessionDir.RecordPath(), "error", err)
			}
		}
		if c.AttachListeningCallback != nil {
			c.AttachListeningCallback(c.AttachSocketFile)
		}
	}

	var g run.Group
	{
		// Handle OS signals for graceful shutdown
		// Platform-specific: Unix listens for SIGINT+SIGTERM, Windows only SIGTERM
		setupSignalHandler(&g, ctx, &shutdownRequested)
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			return adminServer.Serve(ctx)
		}, func(err error) {
			_ = adminServer.Shutdown(ctx)
			cancel()
		})
	}
	{
		g.Add(func() error {
			for evt := range eventEmitter.On(upterm.EventClientJoined) {
				args := evt.Args
				if len(args) == 0 {
					continue
				}

				client, ok := args[0].(*api.Client)
				if ok {
					_ = clientRepo.Add(client)
					logger.Info("Client joined", "client", client.Addr)
					if c.ClientJoinedCallback != nil {
						c.ClientJoinedCallback(client)
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off(upterm.EventClientJoined)
		})
	}
	{
		g.Add(func() error {
			for evt := range eventEmitter.On(upterm.EventClientLeft) {
				args := evt.Args
				if len(args) == 0 {
					continue
				}

				cid, ok := args[0].(string)
				if ok {
					client := clientRepo.Get(cid)
					if client != nil {
						logger.Info("Client left", "client", client.Addr)
						clientRepo.Delete(cid)
						if c.ClientLeftCallback != nil {
							c.ClientLeftCallback(client)
						}
					}
				}
			}

			return nil
		}, func(err error) {
			eventEmitter.Off(upterm.EventClientLeft)
		})
	}
	// Hoisted out of the block below so the classification after g.Run can ask
	// it what the command actually did.
	var sshServer internal.Server
	{
		logger.Info("Starting sshd server")
		defer logger.Info("Finishing sshd server")

		commandEnv := []string{fmt.Sprintf("%s=%s", upterm.HostAdminSocketEnvVar, c.AdminSocketFile)}
		if c.SessionDir != nil {
			commandEnv = append(commandEnv, fmt.Sprintf("%s=%s", upterm.HostSessionNameEnvVar, c.SessionDir.Name()))
		}

		ctx, cancel := context.WithCancel(ctx)
		sshServer = internal.Server{
			Command:                 c.Command,
			CommandEnv:              commandEnv,
			ForceCommand:            c.ForceCommand,
			Signers:                 c.Signers,
			AuthorizedKeys:          aks,
			EventEmitter:            eventEmitter,
			KeepAliveDuration:       c.KeepAliveDuration,
			Logger:                  logger.With("component", "server"),
			ReadOnly:                c.ReadOnly,
			AllowLocalTCPForwarding: c.AllowLocalTCPForwarding,
			PtySize:                 c.PtySize,
			PinPtySize:              c.PinPtySize,
			Term:                    c.Term,
			AwaitInitialClient:      c.AwaitInitialClient,
			InitialClientTimeout:    c.InitialClientTimeout,
			SFTPDisabled:            c.SFTPDisabled,
			SFTPPermissionChecker:   c.SFTPPermissionChecker,
			OnCommandStarted: func() {
				cmdOnce.Do(func() { close(cmdReady) })
				if c.CommandStartedCallback != nil {
					c.CommandStartedCallback()
				}
			},
			OnGuestServerStopped: func(err error) {
				logger.Warn("reverse tunnel stopped serving guests; command continues", "error", err)
				if c.SessionDir != nil {
					_ = c.SessionDir.Update(func(r *sessiondir.Record) {
						advanceStatus(r, sessiondir.StatusDisconnected)
					})
				}
			},
		}
		g.Add(func() error {
			return sshServer.ServeWithContext(ctx, rt.Listener(), attachLn)
		}, func(err error) {
			cancel()
		})
	}
	{
		ready := make(chan struct{})
		g.Add(func() error {
			select {
			case <-adminReady:
			case <-ready:
				return nil
			}
			select {
			case <-cmdReady:
			case <-ready:
				return nil
			}

			// Both acknowledged. Only now is every claim a reader makes off
			// "ready" true: the session is registered, the user accepted it,
			// the admin socket is bound, and the command is running.
			if c.SessionDir != nil {
				_ = c.SessionDir.Update(func(r *sessiondir.Record) {
					r.SessionID = sessionID
					advanceStatus(r, sessiondir.StatusReady)
				})
			}

			<-ready
			return nil
		}, func(err error) {
			close(ready)
		})
	}

	err = g.Run()

	// The command's own outcome, and the cause that initiated teardown, are
	// two different questions. Precedence is explicit because the wait status
	// cannot answer the second: our own teardown kills the command, so a
	// requested shutdown surfaces as a signal on Unix and as an ordinary
	// non-zero exit on Windows.
	res := sshServer.CommandResult()
	switch {
	case shutdownRequested.Load():
		// We asked for this. Whatever the wait says, the reason is that it was
		// stopped — and the exit code of a process we killed is not the
		// command's own outcome, so it is deliberately not reported.
		runReason = sessiondir.ReasonStopped
	case errors.Is(err, internal.ErrNoInitialClient):
		// Nobody attached, so nothing ran and nothing failed: the session
		// was abandoned before its command started.
		runReason = sessiondir.ReasonStartupAbandoned
	case res.Exited:
		code := res.Code
		runExitCode = &code
		runReason = sessiondir.ReasonExited
	case res.Signal != "":
		runSignal = res.Signal
		runReason = sessiondir.ReasonSignaled
	default:
		runReason = sessiondir.ReasonStartupFailed
	}

	return err
}

func keyType(t string) string {
	return strings.ToUpper(strings.TrimPrefix(t, "ssh-"))
}

func createFileIfNotExist(file string) error {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}

		file, err := os.Create(file)
		if err != nil {
			return err
		}

		defer func() {
			_ = file.Close()
		}()
	}

	return nil
}

func toApiAuthorizedKeys(aks []*AuthorizedKey) []*api.AuthorizedKey {
	var apiAks []*api.AuthorizedKey
	for _, ak := range aks {
		var fps []string
		for _, pk := range ak.PublicKeys {
			fps = append(fps, utils.FingerprintSHA256(pk))
		}

		apiAks = append(apiAks, &api.AuthorizedKey{
			PublicKeyFingerprints: fps,
			Comment:               ak.Comment,
		})
	}

	return apiAks
}

// DisplayVersionWarning prints a formatted version mismatch warning to the
// given writer. Run no longer prints it — a daemon has no terminal — so this
// is for a caller that does, from VersionWarningCallback.
func DisplayVersionWarning(out io.Writer, logger *slog.Logger, result *version.CompatibilityResult) {
	messages := []struct {
		text     string
		debugMsg string
	}{
		{"[WARNING] VERSION MISMATCH DETECTED\n", "failed to display version warning header"},
		{result.Message + "\n", "failed to display version warning message"},
		{fmt.Sprintf("Host version:   %s\n", result.HostVersion), "failed to display host version"},
		{fmt.Sprintf("Server version: %s\n", result.ServerVersion), "failed to display server version"},
		{"\nThis may cause compatibility issues. Consider updating to matching versions.\n\n", "failed to display version warning footer"},
	}

	for _, msg := range messages {
		if _, err := fmt.Fprint(out, msg.text); err != nil {
			logger.Debug(msg.debugMsg, "error", err)
		}
	}
}
