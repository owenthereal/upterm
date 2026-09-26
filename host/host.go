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
	"syscall"
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

// NewPromptingHostKeyCallback creates a host key callback that asks before
// accepting an unknown host key.
//
// Set proxied when the transport passes through an HTTP proxy. x/crypto hands
// the callback the socket's peer, which is then the proxy rather than the
// server, and presenting it as the server's address is misleading — OpenSSH
// prints a placeholder in the same situation. It is display-only: knownhosts
// matches on the hostname argument and appendHostLine stores only that, so
// verification is unaffected either way.
func NewPromptingHostKeyCallback(stdin io.Reader, stdout io.Writer, knownHostsFilename string, proxied bool) (ssh.HostKeyCallback, error) {
	return newHostKeyCallback(stdin, stdout, knownHostsFilename, false, proxied)
}

// NewAutoAcceptingHostKeyCallback creates a host key callback that automatically
// accepts unknown host keys and adds them to the known_hosts file without prompting.
// This is similar to SSH's StrictHostKeyChecking=accept-new behavior:
// - Unknown host keys are automatically accepted and added to known_hosts
// - Known host keys are still validated (preventing MITM attacks on subsequent connections)
//
// It takes no proxied flag: its message names the hostname and the key type,
// never the peer address.
func NewAutoAcceptingHostKeyCallback(stdout io.Writer, knownHostsFilename string) (ssh.HostKeyCallback, error) {
	return newHostKeyCallback(nil, stdout, knownHostsFilename, true, false)
}

func newHostKeyCallback(stdin io.Reader, stdout io.Writer, knownHostsFilename string, autoAccept, proxied bool) (ssh.HostKeyCallback, error) {
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
		proxied:         proxied,
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
	// proxied suppresses the peer address in the prompt, because through a
	// tunnel it belongs to the proxy rather than to the server.
	proxied bool
	ssh.HostKeyCallback
}

// noHostIP stands in for the server's address when the connection was
// tunnelled. OpenSSH prints "<no hostip for proxy command>" in the same
// situation; upterm reaches it through --proxy or the proxy environment rather
// than a ProxyCommand.
const noHostIP = "<no hostip for proxy>"

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
	hostIP := knownhosts.Normalize(remote.String())
	if cb.proxied {
		hostIP = noHostIP
	}
	_, _ = fmt.Fprintf(cb.stdout, "The authenticity of host '%s (%s)' can't be established.\n", knownhosts.Normalize(hostname), hostIP)
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
	Host              string
	KeepAliveDuration time.Duration
	Command           []string
	ForceCommand      []string
	Signers           []ssh.Signer
	// HostKey is the key the embedded sshd presents on both its doors and
	// the key the relay is told to expect from this host. A session's key,
	// not the operator's: Signers authenticate the tunnel and are used for
	// nothing else. Left nil, Run generates one for that run and does not
	// keep it, so a Host run twice presents two keys; a caller that needs
	// the public half before Run — the CLI, to pin its own attach — sets it
	// and it is used as given.
	HostKey                 ssh.Signer
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
	// SessionReadyCallback is called once the session's record has been
	// published: the admin socket is bound, the command is running, and the
	// record a reader would consult already carries the session ID and the
	// status handed to this callback. A caller that tells anyone else the
	// session is up says it here, not from CommandStartedCallback — the
	// command starting is one of the two facts readiness is made of, and the
	// record is written after both. A script that runs `upterm session info`
	// the instant it is told "ready" would otherwise be told "starting" by
	// the record.
	//
	// The status is what the record ended on, which is not always ready:
	// advanceStatus refuses to move a status backwards, so a tunnel lost
	// between the command starting and this write leaves "disconnected"
	// standing and the ready write is a no-op. The caller is told what the
	// record says rather than what this actor asked for, because the two
	// agreeing is the whole point of the callback.
	//
	// Not called when the record could not be published: the run fails
	// instead, so that nobody is told about a record that was never written.
	// With no session directory — an embedder that supplied its own admin
	// socket — there is no record, the two facts alone are it, and the
	// status is ready.
	//
	// Called once, on the readiness actor's own goroutine, after the write;
	// it must not block.
	SessionReadyCallback func(status string)
	// SessionClaimedCallback is called once the session's name is claimed,
	// with the directory that holds it, before the tunnel is dialled: the
	// first thing a caller can know about a session is its name and its
	// paths, and a caller that relays prompts wants them before any prompt.
	// Not called when AdminSocketFile was supplied, since nothing is claimed.
	//
	// Called on Run's own goroutine; it must not block.
	SessionClaimedCallback func(*sessiondir.Dir)
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

	// StopGrace bounds each step of the command's teardown; zero means
	// internal.DefaultStopGrace.
	StopGrace time.Duration

	// JoinTimeout bounds the wait for the first guest, starting at readiness.
	// Zero waits forever. A running session's timeout can be replaced or
	// disabled over the admin socket (`upterm session set`); each replacement
	// counts from when it is made. The session enforces it independently of its
	// launcher; a guest joining disarms it permanently, even after that guest
	// leaves.
	JoinTimeout time.Duration

	// onJoinDeadlineFired is a per-Host test barrier for a late losing deadline.
	onJoinDeadlineFired func(stop <-chan struct{})
	// onJoinPublish is a per-Host test barrier run before each join-timeout
	// record write: blocking in it holds the write, and an error skips it as
	// a failed write.
	onJoinPublish func() error
	// joins is the running session's join state, for JoinState. Set by Run
	// before any actor starts and cleared on its way out, so a callback Run
	// makes reads it without a lock of its own.
	joins *joinState

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

// errJoinTimeout requests group teardown; Run maps this winning outcome to success.
var errJoinTimeout = internal.ErrJoinTimeout

// errSessionStopped retains the cancellation contract for Host.Run callers.
var errSessionStopped = fmt.Errorf("session stopped: %w", context.Canceled)

type hostSignalError struct{ signal syscall.Signal }

func (e hostSignalError) Error() string { return fmt.Sprintf("received signal %s", e.signal) }

// abandonedBy reports whether ctx was cancelled because the process that
// started the session went away: a cancellation whose cause is
// ErrSessionAbandoned. Nothing failed and nothing was asked to stop; the
// record must say so.
func abandonedBy(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrSessionAbandoned)
}

// readinessEstablished waits for the two facts readiness is made of — the
// admin socket bound and the command started — and reports whether both were
// established. A teardown that beats them to it is a "no"; a teardown that
// merely coincides with them is not.
//
// That distinction is the whole of this function. Go picks between two ready
// cases at random, and both are ready whenever a command starts and ends
// before this actor is scheduled again — `upterm host --detach -- true` is
// the whole of that window. Left to the coin, half of those runs published
// the record and told the parent "started", and half returned here, so the
// parent saw the channel close instead and reported "the session daemon
// exited before reporting whether it started" — for a session whose command
// had run to completion. --detach's contract is that it exits 0 once the
// command is running, and a command that started and exited did run; what
// became of it is the record's to say, and the status carried in Started is
// what the parent prints. A script cannot branch on a coin, so an
// established fact wins and the scheduler decides nothing.
//
// The non-blocking re-check on each teardown branch is what makes that so
// rather than merely likely: whichever case the select picks, a fact that is
// established is still established.
//
// A fact that is genuinely not established is still a "no", and that is why
// this waits on the pair rather than assuming them: a command that could not
// start never closes cmdReady — exec reports that failure to Start, so
// OnCommandStarted is never reached — and nothing is published for it.
func readinessEstablished(adminReady, cmdReady, ready <-chan struct{}) bool {
	select {
	case <-adminReady:
	case <-ready:
		if !closed(adminReady) {
			return false
		}
	}
	select {
	case <-cmdReady:
	case <-ready:
		if !closed(cmdReady) {
			return false
		}
	}
	return true
}

// closed reports whether a done-style channel has been closed, without waiting.
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// guestJoinLatch publishes the first guest join into the record. A
// successful publication is attempted once; a failed publication is retried
// on a later guest, carrying the first join's time, which disarm returns.
//
// disarm is the join state's join, and runs before the record write, not
// after: the in-memory state is what enforces the timeout, and making it wait
// on a filesystem write would let a slow disk expire a timeout a guest had
// already answered. A late join -- one registered after the timeout
// committed -- is not published: the session is ending for want of a guest,
// and a record claiming one beside join_timeout would say both.
//
// A publication failure is logged by the caller, never swallowed silently:
// a reader that asks "has anyone ever joined?" and is told "no" for a
// session somebody is sitting in will stop it. The in-memory state still
// holds, so this process's own deadline is safe either way -- it is the
// external reader that loses.
type guestJoinLatch struct {
	update    func(func(*sessiondir.Record)) error
	disarm    func() (joinedAt time.Time, late bool)
	published bool
}

// Emit is asynchronous, so a short session's left may reach the consumer
// before its joined. This state reconciles both topics in one actor.
type clientLifecycle struct {
	repo        *internal.ClientRepo
	pendingLeft map[string]struct{}
	onGuestJoin func(*api.Client) error
	onJoined    func(*api.Client)
	onLeft      func(*api.Client)
	logger      *slog.Logger
	recordPath  string
}

func (l *clientLifecycle) joined(client *api.Client, qualifiesAsGuestJoin bool) {
	_ = l.repo.Add(client)
	if l.logger != nil {
		l.logger.Info("Client joined", "client", client.Addr)
	}
	if qualifiesAsGuestJoin && l.onGuestJoin != nil {
		if err := l.onGuestJoin(client); err != nil && l.logger != nil {
			l.logger.Error("failed to publish the first guest join; readers may stop this session as unjoined",
				"record", l.recordPath, "error", err)
		}
	}
	if l.onJoined != nil {
		l.onJoined(client)
	}
	if _, left := l.pendingLeft[client.Id]; left {
		delete(l.pendingLeft, client.Id)
		l.left(client.Id)
	}
}

func (l *clientLifecycle) left(id string) {
	client := l.repo.Get(id)
	if client == nil {
		l.pendingLeft[id] = struct{}{}
		return
	}
	if l.logger != nil {
		l.logger.Info("Client left", "client", client.Addr)
	}
	l.repo.Delete(id)
	if l.onLeft != nil {
		l.onLeft(client)
	}
}

func (l *guestJoinLatch) note(client *api.Client) error {
	if client.GetKind() != api.Client_GUEST {
		return nil
	}
	joinedAt, late := l.disarm()
	if late || l.published {
		return nil
	}
	err := l.update(func(r *sessiondir.Record) {
		if r.FirstGuestJoinedAt.IsZero() {
			r.FirstGuestJoinedAt = joinedAt
		}
		// Joining claims the session for good, so no join timeout applies
		// any more, and the record must not keep advertising one beside it.
		r.JoinTimeout = 0
		r.JoinDeadline = time.Time{}
	})
	if err == nil {
		l.published = true
	}
	return err
}

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
func (c *Host) Run(ctx context.Context) (runErr error) {
	// First, before anything here can write a byte. Whatever a
	// SessionCreatedCallback prints, and whatever a VersionWarningCallback
	// prints, goes out well before the signal actor is assembled, and for an
	// embedder whose reader has gone away a single one of those writes is
	// fatal. See InstallSignalPolicy; calling it again from setupSignalHandler
	// is free.
	InstallSignalPolicy()

	// Admin stop has its own cause; external parent cancellation remains distinct.
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	requestStop := func() { cancelRun(errSessionStopped) }

	u, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("error parsing host url: %s", err)
	}

	// This run's key. Never written back: a Host is reusable, and a key
	// that survived into a second run would make "per run" false.
	hostKey := c.HostKey
	if hostKey == nil {
		key, err := NewHostKey()
		if err != nil {
			return fmt.Errorf("error generating host key: %w", err)
		}
		hostKey = key
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

		if c.SessionClaimedCallback != nil {
			c.SessionClaimedCallback(dir)
		}
	}

	var (
		sessionID       string
		runReason       = sessiondir.ReasonStartupFailed
		runExitCode     *int
		runSignal       string
		runSignalNumber *int
	)

	joins := newJoinState(c.JoinTimeout)
	// On the Host for JoinState, before anything that could ask runs. Cleared
	// on the way out for SessionDir's reason: a Host between runs has no
	// session to answer for.
	c.joins = joins
	defer func() { c.joins = nil }()

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
			// Early returns have no group winner. Only a returned cancellation
			// may change startup_failed; a coincident cancellation cannot hide
			// a genuine startup error.
			if runReason == sessiondir.ReasonStartupFailed && ctx.Err() != nil && errors.Is(runErr, ctx.Err()) {
				runReason = sessiondir.ReasonCanceled
				if abandonedBy(ctx) {
					runReason = sessiondir.ReasonStartupAbandoned
				}
			}

			if err := dir.Update(func(r *sessiondir.Record) {
				r.SessionID = sessionID
				r.FinishedAt = time.Now().UTC()
				advanceStatus(r, sessiondir.StatusEnding)
				r.Reason = runReason
				r.ExitCode = runExitCode
				r.Signal = runSignal
				r.SignalNumber = runSignalNumber
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
		HostKey:           hostKey,
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
	sessionReady := make(chan struct{})
	// sync.Once on each, since a callback that fires twice must not panic on a
	// double close.
	var adminOnce, cmdOnce sync.Once

	// The launch this run is, for the stop RPC to be bound to: the name and
	// the socket are the session's and are handed on to whoever claims the
	// name next, so they cannot say which run a caller meant. Empty when no
	// name was claimed, which the server reads as a session no stop can name.
	var launchID string
	if c.SessionDir != nil {
		launchID = c.SessionDir.LaunchID()
	}

	// publishJoin writes the join timeout as it stands into the record. The
	// snapshot is taken inside Update, under the record's own lock, so
	// whichever write lands last carries the latest state: an arm whose write
	// is overtaken by a join's cannot put a deadline back. It runs only in the
	// publisher actor below; everything else calls markJoinDirty.
	publishJoin := func() {
		if c.SessionDir == nil {
			return
		}
		if c.onJoinPublish != nil {
			if err := c.onJoinPublish(); err != nil {
				logger.Warn("failed to publish the join timeout; the session enforces it regardless", "error", err)
				return
			}
		}
		if err := c.SessionDir.Update(func(r *sessiondir.Record) {
			s := joins.snapshot()
			r.JoinTimeout = s.Timeout
			r.JoinDeadline = s.Deadline
		}); err != nil {
			logger.Warn("failed to publish the join timeout; the session enforces it regardless", "error", err)
		}
	}
	// markJoinDirty asks the publisher for a write and never blocks: one
	// pending request covers any number of changes, since each write takes a
	// fresh snapshot.
	joinDirty := make(chan struct{}, 1)
	markJoinDirty := func() {
		select {
		case joinDirty <- struct{}{}:
		default:
		}
	}

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
		LaunchID:    launchID,
		OnListening: func() { adminOnce.Do(func() { close(adminReady) }) },
		OnStop:      requestStop,
		OnSetJoinTimeout: func(timeout time.Duration) *api.SetJoinTimeoutResponse {
			res := joins.set(timeout)
			switch res.Outcome {
			case joinCounting, joinPending, joinDisabled:
				markJoinDirty()
			}
			return setJoinTimeoutResponse(res)
		},
		JoinState: func() *api.JoinState { return apiJoinState(joins.snapshot()) },
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
		// every record whose attach socket is dialable also carries the key
		// `upterm attach` needs to pin it.
		if c.SessionDir != nil {
			hostKeys := []string{strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(hostKey.PublicKey())), "\n")}
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
	// Interrupts run in registration order. Deliver the selected cause to
	// the command before admin draining or lifecycle unsubscription can block.
	{
		// First, so its interrupt runs first: from the moment teardown
		// begins the join timeout takes no more changes, and a
		// `session set` that reaches the admin socket while it drains is
		// told the session is ending rather than handed a deadline nothing
		// will enforce. joins.close() never blocks -- it only stops a timer
		// under a mutex nothing holds across a wait -- which is why it may
		// run before the cause reaches the command.
		tearingDown := make(chan struct{})
		g.Add(func() error {
			<-tearingDown
			return nil
		}, func(error) {
			joins.close()
			close(tearingDown)
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

		// The group owns this actor's cancellation. Inheriting the parent's
		// cancellation could mask an already selected deadline winner before
		// the interrupt carries its cause to attached clients. The signal
		// actor still observes the parent and initiates ordinary teardown.
		ctx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
		sshServer = internal.Server{
			Command:                 c.Command,
			CommandEnv:              commandEnv,
			ForceCommand:            c.ForceCommand,
			HostKey:                 hostKey,
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
			StopGrace:               c.StopGrace,
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
			// Only the winning group error reaches attached clients.
			cancel(err)
		})
	}
	{
		// Handle OS signals for graceful shutdown
		// Platform-specific: Unix listens for SIGINT+SIGTERM, Windows only SIGTERM
		setupSignalHandler(&g, ctx)
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			return adminServer.Serve(ctx)
		}, func(err error) {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer shutdownCancel()
			_ = adminServer.Shutdown(shutdownCtx)
			cancel()
		})
	}
	// Subscribed here, before any actor runs, rather than inside the actors
	// that read them. run.Group starts its actors as goroutines in no
	// particular order, and by this point the attach socket is bound and its
	// callback has already told the local terminal to connect — so the door's
	// join event can be emitted before a subscription made inside an actor
	// exists. The emitter delivers to whoever is listening at the time and
	// replays nothing, so that client would be missing from the repo for the
	// life of the session: `session info` short by one, and no callback for
	// it. Off stays in the interrupts, which run once, after Run.
	clientJoined := eventEmitter.On(upterm.EventClientJoined)
	forwardingJoined := eventEmitter.On(upterm.EventForwardingClientJoined)
	clientLeft := eventEmitter.On(upterm.EventClientLeft)
	var guestLatch *guestJoinLatch
	if c.SessionDir != nil {
		guestLatch = &guestJoinLatch{update: c.SessionDir.Update, disarm: joins.join}
	}
	lifecycle := &clientLifecycle{
		repo: clientRepo, pendingLeft: make(map[string]struct{}),
		onJoined: c.ClientJoinedCallback, onLeft: c.ClientLeftCallback,
		logger: logger,
	}
	if guestLatch != nil {
		lifecycle.onGuestJoin = guestLatch.note
		lifecycle.recordPath = c.SessionDir.RecordPath()
	} else {
		lifecycle.onGuestJoin = func(client *api.Client) error {
			if client.GetKind() == api.Client_GUEST {
				joins.join()
			}
			return nil
		}
	}
	{
		g.Add(func() error {
			for clientJoined != nil || forwardingJoined != nil || clientLeft != nil {
				select {
				case evt, ok := <-clientJoined:
					if !ok {
						clientJoined = nil
						continue
					}
					if len(evt.Args) > 0 {
						if client, ok := evt.Args[0].(*api.Client); ok {
							lifecycle.joined(client, true)
						}
					}
				case evt, ok := <-forwardingJoined:
					if !ok {
						forwardingJoined = nil
						continue
					}
					if len(evt.Args) > 0 {
						if client, ok := evt.Args[0].(*api.Client); ok {
							lifecycle.joined(client, false)
						}
					}
				case evt, ok := <-clientLeft:
					if !ok {
						clientLeft = nil
						continue
					}
					if len(evt.Args) > 0 {
						if id, ok := evt.Args[0].(string); ok {
							lifecycle.left(id)
						}
					}
				}
			}
			return nil
		}, func(err error) {
			eventEmitter.Off(upterm.EventClientJoined)
			eventEmitter.Off(upterm.EventForwardingClientJoined)
			eventEmitter.Off(upterm.EventClientLeft)
		})
	}

	{
		ready := make(chan struct{})
		g.Add(func() error {
			if !readinessEstablished(adminReady, cmdReady, ready) {
				return nil
			}

			// Both acknowledged. Only now is every claim a reader makes off
			// "ready" true: the session is registered, the user accepted it,
			// the admin socket is bound, and the command is running.
			//
			// publishedStatus is what the record ends up saying, which is
			// not always what is asked for here: advanceStatus will not move
			// a status backwards, so a tunnel lost in the moment between the
			// command starting and this write leaves "disconnected" standing
			// and makes the ready write a no-op. Reported as it is, because
			// a callback that announced "ready" for a record saying
			// otherwise would be the disagreement this callback exists to
			// rule out. Captured inside the closure, which Update runs
			// synchronously under its own lock, once.
			publishedStatus := sessiondir.StatusReady
			if c.SessionDir != nil {
				if err := c.SessionDir.Update(func(r *sessiondir.Record) {
					r.SessionID = sessionID
					advanceStatus(r, sessiondir.StatusReady)
					publishedStatus = r.Status
				}); err != nil {
					// Fatal to the run, where every other record write here
					// is not, because this one is the word readiness is made
					// of: the callback below tells a parent the session is
					// up, and a parent told that goes on to read this record
					// -- `session info`, `session stop`, `attach`. A session
					// whose readiness cannot be published is one no reader
					// can manage, so it fails now, through the reporting the
					// caller already has, rather than running on unreachable.
					logger.Error("Failed to publish the session as ready",
						"record", c.SessionDir.RecordPath(), "error", err)
					return fmt.Errorf("failed to publish the session as ready: %w", err)
				}
			}
			// The join timeout starts counting here, before the callback
			// rather than after it: the callback is what tells a parent the
			// session is ready -- it is what makes --detach return -- so the
			// timeout must already be counting when it runs, or a `session
			// set` made the moment --detach returns would answer "pending"
			// for a session the record calls ready.
			if joins.markReady() {
				markJoinDirty()
			}
			if c.SessionReadyCallback != nil {
				c.SessionReadyCallback(publishedStatus)
			}

			// Unlike ready (closed on teardown), this signals successful readiness.
			close(sessionReady)

			<-ready
			return nil
		}, func(err error) {
			close(ready)
		})
	}

	{
		// The join timeout's record writes, in their own actor, so a write
		// that blocks can never stand between a committed expiry and
		// teardown, nor hold up a `session set`. A write still pending when
		// teardown begins is flushed, so the final record shows what was
		// current.
		stop := make(chan struct{})
		g.Add(func() error {
			for {
				select {
				case <-joinDirty:
					publishJoin()
				case <-stop:
					select {
					case <-joinDirty:
						publishJoin()
					default:
					}
					return nil
				}
			}
		}, func(error) {
			close(stop)
		})
	}
	{
		// The join timeout's enforcement. Always registered, idle until a
		// timeout is set, because `session set` can set one at any point in
		// the session's life. joinState decides everything about it; this
		// actor turns a committed expiry into the group's winner, and never
		// writes the record itself.
		stop := make(chan struct{})
		g.Add(func() error {
			if c.JoinTimeout > 0 {
				// Pending until ready, and published as such, so a reader can
				// tell "set, not counting yet" from "none".
				markJoinDirty()
			}
			// The ready actor starts the clock, before it reports readiness;
			// nothing can fire before then.
			select {
			case <-sessionReady:
			case <-stop:
				return nil
			case <-ctx.Done():
				return errors.Join(ctx.Err(), context.Cause(ctx))
			}
			select {
			case <-joins.Fired():
				// Committed: from here no join can claim the session. The
				// barrier is after the commit, so a test can establish
				// another winner and then exercise this genuinely late
				// losing return.
				if c.onJoinDeadlineFired != nil {
					c.onJoinDeadlineFired(stop)
				}
				return errJoinTimeout
			case <-stop:
				return nil
			case <-ctx.Done():
				return errors.Join(ctx.Err(), context.Cause(ctx))
			}
		}, func(err error) {
			close(stop)
		})
	}

	err = g.Run()

	// The command's own outcome, and the cause that initiated teardown, are
	// two different questions. Precedence is explicit because the wait status
	// cannot answer the second: our own teardown kills the command, so a
	// requested shutdown surfaces as a signal on Unix and as an ordinary
	// non-zero exit on Windows.
	res := sshServer.CommandResult()
	var hostSignal hostSignalError
	switch {
	case errors.Is(err, errJoinTimeout):
		// The group winner alone identifies why teardown happened.
		// The timeout that fired, which `session set` may have replaced
		// since launch.
		logger.Info("no guest joined within the join timeout; session ended", "timeout", joins.snapshot().Timeout)
		runReason = sessiondir.ReasonJoinTimeout
	case errors.Is(err, errSessionStopped):
		runReason = sessiondir.ReasonStopped
	case errors.As(err, &hostSignal):
		runReason = sessiondir.ReasonSignaled
		runSignal = hostSignal.signal.String()
		n := int(hostSignal.signal)
		runSignalNumber = &n
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		runReason = sessiondir.ReasonCanceled
		if abandonedBy(ctx) && !closed(cmdReady) {
			runReason = sessiondir.ReasonStartupAbandoned
		}
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
		runSignalNumber = res.SignalNumber
		runReason = sessiondir.ReasonSignaled
	default:
		runReason = sessiondir.ReasonStartupFailed
	}

	if errors.Is(err, errJoinTimeout) {
		return nil
	}
	return err
}

// JoinState reports the running session's join timeout as its daemon
// holds it, for a caller reporting readiness; nil when Run is not running.
func (c *Host) JoinState() *api.JoinState {
	if c.joins == nil {
		return nil
	}
	return apiJoinState(c.joins.snapshot())
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
