package command

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/ci"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	flagCILimitAccessToActor bool
	flagCILimitAccessToUsers []string
	flagCIWaitTimeout        time.Duration
	flagCIContinueFile       string
	flagCILogSessionOutput   bool

	// ciAuthorizationRequested records that a --limit-access-to-* flag asked
	// for a restriction, for the fail-closed guard in runHostSession.
	//
	// Not derived from suppliedFlags like the other authorization flags are:
	// --limit-access-to-actor is a bool, and `--limit-access-to-actor=false`
	// is supplied without requesting anything. Read through
	// authorizationRequested.
	ciAuthorizationRequested bool
)

// ciDefaultWaitTimeout is how long a session with nobody in it stays up.
//
// A CI job is billed by the minute and a debugging session is opened by
// someone who is, almost by definition, not watching the run at that moment.
// Ten minutes is long enough to notice the annotation and paste the command,
// and short enough that a session opened by a `workflow_dispatch` nobody
// followed up on does not hold a runner for the job's whole timeout.
const ciDefaultWaitTimeout = 10 * time.Minute

// ciPollInterval is how often the continue-file and the wait deadline are
// checked. Nobody is waiting on the difference between one second and five,
// and a session that has been joined does no polling work worth tuning.
const ciPollInterval = 2 * time.Second

func ciCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Host a debugging session from a CI job",
		Long: `Host a terminal session on a CI runner and tell the CI system how to join it.

This is 'upterm host' with the defaults a CI job needs and a lifecycle suited to
one. There is no terminal on a runner and nobody watching the build log as it
scrolls, so the session:

  * accepts clients without an interactive prompt,
  * publishes the SSH command the way the CI system expects (on GitHub Actions:
    the 'ssh-command' step output, the job summary, and a notice annotation),
  * shuts down on its own if nobody connects within --wait-timeout, so an
    unanswered session does not hold the runner for the job's whole timeout,
  * keeps the session's own terminal output out of the job log, which on a
    public repository is public (--log-session-output puts it back),
  * ends when a 'continue' file appears, which is how someone inside the
    session hands the job back.

Once a client connects, --wait-timeout no longer applies: the session stays up
until the shell exits, the continue file appears, or the job is cancelled.

Restrict who may join with --limit-access-to-actor and --limit-access-to-users,
or with any of 'upterm host's own --authorized-user and --authorized-keys flags.
Without one of those, anyone holding the session's SSH command can join, and on
a public repository that command is in a public build log.`,
		Example: `  # Debug a GitHub Actions job, letting only the user who triggered it in:
  upterm ci --limit-access-to-actor

  # Let a named set of GitHub users in, and wait half an hour for one of them:
  upterm ci --limit-access-to-users alice,bob --wait-timeout 30m

  # Hand the job back from inside the session:
  $ touch /continue

  # Use your own upterm server:
  upterm ci --server wss://YOUR_UPTERMD_SERVER --limit-access-to-actor`,
		PreRunE: validateCIFlags,
		RunE:    ciRunE,
	}

	registerHostFlags(cmd.PersistentFlags())

	// A runner has no known_hosts to have recorded the server in, so the
	// interactive "is this the right host key?" question has no answer
	// available and its default has to be the other one. Still a flag: a job
	// that ships a known_hosts file of its own should be able to say so.
	//
	// Only the reported default is set here. The value itself is applied in
	// ciRunE, because registerHostFlags writes package-level variables shared
	// with `upterm host`, whose own registration runs after this one and would
	// overwrite anything set now.
	markFlagDefault(cmd.PersistentFlags(), "skip-host-key-check", "true")

	// --accept is not a choice here: it is the prompt, and there is no
	// terminal to answer it on. Hidden rather than removed so that a config
	// file or UPTERM_ACCEPT left over from `upterm host` still parses; ciRunE
	// forces it on regardless of what it parsed to.
	_ = cmd.PersistentFlags().MarkHidden("accept")

	cmd.Flags().BoolVar(&flagCILimitAccessToActor, "limit-access-to-actor", false,
		"Authorize only the account that triggered the CI job, by fetching its public keys from the CI system's code host.")
	// registerAuthUserFlag, not StringSliceVar: pflag's own string-slice
	// parser reads one CSV record, so a newline-separated list silently
	// becomes its first name and the rest are never authorized. This is an
	// allow-list, so a value it cannot parse whole has to be an error — the
	// same reason the five --*-user flags use this parser.
	registerAuthUserFlag(cmd.Flags(), &flagCILimitAccessToUsers, "limit-access-to-users",
		"Authorize only these GitHub users, by fetching their public keys. Repeatable, and accepts a comma- or space-separated list.")
	cmd.Flags().DurationVar(&flagCIWaitTimeout, "wait-timeout", ciDefaultWaitTimeout,
		"Shut down the session if no client has connected within this long. 0 waits forever.")
	cmd.Flags().StringVar(&flagCIContinueFile, "continue-file", "",
		"End the session when this file appears. Defaults to /continue and $GITHUB_WORKSPACE/continue.")
	cmd.Flags().BoolVar(&flagCILogSessionOutput, "log-session-output", false,
		"Mirror the session's terminal output into the CI job log. Off by default: that log may be public and outlives the run.")

	return cmd
}

// markFlagDefault changes the default that --help and the generated docs
// report for one of the shared host flags.
//
// It reports only. The flags registerHostFlags registers are backed by
// package-level variables that `upterm host` registers over the top of, so a
// value set at registration does not survive to RunE; ciRunE applies the
// matching value itself, guarded by suppliedFlags so that it defers to an
// actual answer from the command line, the environment or the config file.
func markFlagDefault(fs *pflag.FlagSet, name, value string) {
	f := fs.Lookup(name)
	if f == nil {
		// Only reachable if a flag registerHostFlags registers is renamed, in
		// which case every run of this command is wrong and should say so.
		panic(fmt.Sprintf("upterm ci: no flag %q to set a default on", name))
	}
	f.DefValue = value
}

func validateCIFlags(c *cobra.Command, args []string) error {
	var result error

	if err := validateShareRequiredFlags(c, args); err != nil {
		result = multierror.Append(result, err)
	}

	if flagCIWaitTimeout < 0 {
		result = multierror.Append(result, fmt.Errorf("--wait-timeout cannot be negative; use 0 to wait forever"))
	}

	return result
}

func ciRunE(c *cobra.Command, args []string) error {
	logger := uptermctx.Logger(c.Context())
	if logger == nil {
		return fmt.Errorf("logger not available")
	}

	provider := ci.Detect()
	if provider == nil {
		// Not fatal. `upterm ci` run from a laptop, or on a CI system this
		// does not know how to report to, still hosts the session and still
		// prints the banner; only the CI-native reporting is missing, and
		// saying so beats leaving someone to wonder where their step output
		// went.
		fmt.Fprintln(os.Stdout, "upterm: no supported CI system detected; the session will only be reported in this log.")
	}

	users, err := ciAuthorizedUsers(provider, flagCILimitAccessToActor, flagCILimitAccessToUsers)
	if err != nil {
		return err
	}
	// Appended rather than assigned: --authorized-user and the per-provider
	// flags are registered on this command too, and a job that uses both is
	// asking for the union.
	flagAuthorizedUsers = append(flagAuthorizedUsers, users...)
	ciAuthorizationRequested = ciRestrictionRequested(flagCILimitAccessToActor, flagCILimitAccessToUsers, suppliedFlags)

	// See the hidden --accept registration above: there is no terminal here to
	// answer a confirmation prompt on.
	flagAccept = true

	// The CI default for a flag `upterm host` also owns. suppliedFlags is the
	// union of the command line, UPTERM_SKIP_HOST_KEY_CHECK and the config
	// file, so an explicit --skip-host-key-check=false still wins.
	if !suppliedFlags["skip-host-key-check"] {
		flagSkipHostKeyCheck = true
	}

	ctx, cancel := context.WithCancel(c.Context())
	defer cancel()
	// The session is run from this command's context, so replacing it is how
	// the watchers below get to end a session that nobody joined.
	c.SetContext(ctx)

	// Where the hosted session's own terminal output goes. Not the job log by
	// default: on a public repository that log is public and outlives the run,
	// and everything a guest types and every file they cat would be in it.
	// The banner and this command's own progress lines are printed separately
	// and are unaffected.
	sessionStdout := os.Stdout
	if !flagCILogSessionOutput {
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("cannot discard the session's output: %w", err)
		}
		defer devNull.Close()
		sessionStdout = devNull
	}

	sess := &ciSession{
		provider:      provider,
		logger:        logger.Logger,
		out:           os.Stdout,
		waitTimeout:   flagCIWaitTimeout,
		continueFiles: ciContinueFiles(flagCIContinueFile, provider),
		pollInterval:  ciPollInterval,
		cancel:        cancel,
	}

	err = runHostSession(c, args, sessionOptions{
		Stdout:         sessionStdout,
		SessionCreated: sess.created,
		ClientJoined:   sess.clientJoined,
		ClientLeft:     sess.clientLeft,
	})

	// A session this command ended on purpose is not a failed one, whatever
	// the cancellation surfaced as on the way out. Without this, every
	// wait-timeout and every `touch /continue` would fail the job it was
	// supposed to let continue.
	if reason := sess.stopReason(); reason != "" {
		sess.printf("upterm: session ended: %s", reason)
		sess.logger.Info("ci session ended", "reason", reason, "error", err)
		return nil
	}

	return err
}

// ciRestrictionRequested reports whether the --limit-access-to-* flags asked
// for a restriction at all, which is a different question from whether any
// keys came back.
//
// supplied, not len(users): pflag parses --limit-access-to-users "" into an
// empty slice, so a length test alone reads an empty workflow input as "no
// restriction asked for", and the fail-closed guard in runHostSession never
// fires — the session then accepts anyone holding the connect string this
// command has just published to a step output, a job summary and a run
// annotation. suppliedFlags is the union of the command line, the environment
// and the config file, which is the question actually being asked.
//
// The length test stays as well, for a restriction that reached the variable
// without going through a flag at all.
func ciRestrictionRequested(limitToActor bool, users []string, supplied map[string]bool) bool {
	return limitToActor || supplied["limit-access-to-users"] || len(users) > 0
}

// ciAuthorizedUsers turns the --limit-access-to-* flags into the user
// references runHostSession authorizes.
//
// An unresolvable restriction is an error rather than a warning: the session
// it would otherwise start is one that accepts anybody holding a connect
// string that is sitting in a build log.
func ciAuthorizedUsers(provider ci.Provider, limitToActor bool, users []string) ([]string, error) {
	seen := make(map[string]bool)
	var refs []string
	add := func(user string) {
		ref := "github:" + user
		if seen[ref] {
			return
		}
		seen[ref] = true
		refs = append(refs, ref)
	}

	if limitToActor {
		if provider == nil {
			return nil, fmt.Errorf("--limit-access-to-actor: no CI system detected, so there is no actor to authorize; name the users with --limit-access-to-users or --authorized-user")
		}
		actor := provider.Actor()
		if actor == "" {
			return nil, fmt.Errorf("--limit-access-to-actor: %s did not say who triggered this job; name the users with --limit-access-to-users or --authorized-user", provider.Name())
		}
		refs = append(refs, "github:"+actor)
		seen["github:"+actor] = true
	}

	for _, user := range splitUserList(users) {
		add(user)
	}

	return refs, nil
}

// splitUserList flattens the --limit-access-to-users values.
//
// The flag's parser has already split on commas, which covers
// `--limit-access-to-users alice,bob`. Splitting again on spaces covers
// `--limit-access-to-users "alice bob"`, which CSV does not separate, and
// drops an empty entry rather than turning it into a lookup of "".
//
// Newlines never reach here: the parser rejects them, in every origin, rather
// than returning a truncated allow-list. A workflow input written as a YAML
// block has to be joined with commas by whoever passes it.
func splitUserList(values []string) []string {
	var out []string
	for _, v := range values {
		for _, field := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
			out = append(out, field)
		}
	}
	return out
}

// ciContinueFiles lists the paths whose appearance ends the session.
//
// With no --continue-file, both of action-upterm's paths are watched: /continue
// is what the documented `touch /continue` writes, and the one under the
// checkout is for a container or a self-hosted runner where the root of the
// filesystem is not writable.
func ciContinueFiles(explicit string, provider ci.Provider) []string {
	if explicit != "" {
		return []string{explicit}
	}

	paths := []string{ciRootContinueFile}
	if provider != nil {
		if ws := provider.Workspace(); ws != "" {
			paths = append(paths, filepath.Join(ws, "continue"))
		}
	}
	return paths
}

// ciSession is the lifecycle `upterm ci` adds around a hosted session: report
// it to the CI system when it comes up, and end it when the reason it was
// started has gone away.
type ciSession struct {
	provider      ci.Provider
	logger        *slog.Logger
	out           io.Writer
	waitTimeout   time.Duration
	continueFiles []string
	pollInterval  time.Duration
	cancel        context.CancelFunc

	// connected latches on the first client and never clears. The question
	// --wait-timeout asks is whether anyone ever arrived, not whether anyone
	// is here now: a guest who joins, fixes the build and disconnects has
	// answered it, and re-arming the timeout behind them would shut down a
	// session they are about to reconnect to.
	connected atomic.Bool

	stopOnce sync.Once
	reason   atomic.Pointer[string]

	// startedAt is when this session began watching. A continue file older
	// than that was left by something else and says nothing about this
	// session; see continueFileFound.
	startedAt time.Time
	staleOnce sync.Once
}

// created runs once the session is up: it prints the banner every host
// session prints, hands the join command to the CI system, and starts the
// watchers that can end the session.
func (s *ciSession) created(ctx context.Context, session *api.GetSessionResponse, name string) error {
	if err := displaySession(ctx, session, name); err != nil {
		return err
	}

	s.report(session, name)

	go s.watch(ctx)

	if s.waitTimeout > 0 {
		s.printf("upterm: waiting up to %s for a client to connect.", s.waitTimeout)
	}
	for _, path := range s.continueFiles {
		s.printf("upterm: create %s from inside the session to end it and continue the job.", path)
	}

	return nil
}

// report tells the CI system how to join.
//
// Every failure here is logged and swallowed. This runs from
// SessionCreatedCallback, where returning an error abandons the session — and
// a session that is up and joinable is worth more than the annotation that
// failed to describe it, which the banner on stdout has already said anyway.
func (s *ciSession) report(session *api.GetSessionResponse, name string) {
	if s.provider == nil {
		return
	}

	detail, err := buildSessionDetail(session)
	if err != nil {
		s.logger.Warn("could not describe the session for the CI system", "error", err)
		return
	}

	if err := s.provider.Ready(ci.Session{SSHCommand: detail.SSHCommand, Name: name}); err != nil {
		s.logger.Warn("could not report the session to the CI system", "ci", s.provider.Name(), "error", err)
		s.printf("upterm: could not report the session to %s: %v", s.provider.Name(), err)
	}
}

func (s *ciSession) clientJoined(c *api.Client) {
	s.connected.Store(true)
	s.printf("upterm: client joined: %s", clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint))
}

func (s *ciSession) clientLeft(c *api.Client) {
	s.printf("upterm: client left: %s", clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint))
}

// watch ends the session when nobody came, or when someone inside it asked for
// the job to continue.
func (s *ciSession) watch(ctx context.Context) {
	// Truncated to the second because that is the coarsest mtime granularity
	// a runner's filesystem might have. Rounding down can only make a stale
	// file from this same second look fresh, which costs one early exit;
	// rounding up would make a genuinely new file look stale, and the session
	// would then ignore the one instruction it is watching for.
	s.startedAt = time.Now().Truncate(time.Second)

	var deadline time.Time
	if s.waitTimeout > 0 {
		deadline = time.Now().Add(s.waitTimeout)
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if path := s.continueFileFound(); path != "" {
			s.stop(fmt.Sprintf("%s was created", path))
			return
		}

		// Checked after the continue file, and only while the session is still
		// empty: once anyone has connected the deadline is spent, and the
		// session belongs to whoever is in it.
		if !deadline.IsZero() && !s.connected.Load() && !time.Now().Before(deadline) {
			s.stop(fmt.Sprintf("no client connected within %s", s.waitTimeout))
			return
		}
	}
}

// continueFileFound returns the first continue file that this session should
// act on, or "".
//
// A stat error other than "not there" is treated as not there: an unreadable
// parent directory is not someone asking for the session to end, and ending it
// on that would make a misconfigured path look like a guest's decision.
//
// A file older than the session is ignored. /continue and the one under the
// checkout both outlive the session that ended on them, and a self-hosted
// runner — or a job with two `if: failure()` steps — reuses both paths. Acting
// on a leftover would mean publishing the annotation, the step output and the
// summary for a session that then ends a tick later with no hint that a stale
// file, rather than a guest, ended it. Comparing mtime rather than deleting
// the file keeps `touch` working on a path that already exists: touching a
// stale file makes it current, which is exactly what the guest meant.
func (s *ciSession) continueFileFound() string {
	for _, path := range s.continueFiles {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(s.startedAt) {
			s.staleOnce.Do(func() {
				s.printf("upterm: ignoring %s: it predates this session. Touch it again to end the session.", path)
				s.logger.Info("ignoring a continue file that predates the session", "path", path, "modified", fi.ModTime())
			})
			continue
		}
		return path
	}
	return ""
}

// stop ends the session and records why, for ciRunE to report instead of the
// cancellation error the session will surface.
func (s *ciSession) stop(reason string) {
	s.stopOnce.Do(func() {
		s.reason.Store(&reason)
		s.logger.Info("ending ci session", "reason", reason)
		s.cancel()
	})
}

// stopReason is the reason this command ended the session, or "" when it did
// not — the shell exited, or the job was cancelled.
func (s *ciSession) stopReason() string {
	if r := s.reason.Load(); r != nil {
		return *r
	}
	return ""
}

// printf writes a progress line where a CI job's log will show it.
//
// Not the logger: root.go points that at upterm's log file, which on a runner
// is discarded with the runner. The banner already goes to stdout for the same
// reason.
func (s *ciSession) printf(format string, args ...any) {
	fmt.Fprintf(s.out, format+"\n", args...)
}
