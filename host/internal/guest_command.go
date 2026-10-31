package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
)

type guestCommandPolicy struct {
	LoginCommand, ForceCommand []string
	ReadOnly, ExecDisabled     bool
}
type guestCommandSelection struct {
	Shared, NeedsExecConsent, ForcedExec bool
	Argv                                 []string
	RawCommand                           string
}

// errGuestExecDisabled is --read-only's and --no-exec's denial. Nothing a
// guest or the host's terminal does can lift it for this run.
var errGuestExecDisabled = errors.New("guest exec is disabled")

func selectGuestCommand(requestType, raw string, p guestCommandPolicy) (guestCommandSelection, error) {
	selection := guestCommandSelection{RawCommand: raw}
	switch requestType {
	case "exec":
		if p.ReadOnly || p.ExecDisabled {
			return selection, errGuestExecDisabled
		}
		if len(p.ForceCommand) > 0 {
			selection.Argv = p.ForceCommand
			selection.ForcedExec = true
			return selection, nil
		}
		selection.NeedsExecConsent = true
		var err error
		selection.Argv, err = guestExecArgv(raw)
		return selection, err
	case "shell":
		switch {
		case len(p.ForceCommand) > 0:
			selection.Argv = p.ForceCommand
		case len(p.LoginCommand) > 0:
			selection.Argv = p.LoginCommand
		default:
			selection.Shared = true
		}
		return selection, nil
	default:
		return selection, fmt.Errorf("unsupported guest request %q", requestType)
	}
}

func (h *sessionHandler) commandSelection(sess gssh.Session, requestType string) (guestCommandSelection, error) {
	raw := ""
	if requestType == "exec" {
		raw = sess.RawCommand()
	}
	return selectGuestCommand(requestType, raw, guestCommandPolicy{LoginCommand: h.loginCommand, ForceCommand: h.forceCommand, ReadOnly: h.readonly, ExecDisabled: h.execDisabled})
}

// Consent owns only this wait. A permitted process retains its channel/host
// context, so expiry of the review deadline never terminates an approved child.
func (h *sessionHandler) checkExecPermission(ctx context.Context, arrived time.Time, client consent.ClientInfo, raw string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.acceptExec {
		return nil
	}
	if h.permissionChecker == nil {
		return fmt.Errorf("%w: exec needs approval in the primary host terminal or --accept-exec", consent.ErrUnavailable)
	}
	permissionCtx, cancel := context.WithDeadline(ctx, arrived.Add(consent.PermissionTimeout))
	defer cancel()
	if err := permissionCtx.Err(); err != nil {
		return err
	}
	decision, err := h.permissionChecker.CheckPermission(permissionCtx, consent.OpExec, client, raw)
	if err == nil {
		err = permissionCtx.Err()
	}
	if err == nil && !time.Now().Before(arrived.Add(consent.PermissionTimeout)) {
		err = context.DeadlineExceeded
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return err
	}
	if decision != consent.AllowConnection && decision != consent.AllowGuest {
		return consent.ErrDenied
	}
	return nil
}

// Boundary IDs identify admitted explicit exec requests even when no manager
// review exists (forced commands, pregrants, custom policy, and cached grants).
var execRequestSequence atomic.Uint64

func logExecPermission(logger *slog.Logger, client consent.ClientInfo, requestID, raw string, err error) {
	outcome := "allowed"
	switch {
	case errors.Is(err, consent.ErrUnavailable):
		outcome = "unavailable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, consent.ErrTimeout):
		outcome = "timeout"
	case errors.Is(err, context.Canceled), errors.Is(err, consent.ErrCanceled):
		outcome = "canceled"
	case errors.Is(err, consent.ErrOverloaded):
		outcome = "overloaded"
	case errors.Is(err, consent.ErrStale):
		outcome = "stale"
	case errors.Is(err, consent.ErrSubjectTooLarge):
		outcome = "subject_too_large"
	case err != nil:
		outcome = "denied"
	}
	reason := ""
	if err != nil {
		reason = execLogText(err.Error())
	}
	logger.Info("exec permission policy", "outcome", outcome,
		"capability", consent.CapabilityExec, "operation", consent.OpExec,
		"subjects", []string{execLogText(raw)}, "fingerprint", execLogText(client.Fingerprint),
		"connection_id", execLogText(client.ConnectionID), "request_id", execLogText(requestID), "reason", reason)
}

func execLogText(text string) string {
	if len(text) > 256 {
		text = text[:256] + "..."
	}
	return strconv.QuoteToASCII(text)
}

// execDenialNotice is what a guest whose command won't run is told, in the
// order the audit classifies the same error. Hard policy comes before any
// grant or prompt, so only a request that could have been approved is offered
// a way to be.
func execDenialNotice(err error) string {
	switch {
	case errors.Is(err, errGuestExecDisabled):
		return "upterm: guest exec is disabled for this session.\r\n"
	case errors.Is(err, consent.ErrUnavailable):
		return "upterm: guest exec denied; nothing on the host can approve it now. The host can attach its terminal or run with --accept-exec.\r\n"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, consent.ErrTimeout):
		return "upterm: guest exec denied; the request timed out before it was approved.\r\n"
	case errors.Is(err, context.Canceled), errors.Is(err, consent.ErrCanceled):
		return "upterm: guest exec request canceled.\r\n"
	case errors.Is(err, consent.ErrOverloaded):
		return "upterm: guest exec denied; too many permission requests are waiting. Try again later.\r\n"
	case errors.Is(err, consent.ErrStale):
		return "upterm: guest exec denied; the host's answer came after the request ended.\r\n"
	case errors.Is(err, consent.ErrSubjectTooLarge):
		return fmt.Sprintf("upterm: guest exec denied; the command is longer than the %d bytes approval can show.\r\n", consent.MaxSubjectBytes)
	case errors.Is(err, consent.ErrDenied):
		return "upterm: the host denied this command.\r\n"
	}
	return "upterm: guest exec denied.\r\n"
}

func (h *sessionHandler) handlePrivateCommand(sess gssh.Session, selection guestCommandSelection, selectionErr error) {
	var auth *server.AuthRequest
	client := consent.ClientInfo{ConnectionID: sess.Context().Value(gssh.ContextKeySessionID).(string)}
	guest, isGuest := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest)
	if isGuest {
		auth = guest.auth
		if guest.key != nil {
			client.Fingerprint = utils.FingerprintSHA256(guest.key)
		}
	}
	requestID := ""
	if sessionRequestType(sess) == "exec" {
		requestID = "exec-" + strconv.FormatUint(execRequestSequence.Add(1), 10)
	}
	logPermission := func(err error) {
		if requestID != "" {
			logExecPermission(h.logger, client, requestID, selection.RawCommand, err)
		}
	}
	// Observe the original owners synchronously: context watchers may still be
	// queued when a checker or host-supplied audit sink cancels an owner.
	operationError := func() error {
		for _, owner := range []context.Context{h.ctx, h.stopCtx, sess.Context()} {
			if owner != nil {
				if err := owner.Err(); err != nil {
					return err
				}
			}
		}
		select {
		case <-channelClosed(sess):
			return context.Canceled
		default:
		}
		return nil
	}
	if h.ctx.Err() != nil || h.stopCtx != nil && h.stopCtx.Err() != nil {
		logPermission(operationError())
		h.exitLate(sess)
		return
	}
	ctx, cancel := sessionOperationContext(h.ctx, sess)
	defer cancel()
	stopKeepAlive := h.privateKeepAlive(ctx, sess)
	defer stopKeepAlive()
	var consentDeadline time.Time
	if selectionErr == nil && selection.NeedsExecConsent {
		arrived := sessionRequestReceivedAt(sess)
		if arrived.IsZero() {
			arrived = time.Now()
		}
		// Preserve pregrant/forced bypass semantics: only a request which actually
		// needs consent retains its arrival deadline through the pre-start audit.
		if !h.acceptExec {
			consentDeadline = arrived.Add(consent.PermissionTimeout)
		}
		permissionParent := ctx
		if h.stopCtx != nil {
			permissionParent = h.stopCtx
		}
		permissionCtx, releasePermission := sessionOperationContext(permissionParent, sess)
		selectionErr = h.checkExecPermission(permissionCtx, arrived, client, selection.RawCommand)
		releasePermission()
	}
	requestError := func() error {
		if err := operationError(); err != nil {
			return err
		}
		if !consentDeadline.IsZero() && !time.Now().Before(consentDeadline) {
			return context.DeadlineExceeded
		}
		return nil
	}
	exitBeforeStart := func() {
		// Preserve the original ctx-before-stop status precedence.
		if ctx.Err() == nil && h.stopCtx != nil && h.stopCtx.Err() != nil {
			h.exitLate(sess)
		} else {
			_ = sess.Exit(1)
		}
	}
	if selectionErr != nil {
		logPermission(selectionErr)
		// A request whose channel, transport or host has gone was ended by
		// that, whatever the check returned: it ends as one arriving then does.
		if operationError() != nil {
			exitBeforeStart()
			return
		}
		guestCommandDiagnostic(sess, execDenialNotice(selectionErr))
		_ = sess.Exit(1)
		return
	}
	if err := requestError(); err != nil {
		logPermission(err)
		exitBeforeStart()
		return
	}
	logPermission(nil)
	// Synchronous audit output can itself lose an owner or consent deadline.
	// Keep the final pre-start guard and correlate that outcome with this request.
	if err := requestError(); err != nil {
		logPermission(err)
		exitBeforeStart()
		return
	}
	env := withoutSSHSessionVars(append(os.Environ(), h.commandEnv...))
	env = append(env, guestConnectionEnv(auth, h.hideClientIP)...)
	if selection.ForcedExec {
		env = append(env, "SSH_ORIGINAL_COMMAND="+selection.RawCommand)
	}
	var ended, afterShutdown, observedOutcome atomic.Bool
	var observedCode atomic.Int64
	var joinedID string
	spec := guestProcessSpec{Argv: selection.Argv, Env: env, Dir: h.commandDir, ReadOnly: h.readonly,
		onWait: func(waitErr error) {
			afterShutdown.Store(h.order.commandEnded())
			code, normal := exitCode(waitErr)
			if _, sig := signalOutcome(waitErr); sig != nil {
				code, normal = 128+*sig, true
			}
			observedCode.Store(int64(code))
			observedOutcome.Store(normal)
			ended.Store(true)
		},
		onStarted: func() {
			if isGuest {
				joinedID = clientEventID(client.ConnectionID)
				emitClientJoinEvent(h.eventEmmiter, joinedID, guest.auth, guest.key)
			}
		},
	}
	if h.readonly {
		// What a read-only shared terminal says, before any of the command's
		// output. Without a terminal it goes to stderr, out of that output.
		if _, _, pty := sess.Pty(); pty {
			writeGuestNotice(sess, sess, "\r\nupterm: this session is read-only; what you type isn't sent.\r\n\r\n")
		} else {
			guestCommandDiagnostic(sess, "upterm: this session is read-only; what you type isn't sent.\r\n")
		}
	}
	runner := h.runPrivateProcess
	if runner == nil {
		runner = h.runGuestProcess
	}
	code, err := runner(ctx, sess, spec)
	if joinedID != "" {
		defer emitClientLeftEvent(h.eventEmmiter, joinedID)
	}
	if err != nil {
		h.logger.Info("guest command ended", "error", err)
		var startErr *guestProcessStartError
		if errors.As(err, &startErr) {
			code = 126
			if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
				code = 127
			}
		}
		if code == 126 || code == 127 {
			guestCommandDiagnostic(sess, "upterm: this session's command couldn't start; the host's log has why.\r\n")
		}
	}
	kind, _, _, _ := h.endingCause()
	if kind.overrides() {
		switch {
		case !ended.Load() || afterShutdown.Load():
			code = 1
		case observedOutcome.Load() && errors.Is(err, context.Canceled) && h.ctx.Err() != nil && sess.Context().Err() == nil:
			// The leader had already ended before host shutdown. Its output was
			// still draining when host cancellation reached the runner. A peer's
			// own channel/transport cancellation must still remain a failure.
			select {
			case <-channelClosed(sess):
			default:
				code = int(observedCode.Load())
			}
		}
	}
	_ = sess.Exit(code)
}

// Closing only this channel releases a blocked diagnostic write under a bound.
func guestCommandDiagnostic(sess gssh.Session, message string) {
	writeGuestNotice(sess, sess.Stderr(), message)
}

func writeGuestNotice(sess gssh.Session, dst io.Writer, message string) {
	timer := time.AfterFunc(guestFlushTimeout, func() { _ = sess.Close() })
	defer timer.Stop()
	_, _ = io.WriteString(dst, message)
}

// privateKeepAlive preserves the shared handler's keepalive requests while a
// private command waits for permission, runs, and drains. Exit precedes this
// cleanup, so a normal peer answers channel CLOSE and releases any reply wait.
func (h *sessionHandler) privateKeepAlive(parent context.Context, sess gssh.Session) func() {
	if h.keepAliveDuration <= 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() { defer close(done); _ = h.keepAlive(ctx, sess) }()
	return func() {
		cancel()
		timer := time.NewTimer(guestFlushTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-timer.C:
		}
		// A peer which neither replies nor acknowledges CLOSE cannot retain an
		// owned handler indefinitely. Transport close releases SSH request waits.
		if conn := serverConn(sess); conn != nil {
			_ = conn.Close()
		} else {
			_ = sess.Close()
		}
		<-done
	}
}
