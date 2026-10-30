package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

func selectGuestCommand(requestType, raw string, p guestCommandPolicy) (guestCommandSelection, error) {
	selection := guestCommandSelection{RawCommand: raw}
	switch requestType {
	case "exec":
		if p.ReadOnly || p.ExecDisabled {
			return selection, fmt.Errorf("guest exec is disabled")
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

func (h *sessionHandler) handlePrivateCommand(sess gssh.Session, selection guestCommandSelection, selectionErr error) {
	if h.ctx.Err() != nil || h.stopCtx != nil && h.stopCtx.Err() != nil {
		h.exitLate(sess)
		return
	}
	ctx, cancel := sessionOperationContext(h.ctx, sess)
	defer cancel()
	stopKeepAlive := h.privateKeepAlive(ctx, sess)
	defer stopKeepAlive()
	var auth *server.AuthRequest
	client := consent.ClientInfo{ConnectionID: sess.Context().Value(gssh.ContextKeySessionID).(string)}
	guest, isGuest := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest)
	if isGuest {
		auth = guest.auth
		if guest.key != nil {
			client.Fingerprint = utils.FingerprintSHA256(guest.key)
		}
	}
	if selectionErr == nil && selection.NeedsExecConsent {
		arrived := sessionRequestReceivedAt(sess)
		if arrived.IsZero() {
			arrived = time.Now()
		}
		permissionParent := ctx
		if h.stopCtx != nil {
			permissionParent = h.stopCtx
		}
		permissionCtx, releasePermission := sessionOperationContext(permissionParent, sess)
		selectionErr = h.checkExecPermission(permissionCtx, arrived, client, selection.RawCommand)
		releasePermission()
	}
	if selectionErr != nil {
		h.logger.Info("guest exec denied", "reason", selectionErr)
		guestCommandDiagnostic(sess, "upterm: guest exec denied; approval in the primary host terminal or --accept-exec is required.\r\n")
		_ = sess.Exit(1)
		return
	}
	// Check original cancellation again after any custom permission checker.
	if ctx.Err() != nil {
		_ = sess.Exit(1)
		return
	}
	if h.stopCtx != nil && h.stopCtx.Err() != nil {
		h.exitLate(sess)
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
