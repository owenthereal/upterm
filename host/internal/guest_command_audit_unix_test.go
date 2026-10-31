//go:build !windows

package internal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func execAuditRecords(t *testing.T, output *recordingWriter, message string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(output.bytes())), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == message {
			records = append(records, record)
		}
	}
	return records
}

func requireExecAudit(t *testing.T, record map[string]any, outcome, raw string) string {
	t.Helper()
	require.Equal(t, "exec", record["capability"])
	require.Equal(t, "exec", record["operation"])
	require.Equal(t, outcome, record["outcome"])
	projected := raw
	if len(projected) > 256 {
		projected = projected[:256] + "..."
	}
	require.Equal(t, []any{strconv.QuoteToASCII(projected)}, record["subjects"])
	id, err := strconv.Unquote(record["request_id"].(string))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(id, "exec-"))
	require.Less(t, len(id), 128)
	if outcome == "allowed" {
		require.Empty(t, record["reason"])
	} else {
		require.NotEmpty(t, record["reason"])
	}
	return id
}

func TestGuestExecAudit(t *testing.T) {
	for _, tc := range []struct {
		name, outcome, notice                                string
		accept, force, readonly, disabled, nilChecker, empty bool
		decision                                             consent.Decision
		err                                                  error
	}{
		{name: "pregrant", outcome: "allowed", accept: true},
		{name: "forced exec", outcome: "allowed", force: true},
		{name: "empty pregranted exec", outcome: "allowed", accept: true, empty: true},
		{name: "empty forced exec", outcome: "allowed", force: true, empty: true},
		{name: "read-only before force and pregrant", outcome: "denied", notice: execDisabledNotice, readonly: true, accept: true, force: true},
		{name: "no-exec before force and pregrant", outcome: "denied", notice: execDisabledNotice, disabled: true, accept: true, force: true},
		{name: "nil checker", outcome: "unavailable", notice: execUnavailableNotice, nilChecker: true},
		{name: "custom connection grant", outcome: "allowed", decision: consent.AllowConnection},
		{name: "custom guest grant", outcome: "allowed", decision: consent.AllowGuest},
		{name: "custom denial", outcome: "denied", notice: execDeniedNotice},
		{name: "host denial", outcome: "denied", notice: execDeniedNotice, err: consent.ErrDenied},
		{name: "unavailable", outcome: "unavailable", notice: execUnavailableNotice, err: consent.ErrUnavailable},
		{name: "context timeout", outcome: "timeout", notice: execTimeoutNotice, err: context.DeadlineExceeded},
		{name: "consent timeout", outcome: "timeout", notice: execTimeoutNotice, err: consent.ErrTimeout},
		{name: "context canceled", outcome: "canceled", notice: "upterm: guest exec request canceled.\r\n", err: context.Canceled},
		{name: "consent canceled", outcome: "canceled", notice: "upterm: guest exec request canceled.\r\n", err: consent.ErrCanceled},
		{name: "overloaded", outcome: "overloaded", notice: "upterm: guest exec denied; too many permission requests are waiting. Try again later.\r\n", err: consent.ErrOverloaded},
		{name: "late answer", outcome: "stale", notice: "upterm: guest exec denied; the host's answer came after the request ended.\r\n", err: consent.ErrStale},
		{name: "subject overflow", outcome: "subject_too_large", notice: "upterm: guest exec denied; the command is longer than the 8192 bytes approval can show.\r\n", err: consent.ErrSubjectTooLarge},
		{name: "other denial", outcome: "denied", notice: "upterm: guest exec denied.\r\n", err: errors.New("checker failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &recordingWriter{}
			logger := slog.New(slog.NewJSONHandler(output, nil))
			srv := &Server{Command: readsALine("HOST", 0), Logger: logger, AcceptExec: tc.accept, ReadOnly: tc.readonly, ExecDisabled: tc.disabled}
			if tc.force {
				srv.ForceCommand = []string{"sh", "-c", "printf FORCED"}
			}
			var checked atomic.Bool
			raw := `printf '%s' 'a b|$value'`
			if tc.empty {
				raw = ""
			}
			if !tc.nilChecker {
				srv.PermissionChecker = execPermissionFunc(func(_ context.Context, op consent.Operation, client consent.ClientInfo, subjects ...string) (consent.Decision, error) {
					checked.Store(true)
					require.Equal(t, consent.OpExec, op)
					require.NotEmpty(t, client.Fingerprint)
					require.NotEmpty(t, client.ConnectionID)
					require.Equal(t, []string{raw}, subjects)
					return tc.decision, tc.err
				})
			}
			h := startHost(t, srv)
			client := h.guestClient(t)
			session := execSession(t, client, false)
			var stderr recordingWriter
			session.Stderr = &stderr
			got, err := session.Output(raw)
			if tc.outcome == "allowed" {
				require.NoError(t, err)
				want := "a b|$value"
				if tc.empty {
					want = ""
				}
				if tc.force {
					want = "FORCED"
				}
				require.Equal(t, want, string(got))
			} else {
				requireExitStatus(t, err, 1)
				require.Empty(t, got)
			}
			require.Equal(t, tc.notice, string(stderr.bytes()))
			records := execAuditRecords(t, output, "exec permission policy")
			require.Len(t, records, 1)
			requireExecAudit(t, records[0], tc.outcome, raw)
			require.Equal(t, strconv.QuoteToASCII(utils.FingerprintSHA256(h.relaySigner.PublicKey())), records[0]["fingerprint"])
			require.NotEqual(t, strconv.QuoteToASCII(utils.FingerprintSHA256(h.guestSigner.PublicKey())), records[0]["fingerprint"], "relay certificate is not guest identity")
			require.Equal(t, strconv.QuoteToASCII(hex.EncodeToString(client.SessionID())), records[0]["connection_id"])
			require.Equal(t, !tc.accept && !tc.force && !tc.readonly && !tc.disabled && !tc.nilChecker, checked.Load())
		})
	}
}

func TestGuestExecAuditManagerAndConcurrentIdentity(t *testing.T) {
	t.Run("cached grants retain separate boundary and review identities", func(t *testing.T) {
		output := &recordingWriter{}
		logger := slog.New(slog.NewJSONHandler(output, nil))
		var prompts atomic.Int32
		manager := consent.NewManager(sftpConsentPrompter(func(context.Context, consent.Prompt) (consent.Decision, error) {
			prompts.Add(1)
			return consent.AllowConnection, nil
		}), logger)
		defer manager.Close()
		h := startHost(t, &Server{Command: readsALine("HOST", 0), Logger: logger, PermissionChecker: manager})
		client := h.guestClient(t)
		for range 2 {
			got, err := execSession(t, client, false).Output("printf cached")
			require.NoError(t, err)
			require.Equal(t, "cached", string(got))
		}
		manager.Close()
		require.EqualValues(t, 1, prompts.Load())
		records := execAuditRecords(t, output, "exec permission policy")
		require.Len(t, records, 2)
		first := requireExecAudit(t, records[0], "allowed", "printf cached")
		second := requireExecAudit(t, records[1], "allowed", "printf cached")
		require.NotEqual(t, first, second)
		managed := execAuditRecords(t, output, "consent decision")
		require.Len(t, managed, 2)
		reviewID, err := strconv.Unquote(managed[0]["request_id"].(string))
		require.NoError(t, err)
		require.NotEmpty(t, reviewID)
		require.NotEqual(t, first, reviewID)
		require.NotEqual(t, second, reviewID)
	})
	t.Run("concurrent requests on one transport", func(t *testing.T) {
		output := &recordingWriter{}
		logger := slog.New(slog.NewJSONHandler(output, nil))
		h := startHost(t, &Server{Command: readsALine("HOST", 0), Logger: logger, AcceptExec: true})
		client := h.guestClient(t)
		sessions := make([]*ssh.Session, 4)
		for i := range sessions {
			sessions[i] = execSession(t, client, false)
		}
		var wg sync.WaitGroup
		for _, session := range sessions {
			wg.Go(func() {
				got, err := session.Output("printf concurrent")
				require.NoError(t, err)
				require.Equal(t, "concurrent", string(got))
			})
		}
		wg.Wait()
		records := execAuditRecords(t, output, "exec permission policy")
		require.Len(t, records, 4)
		ids := map[string]bool{}
		for _, record := range records {
			id := requireExecAudit(t, record, "allowed", "printf concurrent")
			require.False(t, ids[id])
			ids[id] = true
			require.Equal(t, records[0]["connection_id"], record["connection_id"])
			require.Equal(t, records[0]["fingerprint"], record["fingerprint"])
		}
	})
}

func TestGuestExecAuditShellControls(t *testing.T) {
	for _, mode := range []string{"shared", "login", "forced", "local attachment"} {
		t.Run(mode, func(t *testing.T) {
			output := &recordingWriter{}
			srv := &Server{Command: readsALine("HOST", 0), Logger: slog.New(slog.NewJSONHandler(output, nil)), ReadOnly: true, ExecDisabled: true}
			argv := []string{"sh", "-c", "printf chosen"}
			if mode == "login" {
				srv.LoginCommand = argv
			}
			if mode == "forced" || mode == "local attachment" {
				srv.ForceCommand = argv
			}
			h := startHost(t, srv)
			switch mode {
			case "shared":
				_, out, s := h.connectGuestSession(t)
				readUntil(t, out, "HOST")
				require.NoError(t, s.Close())
			case "local attachment":
				_, out, s := h.connectHost(t, nil)
				readUntil(t, out, "HOST")
				require.NoError(t, s.Close())
			default:
				s := execSession(t, h.guestClient(t), false)
				var out recordingWriter
				s.Stdout = &out
				require.NoError(t, s.Shell())
				require.NoError(t, s.Wait())
				require.Equal(t, "chosen", string(out.bytes()))
			}
			require.Empty(t, execAuditRecords(t, output, "exec permission policy"))
		})
	}
}

func TestGuestExecAuditBounds(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			hostile := "bad\x1b\r\n\u202e" + strings.Repeat("x", 8192) + "SECRET_TAIL"
			output := &recordingWriter{}
			var sink slog.Handler = slog.NewJSONHandler(output, nil)
			if format == "text" {
				sink = slog.NewTextHandler(output, nil)
			}
			ctx := fakeGuestContext{sessionID: hostile}
			guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: ctx, out: output}, exited: make(chan int, 1)}
			h := &sessionHandler{kind: kindGuest, ctx: t.Context(), logger: slog.New(sink), permissionChecker: execPermissionFunc(func(_ context.Context, _ consent.Operation, client consent.ClientInfo, subjects ...string) (consent.Decision, error) {
				require.Equal(t, hostile, client.ConnectionID)
				require.Equal(t, []string{hostile}, subjects)
				return consent.Deny, errors.New(hostile)
			})}
			raw := &rawSession{Session: guest, requestType: "exec", requestReceivedAt: time.Now(), commandSelection: guestCommandSelection{NeedsExecConsent: true, Argv: []string{"unused"}, RawCommand: hostile}}
			// Keep protocol stderr apart from the captured host log.
			raw.Session = &execAuditQuietSession{Session: guest}
			h.HandleSession(raw)
			require.Equal(t, 1, <-guest.exited)
			data := string(output.bytes())
			require.NotEmpty(t, data)
			require.Less(t, len(data), 4096)
			require.NotContains(t, data, "SECRET_TAIL")
			require.NotContains(t, data, "\x1b")
			require.NotContains(t, data, "\r")
			require.Equal(t, 1, strings.Count(data, "\n"))
			if format == "json" {
				records := execAuditRecords(t, output, "exec permission policy")
				require.Len(t, records, 1)
				requireExecAudit(t, records[0], "denied", hostile)
				for _, key := range []string{"connection_id", "fingerprint", "reason"} {
					projected := records[0][key].(string)
					require.Less(t, len(projected), 1600)
					for _, r := range projected {
						require.True(t, r >= 0x20 && r <= 0x7e)
					}
				}
			}
		})
	}
}

type execAuditQuietSession struct{ gssh.Session }

func (*execAuditQuietSession) Stderr() io.ReadWriter { return &bytes.Buffer{} }

type execAuditContext struct {
	fakeGuestContext
	owner context.Context
}

func (c execAuditContext) Done() <-chan struct{}       { return c.owner.Done() }
func (c execAuditContext) Err() error                  { return c.owner.Err() }
func (c execAuditContext) Deadline() (time.Time, bool) { return c.owner.Deadline() }

type execAuditHandler struct {
	slog.Handler
	onRecord func(slog.Record)
}

func (h execAuditHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.Handler.Handle(ctx, record)
	h.onRecord(record)
	return err
}
func (h execAuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return execAuditHandler{h.Handler.WithAttrs(attrs), h.onRecord}
}
func (h execAuditHandler) WithGroup(name string) slog.Handler {
	return execAuditHandler{h.Handler.WithGroup(name), h.onRecord}
}

func TestGuestExecAuditCancellationDuringLogging(t *testing.T) {
	for _, policy := range []string{"pregrant", "forced", "consent"} {
		for _, owner := range []string{"host", "stop", "transport", "channel", "deadline"} {
			t.Run(policy+"/"+owner, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					host, cancelHost := context.WithCancel(t.Context())
					defer cancelHost()
					stop, cancelStop := context.WithCancel(t.Context())
					defer cancelStop()
					transport, cancelTransport := context.WithCancel(t.Context())
					defer cancelTransport()
					closed := make(chan struct{})
					output := &recordingWriter{}
					triggered := false
					logger := slog.New(execAuditHandler{slog.NewJSONHandler(output, nil), func(record slog.Record) {
						if record.Message != "exec permission policy" || triggered {
							return
						}
						triggered = true
						switch owner {
						case "host":
							cancelHost()
						case "stop":
							cancelStop()
						case "transport":
							cancelTransport()
						case "channel":
							close(closed)
						case "deadline":
							time.Sleep(61 * time.Second)
						}
					}})
					called := false
					h := &sessionHandler{kind: kindGuest, ctx: host, stopCtx: stop, logger: logger, acceptExec: policy == "pregrant", permissionChecker: execPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
						return consent.AllowConnection, nil
					}), runPrivateProcess: func(ctx context.Context, _ gssh.Session, spec guestProcessSpec) (int, error) {
						require.NoError(t, ctx.Err())
						called = true
						spec.onWait(nil)
						return 0, nil
					}}
					selection := guestCommandSelection{NeedsExecConsent: true, Argv: []string{"controlled"}, RawCommand: "original"}
					if policy == "forced" {
						h.forceCommand = []string{"controlled"}
						selection.NeedsExecConsent = false
						selection.ForcedExec = true
					}
					guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: execAuditContext{fakeGuestContext{sessionID: "audit-connection"}, transport}}, exited: make(chan int, 1)}
					raw := &rawSession{Session: guest, closed: closed, requestType: "exec", requestReceivedAt: time.Now(), commandSelection: selection}
					h.HandleSession(raw)
					allowed := owner == "deadline" && policy != "consent"
					require.Equal(t, allowed, called, "owner/deadline lost inside synchronous audit must prevent process start")
					code := <-guest.exited
					if allowed {
						require.Zero(t, code)
					} else {
						require.Equal(t, 1, code)
					}
					records := execAuditRecords(t, output, "exec permission policy")
					require.NotEmpty(t, records)
					first := requireExecAudit(t, records[0], "allowed", "original")
					if allowed {
						require.Len(t, records, 1)
					} else {
						require.Len(t, records, 2)
						outcome := "canceled"
						if owner == "deadline" {
							outcome = "timeout"
						}
						require.Equal(t, first, requireExecAudit(t, records[1], outcome, "original"), "same boundary identity must correlate the lost owner with the initial audit")
					}
				})
			})
		}
	}
}

func TestGuestExecAuditCanceledBeforeHandler(t *testing.T) {
	for _, source := range []string{"host", "channel"} {
		t.Run(source, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				closed := make(chan struct{})
				if source == "host" {
					cancel()
				} else {
					close(closed)
				}
				output := &recordingWriter{}
				called := false
				h := &sessionHandler{kind: kindGuest, ctx: ctx, stopCtx: ctx, logger: slog.New(slog.NewJSONHandler(output, nil)), acceptExec: true, runPrivateProcess: func(context.Context, gssh.Session, guestProcessSpec) (int, error) { called = true; return 0, nil }}
				guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "canceled"}}, exited: make(chan int, 1)}
				raw := &rawSession{Session: &execAuditQuietSession{Session: guest}, closed: closed, requestType: "exec", requestReceivedAt: time.Now(), commandSelection: guestCommandSelection{NeedsExecConsent: true, Argv: []string{"controlled"}, RawCommand: "original"}}
				h.HandleSession(raw)
				require.False(t, called)
				require.Equal(t, 1, <-guest.exited)
				records := execAuditRecords(t, output, "exec permission policy")
				require.Len(t, records, 1)
				requireExecAudit(t, records[0], "canceled", "original")
			})
		})
	}
}

// A request still waiting for approval when the host stops was ended by the
// stop, not refused by policy. It is told nothing about approval, and its
// status is the one any client arriving as the session ends gets: 1 for a
// stop, 0 after a join timeout.
func TestGuestExecConsentEndedByHostStop(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		code  int
	}{
		{"stopped", ErrSessionStopped, 1},
		{"join timeout", ErrJoinTimeout, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stop, cancelStop := context.WithCancelCause(t.Context())
				defer cancelStop(nil)
				asked := make(chan struct{})
				output := &recordingWriter{}
				called := false
				h := &sessionHandler{kind: kindGuest, ctx: t.Context(), stopCtx: stop, logger: slog.New(slog.NewJSONHandler(output, nil)), permissionChecker: execPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
					close(asked)
					<-ctx.Done()
					return consent.Deny, consent.ErrCanceled
				}), runPrivateProcess: func(context.Context, gssh.Session, guestProcessSpec) (int, error) { called = true; return 0, nil }}
				notices := &recordingWriter{}
				guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "stopping"}, out: notices}, exited: make(chan int, 1)}
				raw := &rawSession{Session: guest, closed: make(chan struct{}), requestType: "exec", requestReceivedAt: time.Now(), commandSelection: guestCommandSelection{NeedsExecConsent: true, Argv: []string{"controlled"}, RawCommand: "original"}}
				handled := make(chan struct{})
				go func() { defer close(handled); h.HandleSession(raw) }()
				<-asked
				cancelStop(tc.cause)
				<-handled
				require.False(t, called)
				require.Equal(t, tc.code, <-guest.exited)
				require.Empty(t, string(notices.bytes()))
				records := execAuditRecords(t, output, "exec permission policy")
				require.Len(t, records, 1)
				requireExecAudit(t, records[0], "canceled", "original")
			})
		})
	}
}
