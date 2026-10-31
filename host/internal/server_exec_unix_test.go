//go:build !windows

package internal

import (
	"bytes"
	gssh "charm.land/ssh"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type execPermissionFunc func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error)

func (f execPermissionFunc) CheckPermission(c context.Context, o consent.Operation, i consent.ClientInfo, s ...string) (consent.Decision, error) {
	return f(c, o, i, s...)
}
func (execPermissionFunc) ClearConnection(string) {}

func execSession(t *testing.T, c *ssh.Client, pty bool) *ssh.Session {
	t.Helper()
	s, e := c.NewSession()
	require.NoError(t, e)
	t.Cleanup(func() { _ = s.Close() })
	if pty {
		require.NoError(t, s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	}
	return s
}

// What a refused guest is told is all it learns: each notice names the real
// cause, and a remedy only where one could change the answer.
const (
	execDisabledNotice    = "upterm: guest exec is disabled for this session.\r\n"
	execUnavailableNotice = "upterm: guest exec denied; nothing on the host can approve it now. The host can attach its terminal or run with --accept-exec.\r\n"
	execDeniedNotice      = "upterm: the host denied this command.\r\n"
	execTimeoutNotice     = "upterm: guest exec denied; the request timed out before it was approved.\r\n"
)

func TestGuestExecSSH(t *testing.T) {
	for _, tc := range []struct{ policy, notice string }{
		{"unavailable", execUnavailableNotice},
		{"denied", execDeniedNotice},
		{"timeout", execTimeoutNotice},
		{"readonly", execDisabledNotice},
		{"no-exec", execDisabledNotice},
		{"accept-is-sftp-only", execUnavailableNotice},
	} {
		policy := tc.policy
		t.Run("denial/"+policy, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			srv := &Server{Command: readsALine("HOST", 0)}
			if policy == "denied" {
				srv.PermissionChecker = execPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
					return consent.Deny, nil
				})
			}
			if policy == "timeout" {
				srv.PermissionChecker = execPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
					return consent.Deny, consent.ErrTimeout
				})
			}
			if policy == "readonly" {
				srv.ReadOnly = true
				srv.ForceCommand = []string{"sh", "-c", `touch "$1"`, "sh", marker}
				srv.AcceptExec = true
			}
			if policy == "no-exec" {
				srv.ExecDisabled = true
				srv.ForceCommand = []string{"sh", "-c", `touch "$1"`, "sh", marker}
				srv.AcceptExec = true
			}
			if policy == "accept-is-sftp-only" {
				srv.SFTPAutoAccept = true
			}
			h := startHost(t, srv)
			s := execSession(t, h.guestClient(t), false)
			var out, stderr bytes.Buffer
			s.Stdout = &out
			s.Stderr = &stderr
			requireExitStatus(t, s.Run(fmt.Sprintf("touch %q", marker)), 1)
			require.Empty(t, out.String())
			require.Equal(t, tc.notice, stderr.String())
			_, err := os.Stat(marker)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
	t.Run("empty exec requires consent", func(t *testing.T) {
		calls := make(chan string, 1)
		h := startHost(t, &Server{Command: readsALine("HOST", 0), LoginCommand: []string{"sh", "-c", "printf LOGIN"}, PermissionChecker: execPermissionFunc(func(_ context.Context, o consent.Operation, _ consent.ClientInfo, subjects ...string) (consent.Decision, error) {
			calls <- string(o) + ":" + subjects[0]
			return consent.AllowConnection, nil
		})})
		out, err := execSession(t, h.guestClient(t), false).Output("")
		require.NoError(t, err)
		require.Empty(t, out)
		require.Equal(t, "exec:", <-calls)
	})
	t.Run("raw quoting streams status and guest env", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/sh")
		t.Setenv("SSH_ORIGINAL_COMMAND", "stale")
		t.Setenv("SSH_CLIENT", "stale")
		t.Setenv("SSH_TTY", "stale")
		h := startHost(t, &Server{Command: readsALine("HOST", 0), AcceptExec: true, CommandEnv: []string{"SSH_ORIGINAL_COMMAND=also-stale", "VALUE=override"}})
		s := execSession(t, h.guestClient(t), false)
		require.NoError(t, s.Setenv("VALUE", "guest"))
		var out, stderr bytes.Buffer
		s.Stdout = &out
		s.Stderr = &stderr
		s.Stdin = strings.NewReader("input")
		requireExitStatus(t, s.Run(`cat; printf '|%s|%s|%s|%s' 'a b|$x' "$VALUE" "${SSH_ORIGINAL_COMMAND-unset}" "${SSH_TTY-unset}"; printf error >&2; exit 7`), 7)
		require.Equal(t, "input|a b|$x|override|unset|unset", out.String())
		require.Equal(t, "error", stderr.String())
	})
	for _, raw := range []string{"", `printf "raw ' $ |"`} {
		t.Run("forced original/"+raw, func(t *testing.T) {
			h := startHost(t, &Server{Command: readsALine("HOST", 0), ForceCommand: []string{"sh", "-c", `printf '%s:%s' "${SSH_ORIGINAL_COMMAND+set}" "$SSH_ORIGINAL_COMMAND"`}})
			out, err := execSession(t, h.guestClient(t), false).Output(raw)
			require.NoError(t, err)
			require.Equal(t, "set:"+raw, string(out))
		})
	}
	for _, mode := range []string{"login", "forced"} {
		t.Run(mode+" shell", func(t *testing.T) {
			argv := []string{"sh", "-c", `printf '%s:%s' PRIVATE "${SSH_ORIGINAL_COMMAND-unset}"`}
			srv := &Server{Command: readsALine("HOST", 0), ReadOnly: true, ExecDisabled: true}
			if mode == "login" {
				srv.LoginCommand = argv
			} else {
				srv.ForceCommand = argv
			}
			h := startHost(t, srv)
			s := execSession(t, h.guestClient(t), false)
			var out bytes.Buffer
			s.Stdout = &out
			require.NoError(t, s.Shell())
			require.NoError(t, s.Wait())
			require.Equal(t, "PRIVATE:unset", out.String())
			_, hostOut, _ := h.connectHost(t, nil)
			readUntil(t, hostOut, "HOST")
		})
	}
	t.Run("concurrent private exits", func(t *testing.T) {
		h := startHost(t, &Server{Command: readsALine("HOST", 0), AcceptExec: true})
		client := h.guestClient(t)
		a, b := execSession(t, client, false), execSession(t, client, true)
		var ao, bo bytes.Buffer
		a.Stdout = &ao
		b.Stdout = &bo
		require.NoError(t, a.Start("printf first; exit 7"))
		require.NoError(t, b.Start("printf second; exit 9"))
		var wg sync.WaitGroup
		wg.Go(func() { requireExitStatus(t, a.Wait(), 7) })
		wg.Go(func() { requireExitStatus(t, b.Wait(), 9) })
		wg.Wait()
		require.Equal(t, "first", ao.String())
		require.Equal(t, "second", bo.String())
	})
	t.Run("fixed cwd after shared shell cd", func(t *testing.T) {
		launch, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		other := t.TempDir()
		h := startHost(t, &Server{Command: []string{"sh", "-c", `stty -echo; cd "$1"; printf HOST; read line`, "sh", other}, CommandDir: launch, AcceptExec: true})
		_, out, _ := h.connectHost(t, nil)
		readUntil(t, out, "HOST")
		got, err := execSession(t, h.guestClient(t), false).Output("pwd")
		require.NoError(t, err)
		require.Equal(t, launch+"\n", string(got))
	})
	t.Run("sftp ignores guest command settings", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "must-not-start")
		h := startHost(t, &Server{Command: readsALine("HOST", 0), ForceCommand: []string{"sh", "-c", `touch "$1"`, "sh", marker}, ReadOnly: true, ExecDisabled: true})
		client, err := sftp.NewClient(h.guestClient(t))
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		cwd, err := client.Getwd()
		require.NoError(t, err)
		home, err := os.UserHomeDir()
		require.NoError(t, err)
		require.Equal(t, home, cwd)
		_, err = os.Stat(marker)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("start status", func(t *testing.T) {
		for _, executable := range []bool{false, true} {
			cmd := filepath.Join(t.TempDir(), "command")
			want := 127
			if executable {
				require.NoError(t, os.WriteFile(cmd, []byte("data"), 0600))
				want = 126
			}
			h := startHost(t, &Server{Command: readsALine("HOST", 0), ForceCommand: []string{cmd}})
			s := execSession(t, h.guestClient(t), false)
			requireExitStatus(t, s.Run("ignored"), want)
		}
	})
	t.Run("cancel before approval starts no child", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "started")
		entered := make(chan context.Context, 1)
		release := make(chan struct{})
		defer close(release)
		srv := &Server{Command: readsALine("HOST", 0), PermissionChecker: execPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
			entered <- ctx
			<-release
			return consent.AllowGuest, nil
		})}
		h := startHost(t, srv)
		client := h.guestClient(t)
		s := execSession(t, client, true)
		require.NoError(t, s.Start(fmt.Sprintf("touch %q", marker)))
		ctx := <-entered
		require.NoError(t, s.Close())
		select {
		case <-ctx.Done():
		case <-time.After(harnessTimeout):
			t.Fatal("permission did not cancel")
		}
		release <- struct{}{}
		h.stop(t)
		_, err := os.Stat(marker)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

// A controlled process holds the real dispatch path beyond the permission
// deadline without waiting a minute of wall time or starting a kernel process.
func TestGuestExecConsentLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan struct{})
		h := &sessionHandler{kind: kindGuest, ctx: t.Context(), logger: discardLogger(), permissionChecker: execPermissionFunc(func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.Equal(t, time.Now().Add(consent.PermissionTimeout), deadline)
			return consent.AllowConnection, nil
		}), runPrivateProcess: func(ctx context.Context, _ gssh.Session, spec guestProcessSpec) (int, error) {
			close(started)
			select {
			case <-ctx.Done():
				t.Error("approved process inherited permission expiry")
				return 1, ctx.Err()
			case <-release:
			}
			require.NoError(t, ctx.Err())
			spec.onWait(nil)
			return 7, nil
		}}
		guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "approved"}}, exited: make(chan int, 1)}
		raw := &rawSession{Session: guest, requestType: "exec", requestReceivedAt: time.Now(), commandSelection: guestCommandSelection{NeedsExecConsent: true, Argv: []string{"controlled"}, RawCommand: "controlled"}}
		go func() { defer close(done); h.HandleSession(raw) }()
		<-started
		time.Sleep(61 * time.Second)
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("process ended at consent deadline")
		default:
		}
		close(release)
		<-done
		require.Equal(t, 7, <-guest.exited)
	})
	t.Run("arrival already expired", func(t *testing.T) {
		calls := 0
		h := &sessionHandler{permissionChecker: execPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			calls++
			return consent.AllowGuest, nil
		})}
		require.ErrorIs(t, h.checkExecPermission(t.Context(), time.Now().Add(-61*time.Second), consent.ClientInfo{}, "raw"), context.DeadlineExceeded)
		require.Zero(t, calls)
	})
	t.Run("late checker approval", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := &sessionHandler{permissionChecker: execPermissionFunc(func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
				time.Sleep(61 * time.Second)
				return consent.AllowGuest, nil
			})}
			require.ErrorIs(t, h.checkExecPermission(t.Context(), time.Now(), consent.ClientInfo{}, "raw"), context.DeadlineExceeded)
		})
	})
}

func TestGuestExecExitBeforeShutdownDuringDrain(t *testing.T) {
	for _, source := range []string{"host", "I/O", "channel"} {
		for _, after := range []bool{false, true} {
			for _, code := range []int{0, 7} {
				t.Run(fmt.Sprintf("source=%s/after=%t/code=%d", source, after, code), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						observed := make(chan struct{})
						drain := make(chan struct{})
						done := make(chan struct{})
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						order := &endOrder{}
						order.watch(ctx)
						h := &sessionHandler{kind: kindGuest, ctx: ctx, order: order, acceptExec: true, logger: discardLogger(), runPrivateProcess: func(ctx context.Context, _ gssh.Session, spec guestProcessSpec) (int, error) {
							if after {
								close(observed)
								<-drain
							}
							var waitErr error
							if code != 0 {
								waitErr = &ExitError{Code: uint32(code)}
							}
							spec.onWait(waitErr)
							if !after {
								close(observed)
								<-drain
							}
							require.ErrorIs(t, ctx.Err(), context.Canceled)
							// The controlled runner reports cancellation while its final output is held.
							if source == "I/O" {
								return 1, fmt.Errorf("output failed before status")
							}
							return 1, ctx.Err()
						}}
						guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "exit-and-stop"}}, exited: make(chan int, 1)}
						closed := make(chan struct{})
						raw := &rawSession{Session: guest, closed: closed, requestType: "exec", requestReceivedAt: time.Now(), commandSelection: guestCommandSelection{NeedsExecConsent: true, Argv: []string{"controlled"}}}
						go func() { defer close(done); h.HandleSession(raw) }()
						<-observed
						if source == "channel" {
							close(closed)
						}
						order.publish(ErrSessionStopped)
						cancel()
						close(drain)
						<-done
						want := code
						if after || source != "host" {
							want = 1
						}
						require.Equal(t, want, <-guest.exited)
					})
				})
			}
		}
	}
}

func TestGuestExecCanceledBeforeStart(t *testing.T) {
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
				called := false
				h := &sessionHandler{kind: kindGuest, ctx: ctx, stopCtx: ctx, logger: discardLogger(), runPrivateProcess: func(context.Context, gssh.Session, guestProcessSpec) (int, error) { called = true; return 0, nil }}
				guest := &exitRecordingGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "canceled-before-start"}}, exited: make(chan int, 1)}
				raw := &rawSession{Session: guest, requestType: "exec", requestReceivedAt: time.Now(), closed: closed, commandSelection: guestCommandSelection{ForcedExec: true, Argv: []string{"controlled"}}}
				h.HandleSession(raw)
				require.False(t, called, "canceled admission must not invoke the process runner")
				require.Equal(t, 1, <-guest.exited)
			})
		})
	}
}

type execKeepaliveGuest struct {
	fakeGuestSession
	requests chan string
}

func (s *execKeepaliveGuest) SendRequest(name string, wantReply bool, _ []byte) (bool, error) {
	if wantReply {
		s.requests <- name
	}
	return true, nil
}

func TestGuestExecKeepAlive(t *testing.T) {
	t.Run("deterministic tick and stop", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			guest := &execKeepaliveGuest{requests: make(chan string, 8)}
			h := &sessionHandler{keepAliveDuration: time.Second, logger: discardLogger()}
			done := make(chan error, 1)
			go func() { done <- h.keepAlive(ctx, guest) }()
			time.Sleep(time.Second)
			synctest.Wait()
			require.Equal(t, "keepalive@openssh.com", <-guest.requests)
			cancel()
			require.ErrorIs(t, <-done, context.Canceled)
			time.Sleep(2 * time.Second)
			synctest.Wait()
			require.Empty(t, guest.requests)
		})
	})
	t.Run("blocked reply releases at channel close", func(t *testing.T) {
		finished := make(chan struct{}, 2)
		h := &sessionHandler{kind: kindGuest, ctx: t.Context(), logger: discardLogger(), acceptExec: true, keepAliveDuration: time.Millisecond, privateCommands: &guestHandlers{}, sharedGuests: &guestHandlers{}}
		client := permissionServer(t, &gssh.Server{Handler: func(sess gssh.Session) { h.HandleSession(sess); finished <- struct{}{} }, SessionRequestCallback: h.admitGuest})
		channel, requests, err := client.OpenChannel("session", nil)
		require.NoError(t, err)
		defer func() { _ = channel.Close() }()
		accepted, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"cat >/dev/null"}))
		require.NoError(t, err)
		require.True(t, accepted)
		select {
		case request := <-requests:
			require.Equal(t, "keepalive@openssh.com", request.Type)
			require.True(t, request.WantReply)
		case <-time.After(harnessTimeout):
			t.Fatal("private session sent no keepalive")
		}
		// Deliberately withhold the reply; closing this channel must release its
		// synchronous SendRequest and let its owned handler finish.
		require.NoError(t, channel.Close())
		select {
		case <-finished:
		case <-time.After(harnessTimeout):
			t.Fatal("keepalive outlived channel teardown")
		}
		sibling := execSession(t, client, false)
		out, err := sibling.Output("printf sibling")
		require.NoError(t, err)
		require.Equal(t, "sibling", string(out))
		select {
		case <-finished:
		case <-time.After(harnessTimeout):
			t.Fatal("sibling handler did not finish")
		}
	})
}
