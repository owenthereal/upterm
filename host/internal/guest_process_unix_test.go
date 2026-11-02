//go:build !windows

package internal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type guestProcessResult struct {
	code int
	err  error
}

func guestProcessSession(t *testing.T, spec guestProcessSpec, pty bool, after func(gssh.Session), setup ...func(gssh.Session)) (*ssh.Session, <-chan guestProcessResult, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	results := make(chan guestProcessResult, 1)
	h := &sessionHandler{logger: discardLogger(), timing: serverTiming{hangup: 50 * time.Millisecond, forceCommandStop: 50 * time.Millisecond}}
	client := permissionServer(t, &gssh.Server{Handler: func(sess gssh.Session) {
		for _, f := range setup {
			f(sess)
		}
		op, release := sessionOperationContext(ctx, sess)
		defer release()
		code, err := h.runGuestProcess(op, sess, spec)
		results <- guestProcessResult{code, err}
		if after != nil {
			after(sess)
		}
		_ = sess.Exit(code)
	}})
	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	if pty {
		require.NoError(t, sess.RequestPty("guest-term", 31, 97, ssh.TerminalModes{}))
	}
	return sess, results, cancel
}

func guestResult(t *testing.T, results <-chan guestProcessResult) guestProcessResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(8 * time.Second):
		t.Fatal("private process runner did not return")
		return guestProcessResult{}
	}
}

func guestShell(script string) guestProcessSpec {
	return guestProcessSpec{Argv: []string{"/bin/sh", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}}
}

func TestGuestProcessPipes(t *testing.T) {
	t.Run("binary streams status and stdin EOF", func(t *testing.T) {
		spec := guestShell(`cat >/dev/null; printf 'a\000\n\377'; printf 'error\n' >&2; exit 7`)
		sess, results, _ := guestProcessSession(t, spec, false, nil)
		var out, stderr bytes.Buffer
		sess.Stdout, sess.Stderr = &out, &stderr
		in, err := sess.StdinPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Start("ignored"))
		_, err = io.WriteString(in, "input")
		require.NoError(t, err)
		require.NoError(t, in.Close())
		err = sess.Wait()
		var exit *ssh.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, 7, exit.ExitStatus())
		require.Equal(t, []byte{'a', 0, '\n', 0xff}, out.Bytes())
		require.Equal(t, "error\n", stderr.String())
		r := guestResult(t, results)
		require.NoError(t, r.err)
		require.Equal(t, 7, r.code)
	})
	t.Run("final output exceeds SSH window", func(t *testing.T) {
		spec := guestShell(`head -c 4194304 /dev/zero; exit 7`)
		sess, results, _ := guestProcessSession(t, spec, false, nil)
		var out bytes.Buffer
		sess.Stdout = &out
		err := sess.Run("ignored")
		var exit *ssh.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, 7, exit.ExitStatus())
		require.Equal(t, 4<<20, out.Len())
		require.NoError(t, guestResult(t, results).err)
	})
	t.Run("read only closes stdin", func(t *testing.T) {
		spec := guestShell(`cat; printf EOF`)
		spec.ReadOnly = true
		sess, results, _ := guestProcessSession(t, spec, false, nil)
		sess.Stdin = strings.NewReader("must not reach child")
		out, err := sess.Output("ignored")
		require.NoError(t, err)
		require.Equal(t, "EOF", string(out))
		require.NoError(t, guestResult(t, results).err)
	})
	for _, name := range []string{"missing executable", "canceled startup", "empty argv"} {
		t.Run(name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			spec := guestShell(`echo started > "$1"`)
			spec.Argv = append(spec.Argv, "sh", marker)
			if name == "missing executable" {
				spec.Argv = []string{filepath.Join(t.TempDir(), "missing")}
			}
			if name == "empty argv" {
				spec.Argv = nil
			}
			sess, results, cancel := guestProcessSession(t, spec, false, nil)
			if name == "canceled startup" {
				cancel()
			}
			_ = sess.Run("ignored")
			r := guestResult(t, results)
			require.Error(t, r.err)
			require.NotZero(t, r.code)
			_, err := os.Stat(marker)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
	t.Run("cancellation precedes executable lookup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		code, err := (&sessionHandler{}).runGuestProcess(ctx, nil, guestProcessSpec{Argv: []string{"/missing/executable"}})
		require.Equal(t, 1, code)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("complete environment and cwd", func(t *testing.T) {
		for _, hide := range []bool{false, true} {
			env := append(withoutHostSessionVars([]string{"PATH=/usr/bin:/bin", "VALUE=first", "VALUE=last", "SSH_TTY=stale", "SSH_CLIENT=stale"}), guestConnectionEnv(&server.AuthRequest{RemoteAddr: "203.0.113.7:1234", LocalAddr: "198.51.100.1:22"}, hide)...)
			env = append(env, "SSH_ORIGINAL_COMMAND=raw original", "SSH_TTY=must disappear")
			spec := guestShell(`printf '%s|%s|%s|%s|%s' "$VALUE" "${SSH_TTY-unset}" "${SSH_CLIENT-unset}" "$SSH_ORIGINAL_COMMAND" "$PWD"`)
			spec.Env = env
			dir, err := filepath.EvalSymlinks(t.TempDir())
			spec.Dir = dir
			require.NoError(t, err)
			sess, results, _ := guestProcessSession(t, spec, false, nil)
			out, err := sess.Output("ignored")
			require.NoError(t, err)
			client := "203.0.113.7 1234 22"
			if hide {
				client = "unset"
			}
			require.Equal(t, "last|unset|"+client+"|raw original|"+spec.Dir, string(out))
			require.NoError(t, guestResult(t, results).err)
		}
	})
}

func TestGuestProcessPTY(t *testing.T) {
	t.Run("terminal env geometry and resize", func(t *testing.T) {
		spec := guestShell(`stty -echo -opost; printf '%s|%s|%s\n' "$TERM" "$SSH_TTY" "$(tty)"; stty size; while [ "$(stty size)" != "42 113" ]; do :; done; printf "RESIZED\n"; read line; stty size; exit 7`)
		spec.Env = append(spec.Env, "TERM=host", "SSH_TTY=stale")
		sess, results, _ := guestProcessSession(t, spec, true, nil)
		out, err := sess.StdoutPipe()
		require.NoError(t, err)
		in, err := sess.StdinPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Start("ignored"))
		reader := bufio.NewReader(out)
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		parts := strings.Split(strings.TrimSpace(line), "|")
		require.Len(t, parts, 3)
		require.Equal(t, "guest-term", parts[0])
		require.Equal(t, parts[2], parts[1])
		require.True(t, strings.HasPrefix(parts[1], "/dev/"))
		line, err = reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "31 97\n", line)
		require.NoError(t, sess.WindowChange(42, 113))
		line, err = reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "RESIZED\n", line)
		_, err = io.WriteString(in, "go\n")
		require.NoError(t, err)
		line, err = reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "42 113\n", line)
		_ = sess.Wait()
		r := guestResult(t, results)
		require.NoError(t, r.err)
		require.Equal(t, 7, r.code)
	})
	t.Run("read only ignores guest input", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "input")
		spec := guestShell(`stty -echo; printf READY; read line; echo "$line" > "$1"`)
		spec.Argv = append(spec.Argv, "sh", marker)
		spec.ReadOnly = true
		sess, results, cancel := guestProcessSession(t, spec, true, nil)
		out, err := sess.StdoutPipe()
		require.NoError(t, err)
		in, err := sess.StdinPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Start("ignored"))
		ready := make([]byte, 5)
		_, err = io.ReadFull(out, ready)
		require.NoError(t, err)
		require.Equal(t, "READY", string(ready))
		_, err = io.WriteString(in, "forbidden\n")
		require.NoError(t, err)
		cancel()
		r := guestResult(t, results)
		require.NotZero(t, r.code)
		_, err = os.Stat(marker)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestGuestProcessShutdown(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked input pty=%v", pty), func(t *testing.T) {
			spec := guestShell(`trap '' HUP TERM; printf READY; exec sleep 60`)
			sess, results, cancel := guestProcessSession(t, spec, pty, nil)
			out, err := sess.StdoutPipe()
			require.NoError(t, err)
			in, err := sess.StdinPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Start("ignored"))
			ready := make([]byte, 5)
			_, err = io.ReadFull(out, ready)
			require.NoError(t, err)
			written := make(chan struct{})
			go func() { defer close(written); _, _ = in.Write(bytes.Repeat([]byte("x"), 8<<20)) }()
			cancel()
			r := guestResult(t, results)
			require.Error(t, r.err)
			require.NotZero(t, r.code)
			_ = sess.Close()
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Fatal("stdin writer not released")
			}
		})
	}
	t.Run("unread output cannot hold cancellation", func(t *testing.T) {
		blocked := make(chan struct{})
		sess, results, cancel := guestProcessSession(t, guestShell(`printf READY; exec yes x`), false, nil, func(s gssh.Session) {
			raw := s.(*rawSession)
			raw.channel = &guestWindowObserver{Channel: raw.channel, blocked: blocked}
		})
		out, err := sess.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Start("ignored"))
		ready := make([]byte, 5)
		_, err = io.ReadFull(out, ready)
		require.NoError(t, err)
		select {
		case <-blocked:
		case <-time.After(3 * time.Second):
			t.Fatal("child output did not fill SSH receive window")
		}
		cancel()
		r := guestResult(t, results)
		require.NotZero(t, r.code)
	})
	t.Run("supported signal", func(t *testing.T) {
		sess, results, _ := guestProcessSession(t, guestShell(`printf READY; exec sleep 60`), false, nil)
		out, err := sess.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Start("ignored"))
		ready := make([]byte, 5)
		_, err = io.ReadFull(out, ready)
		require.NoError(t, err)
		require.NoError(t, sess.Signal(ssh.SIGTERM))
		r := guestResult(t, results)
		require.NoError(t, r.err)
		require.Equal(t, 143, r.code)
	})
}

func TestGuestProcessLeaderExit(t *testing.T) {
	t.Run("descendant retains output", func(t *testing.T) {
		// Have a real runner leader spawn a holder, publishing its PID before exit.
		pidfile := filepath.Join(t.TempDir(), "pid")
		spec := guestShell(`sleep 60 & echo $! > "$1"; printf tail; exit 7`)
		spec.Argv = append(spec.Argv, "sh", pidfile)
		t.Cleanup(func() {
			b, e := os.ReadFile(pidfile)
			if e == nil {
				pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
				if e == nil {
					p, _ := os.FindProcess(pid)
					_ = p.Kill()
				}
			}
		})
		sess, results, _ := guestProcessSession(t, spec, false, nil)
		started := time.Now()
		out, err := sess.Output("ignored")
		var exit *ssh.ExitError
		require.ErrorAs(t, err, &exit)
		require.Equal(t, "tail", string(out))
		r := guestResult(t, results)
		require.NoError(t, r.err)
		require.Equal(t, 7, r.code)
		require.LessOrEqual(t, time.Since(started), forceCommandDrainTimeout+2*time.Second)
	})
	t.Run("signal flood remains drained until channel close", func(t *testing.T) {
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		closed := make(chan struct{})
		sess, results, _ := guestProcessSession(t, guestShell("exit 7"), false, func(s gssh.Session) { <-channelClosed(s); close(closed); <-hold })
		require.NoError(t, sess.Start("ignored"))
		r := guestResult(t, results)
		require.NoError(t, r.err)
		require.Equal(t, 7, r.code)
		for range 256 {
			require.NoError(t, sess.Signal(ssh.SIGTERM))
		}
		require.NoError(t, sess.Close())
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("signals blocked observing channel CLOSE")
		}
	})
}

// pipeGuest is a guest without a terminal whose output writes the test can
// hold, standing in for a guest that has stopped taking output.
type pipeGuest struct {
	fakeGuestSession
	hold, writing chan struct{} // nil: writes don't wait
	once          sync.Once
	mu            sync.Mutex
	output        bytes.Buffer
}

func (g *pipeGuest) Pty() (gssh.Pty, <-chan gssh.Window, bool) { return gssh.Pty{}, nil, false }
func (g *pipeGuest) Stderr() io.ReadWriter                     { return g }
func (g *pipeGuest) Write(p []byte) (int, error) {
	if g.hold != nil {
		g.once.Do(func() { close(g.writing) })
		<-g.hold
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.output.Write(p)
}
func (g *pipeGuest) written() string { g.mu.Lock(); defer g.mu.Unlock(); return g.output.String() }

// ptyGuest is a pipeGuest with a terminal.
type ptyGuest struct{ *pipeGuest }

func (g ptyGuest) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "xterm"}, nil, true
}

// The drain cuts off whatever output the guest hasn't taken when it gives up:
// the pipes' at their bound, and a terminal's at its own, or once nothing has
// been read from it or written to the guest for a while. A copy still writing
// to the guest as the drain gives up means some of it was cut, even if that
// write then finishes inside the close's idle window, so the command can't
// report success. A write the guest takes before the bound has delivered its
// output, however long it was held. A copy waiting to read has passed on all
// it was given: a background child holding the pipe or the terminal open
// leaves the leader's status alone, and a terminal's drain gives up on that
// once it is quiet, well inside the bound.
func TestGuestProcessDrainBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		// hold is when the guest takes the copy's first write: at once (""),
		// once the drain gives up ("bound"), or a while after the leader's
		// exit, well inside the bound ("early").
		hold        string
		bound       bool
		code        int
		undelivered bool
	}{
		{"write held across the bound", `printf data; exit 0`, "bound", true, 1, true},
		{"write taken before the bound", `printf data; exit 0`, "early", false, 0, false},
		// It ignores the hangup a terminal's leader sends its group on exit.
		{"descendant holds the output", `trap '' HUP; sleep 60 & echo $! > "$1"; printf data; exit 0`, "", true, 0, false},
		{"output reaches EOF", `printf data; exit 0`, "", false, 0, false},
	} {
		for _, pty := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pty=%v", tc.name, pty), func(t *testing.T) {
				// With no write held, only a descendant holding the output open
				// makes the drain give up, and only Linux lets one hold a
				// terminal open past its session leader.
				if pty && tc.bound && tc.hold == "" && runtime.GOOS != "linux" {
					t.Skip("XNU revokes a terminal as its session leader exits, so no descendant holds it open")
				}
				pidfile := filepath.Join(t.TempDir(), "pid")
				t.Cleanup(func() {
					if b, err := os.ReadFile(pidfile); err == nil {
						if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
							p, _ := os.FindProcess(pid)
							_ = p.Kill()
						}
					}
				})
				guest := &pipeGuest{}
				if tc.hold != "" {
					guest.hold, guest.writing = make(chan struct{}), make(chan struct{})
				}
				var sess gssh.Session = guest
				if pty {
					sess = ptyGuest{guest}
				}
				spec := guestShell(tc.script)
				spec.Argv = append(spec.Argv, "sh", pidfile)
				var reaped, gaveUp time.Time
				spec.onWait = func(error) {
					reaped = time.Now()
					if tc.hold == "early" {
						// Long past the quiet that ends a drain with nothing
						// written, and well inside the bound.
						time.AfterFunc(500*time.Millisecond, func() { close(guest.hold) })
					}
				}
				fired := false
				spec.onDrainBound = func() {
					fired, gaveUp = true, time.Now()
					if tc.hold == "bound" {
						select {
						case <-guest.writing:
						default:
							t.Error("no write to the guest was waiting at the bound")
						}
						close(guest.hold)
					}
				}
				h := &sessionHandler{logger: discardLogger(), timing: serverTiming{hangup: 50 * time.Millisecond, forceCommandStop: 50 * time.Millisecond}}
				code, err := h.runGuestProcess(t.Context(), sess, spec)
				require.Equal(t, tc.code, code)
				if tc.undelivered {
					require.ErrorContains(t, err, "guest output did not drain")
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, tc.bound, fired, "whether the drain gave up")
				require.Equal(t, "data", guest.written())
				if fired {
					// A terminal's drain gives up on quiet only with no write
					// under way; the pipes' only ever at their bound.
					if tc.hold == "bound" || !pty {
						require.GreaterOrEqual(t, gaveUp.Sub(reaped), forceCommandDrainTimeout, "the drain gave up before its bound")
					} else {
						require.Less(t, gaveUp.Sub(reaped), forceCommandDrainTimeout, "a quiet terminal's drain waited for its bound")
					}
				}
			})
		}
	}
}

// A teardown that has had to kill its leader waits for the kernel to reap it:
// a runner that has returned leaves no leader behind, however late after the
// kill the reap comes, as long as it comes within the runner's bound.
func TestGuestProcessTeardownAwaitsTheReap(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(fmt.Sprintf("pty=%v", pty), func(t *testing.T) {
			reap := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(reap) }) }
			t.Cleanup(release)
			// Ignores the hangup and SIGTERM, so only the kill ends it.
			spec := guestShell(`trap '' HUP TERM; printf 'READY %s;' $$; exec sleep 60`)
			spec.beforeWait = func() { <-reap }
			// The reap comes only once the runner is waiting for it.
			var awaited atomic.Bool
			spec.onReapWait = func() { awaited.Store(true); release() }
			sess, results, cancel := guestProcessSession(t, spec, pty, nil)
			out, err := sess.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Start("ignored"))
			seen := readUntil(t, out, ";")
			pid, err := strconv.Atoi(strings.TrimSuffix(seen[strings.Index(seen, "READY ")+len("READY "):], ";"))
			require.NoError(t, err)
			cancel()
			r := guestResult(t, results)
			require.True(t, awaited.Load(), "runner returned without waiting for its killed leader's reap")
			require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH, "runner returned with its leader unreaped")
			require.NotContains(t, fmt.Sprint(r.err), "did not exit during cleanup")
			require.NotZero(t, r.code)
		})
	}
}

// A leader the escalation can't get reaped -- one that is root under sudo
// refuses every signal, and the kernel can hold a killed one in exit -- still
// ends its private command within the session's wait for private commands:
// the runner reports it as not having exited, the guest is sent 1, and the
// handler gives up its admission.
func TestGuestExecUnreapedLeaderStillEnds(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	timings := []struct {
		name   string
		timing serverTiming
	}{
		{"default", serverTiming{}},
		{"50ms", serverTiming{hangup: 50 * time.Millisecond, forceCommandStop: 50 * time.Millisecond}},
		{"40ms", serverTiming{hangup: 40 * time.Millisecond, forceCommandStop: 80 * time.Millisecond}},
		{"80ms", serverTiming{hangup: 80 * time.Millisecond, forceCommandStop: 160 * time.Millisecond}},
	}
	for _, tc := range timings {
		for _, pty := range []bool{false, true} {
			t.Run(fmt.Sprintf("timing=%s/pty=%v", tc.name, pty), func(t *testing.T) { testUnreapedLeaderStillEnds(t, tc.timing, pty) })
		}
	}
}

func testUnreapedLeaderStillEnds(t *testing.T, timing serverTiming, pty bool) {
	// Never released while the runner waits: as far as the runner can
	// tell, its leader can't be killed.
	hold := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(hold) }) })
	stop, cancelStop := context.WithCancelCause(t.Context())
	defer cancelStop(nil)
	sessCtx, endSession := context.WithCancel(sessionContext(stop))
	defer endSession()
	results := make(chan guestProcessResult, 1)
	h := &sessionHandler{kind: kindGuest, ctx: sessCtx, stopCtx: stop, acceptExec: true, timing: timing, logger: discardLogger(), privateCommands: &guestHandlers{}, sharedGuests: &guestHandlers{}}
	h.runPrivateProcess = func(ctx context.Context, sess gssh.Session, spec guestProcessSpec) (int, error) {
		spec.beforeWait = func() { <-hold }
		code, err := h.runGuestProcess(ctx, sess, spec)
		results <- guestProcessResult{code, err}
		return code, err
	}
	client := permissionServer(t, &gssh.Server{Handler: h.HandleSession, SessionRequestCallback: h.admitGuest})
	s, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	if pty {
		require.NoError(t, s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	}
	out, err := s.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, s.Start(`trap '' HUP TERM; printf 'READY;'; exec sleep 60`))
	readUntil(t, out, "READY;")
	// The host stops, and the session's end waits for its private
	// commands as the server's does.
	resolved := timing.orDefault()
	bound := forceCommandStopBound(resolved.hangup, resolved.forceCommandStop)
	stopped := time.Now()
	cancelStop(ErrSessionStopped)
	endSession()
	require.True(t, h.privateCommands.wait(bound), "the session's end gave up waiting for the private command")
	t.Logf("private command ended %v into the session's %v wait", time.Since(stopped).Round(time.Millisecond), bound)
	r := <-results
	require.Equal(t, 1, r.code)
	require.ErrorContains(t, r.err, "guest command did not exit during cleanup")
	requireExitStatus(t, s.Wait(), 1)
}

func TestGuestProcessExitDuringEscalation(t *testing.T) {
	t.Run("late signals never reach the reaped group", func(t *testing.T) {
		fake := newSignalPTY(0)
		owner := &guestProcessOwner{PTY: fake}
		close(fake.exited)
		require.NoError(t, owner.Wait())
		for range 256 {
			_ = owner.Signal(syscall.SIGTERM)
		}
		_ = owner.Kill()
		require.Zero(t, len(fake.signals), "group signals after leader reap")
		require.False(t, fake.killed)
	})

	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			fake := newSignalPTY(sig)
			owner := &guestProcessOwner{PTY: fake}
			reaped := make(chan struct{})
			go func() { _ = owner.Wait(); close(reaped) }()
			terminateWith(owner, newPTYCloser(owner), reaped, time.Millisecond, time.Millisecond, discardLogger(), "guest")
			require.Equal(t, sig, fake.signals[len(fake.signals)-1])
			require.False(t, fake.killed)
			before := len(fake.signals)
			terminateWith(owner, newPTYCloser(owner), reaped, time.Millisecond, time.Millisecond, discardLogger(), "guest")
			require.Equal(t, before, len(fake.signals), "no group signals after leader reap")
		})
	}
}

// The client drains only READY. A write crossing the SSH initial window has
// demonstrably exhausted that peer's credit; this barrier needs no sleeps.
type guestWindowObserver struct {
	ssh.Channel
	written int
	once    sync.Once
	blocked chan struct{}
}

func (c *guestWindowObserver) Write(b []byte) (int, error) {
	if c.written+len(b) > 2<<20 {
		c.once.Do(func() { close(c.blocked) })
	}
	n, err := c.Channel.Write(b)
	c.written += n
	return n, err
}

func TestGuestProcessPipeHandles(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	pipes, err := startGuestPipes(cmd)
	require.NoError(t, err)
	defer func() { _ = pipes.Close() }()
	require.Error(t, pipes.Wait())
	require.NoError(t, pipes.Close())
	require.NoError(t, pipes.Close())
	for _, f := range []*os.File{pipes.stdin, pipes.stdout, pipes.stderr} {
		_, err := f.Stat()
		require.ErrorIs(t, err, os.ErrClosed)
	}
}

// Charm may already have queued signals while the process was starting.
// Registration asynchronously delivers that queue, alongside new requests.
func TestGuestProcessSignalRegistration(t *testing.T) {
	ready, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	sess, results, _ := guestProcessSession(t, guestShell("exit 7"), false, nil, func(gssh.Session) { close(ready); <-release })
	require.NoError(t, sess.Start("ignored"))
	<-ready
	for range 32 {
		require.NoError(t, sess.Signal(ssh.Signal("UNKNOWN")))
	}
	// Signal requests have no reply in Charm. An unsupported request behind
	// them is a barrier proving the request loop consumed the queued signals.
	ok, err := sess.SendRequest("upterm-test-barrier", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	releaseOnce.Do(func() { close(release) })
	r := guestResult(t, results)
	require.NoError(t, r.err)
	require.Equal(t, 7, r.code)
}

func TestGuestProcessReadOnlySignals(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(fmt.Sprintf("pty=%v", pty), func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "release")
			require.NoError(t, syscall.Mkfifo(fifo, 0600))
			gate, err := os.OpenFile(fifo, os.O_RDWR, 0600)
			require.NoError(t, err)
			defer func() { _ = gate.Close() }()
			spec := guestShell(`trap 'exit 9' TERM; printf READY; read line < "$1"; exit 7`)
			spec.Argv = append(spec.Argv, "sh", fifo)
			spec.ReadOnly = true
			sess, results, _ := guestProcessSession(t, spec, pty, nil)
			output, err := sess.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Start("ignored"))
			ready := make([]byte, 5)
			_, err = io.ReadFull(output, ready)
			require.NoError(t, err)
			// More than the signal buffer forces the runner to consume signals before
			// Charm can answer the following barrier. Only the test-owned FIFO permits
			// the child to finish successfully.
			for range 256 {
				require.NoError(t, sess.Signal(ssh.SIGTERM))
			}
			ok, err := sess.SendRequest("upterm-test-barrier", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			_, err = io.WriteString(gate, "go\n")
			require.NoError(t, err)
			r := guestResult(t, results)
			require.NoError(t, r.err)
			require.Equal(t, 7, r.code, "readonly guests must not control the selected command with signals")
		})
	}
}

// Hold the runner exactly between registration and starting its consumer. The
// real Charm worker is then flushing a full pre-registration backlog when the
// channel/transport closes; TestMain's goleak check verifies that worker exits.
func TestGuestProcessQueuedSignalsTeardown(t *testing.T) {
	for _, transport := range []bool{false, true} {
		t.Run(fmt.Sprintf("transport=%v", transport), func(t *testing.T) {
			ready, release, registered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			var closeTransport func() error
			sess, results, _ := guestProcessSession(t, guestShell("exit 7"), false, nil, func(s gssh.Session) {
				raw := s.(*rawSession)
				closeTransport = serverConn(raw).Close
				raw.Session = &guestRegistrationBarrier{Session: raw.Session, registered: registered, closed: raw.closed}
				close(ready)
				<-release
			})
			require.NoError(t, sess.Start("ignored"))
			<-ready
			for range 128 {
				require.NoError(t, sess.Signal(ssh.Signal("UNKNOWN")))
			}
			ok, err := sess.SendRequest("upterm-test-barrier", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			releaseOnce.Do(func() { close(release) })
			select {
			case <-registered:
			case <-time.After(time.Second):
				t.Fatal("runner did not register signals")
			}
			if transport {
				_ = closeTransport()
			} else {
				_ = sess.Close()
			}
			_ = guestResult(t, results)
		})
	}
}

type guestRegistrationBarrier struct {
	gssh.Session
	registered chan struct{}
	closed     <-chan struct{}
}

func (s *guestRegistrationBarrier) Signals(c chan<- gssh.Signal) {
	s.Session.Signals(c)
	close(s.registered)
	<-s.closed
}

// The holder can see stdin EOF only after the runner leaves its first select:
// the client's stdin stays open, and the holder explicitly inherits the pipe.
// DRAIN therefore proves Wait won and post-select draining started before the
// test cancels the channel/transport. The holder exits through an owned FIFO,
// without signaling any PID remembered after the leader has been reaped.
func TestGuestProcessCancellationAfterWait(t *testing.T) {
	for _, transport := range []bool{false, true} {
		t.Run(fmt.Sprintf("transport=%t", transport), func(t *testing.T) {
			dir := t.TempDir()
			gatePath := filepath.Join(dir, "release")
			finishedPath := filepath.Join(dir, "holder-finished")
			require.NoError(t, syscall.Mkfifo(gatePath, 0600))
			gate, err := os.OpenFile(gatePath, os.O_RDWR, 0600)
			require.NoError(t, err)
			defer func() {
				defer func() { _ = gate.Close() }()
				_, _ = io.WriteString(gate, "finish\n")
				require.Eventually(t, func() bool { _, err := os.Stat(finishedPath); return err == nil }, harnessTimeout, time.Millisecond, "owned output holder did not finish after release")
			}()
			spec := guestShell(`exec 3<&0; sh -c 'cat >/dev/null; printf DRAIN; IFS= read -r release < "$1"; : > "$2"' sh "$1" "$2" <&3 3<&- & exit 0`)
			spec.Argv = append(spec.Argv, "sh", gatePath, finishedPath)
			waited := make(chan error, 1)
			spec.onWait = func(err error) { waited <- err }
			connection := make(chan func() error, 1)
			sess, results, _ := guestProcessSession(t, spec, false, nil, func(s gssh.Session) { connection <- serverConn(s).Close })
			input, err := sess.StdinPipe()
			require.NoError(t, err)
			defer func() { _ = input.Close() }()
			output, err := sess.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Start("ignored"))
			closeTransport := <-connection
			marker := make([]byte, len("DRAIN"))
			_, err = io.ReadFull(output, marker)
			require.NoError(t, err)
			require.Equal(t, "DRAIN", string(marker))
			require.NoError(t, <-waited, "the actual runner leader must have exited zero before cancellation")
			if transport {
				require.NoError(t, closeTransport())
			} else {
				require.NoError(t, sess.Close())
			}
			result := guestResult(t, results)
			assert.NotZero(t, result.code, "channel/transport cancellation during draining must not report success")
			assert.ErrorIs(t, result.err, context.Canceled, "the real runner must propagate post-Wait operation cancellation")
		})
	}
}
