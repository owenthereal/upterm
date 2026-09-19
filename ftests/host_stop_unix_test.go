//go:build !windows

package ftests

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// attachInteractive attaches a client with a pty and an input pipe — the
// shape upterm attach has on a terminal — and drains its output, which a
// primary's synchronous writer requires. It returns the input's write end.
func (r *outcomeRun) attachInteractive(t *testing.T, ctx context.Context, socket string) io.Writer {
	t.Helper()
	rec := r.record(t)
	keys := make([]ssh.PublicKey, 0, len(rec.HostKeys))
	for _, k := range rec.HostKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		require.NoError(t, err)
		keys = append(keys, key)
	}
	inR, inW := io.Pipe()
	client := &attach.Client{
		Socket: socket, HostKeys: keys, Stdin: inR, Stdout: io.Discard, Logger: testLogger,
		Pty: &attach.Pty{Term: "xterm", Size: termsize.Size{Cols: 80, Rows: 24}},
	}
	go func() { _, _ = client.Run(ctx) }()
	return inW
}

func awaitPidFile(t *testing.T, path string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && pid > 0
	}, outcomeTimeout, 20*time.Millisecond, "no pid was written to %s", path)
	return pid
}

// processGone: the pid no longer names a running process. A zombie counts
// as gone — on Linux under a PID 1 that does not reap, an orphan stays a
// zombie forever, and what the test asks is whether it was ended.
func processGone(pid int) bool {
	if err := unix.Kill(pid, 0); err != nil {
		return true
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			// "pid (comm) state ..." — the state follows the last ')'.
			s := string(b)
			if i := strings.LastIndex(s, ")"); i >= 0 && len(s) > i+2 {
				return s[i+2] == 'Z'
			}
		}
	}
	return false
}

// Test_Host_StopHangsUpTheShellsJobs is the design's acceptance test for a
// stop: an interactive shell with one foreground and one background job. A
// shell with job control puts each job in its own process group, so a
// signal to the shell's group reaches the shell and nothing it launched —
// except that bash, on SIGHUP, resends it to every job before exiting. Both
// jobs must be gone, and the hangup alone must have done it: the grace is
// set long, so a fall-through to SIGTERM would take longer than the bound.
func Test_Host_StopHangsUpTheShellsJobs(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	bgPid := filepath.Join(dir, "bg.pid")
	fgPid := filepath.Join(dir, "fg.pid")

	run := newOutcomeRun(t, []string{bash, "--noprofile", "--norc", "-i"})
	run.host.AwaitInitialClient = true
	run.host.StopGrace = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	sock := run.awaitAttachSocket(t)
	in := run.attachInteractive(t, ctx, sock)
	_, _ = fmt.Fprintf(in, "bash -c 'echo $$ > %s; exec sleep 300' &\n", bgPid)
	_, _ = fmt.Fprintf(in, "bash -c 'echo $$ > %s; exec sleep 300'\n", fgPid)
	bg := awaitPidFile(t, bgPid)
	fg := awaitPidFile(t, fgPid)
	require.False(t, processGone(bg))
	require.False(t, processGone(fg))

	started := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(outcomeTimeout):
		t.Fatal("host did not return after cancellation")
	}
	require.Eventually(t, func() bool { return processGone(bg) && processGone(fg) },
		5*time.Second, 50*time.Millisecond, "the shell's jobs outlived the session (bg %d fg %d)", bg, fg)
	require.Less(t, time.Since(started), run.host.StopGrace,
		"the hangup alone must end an interactive shell; a fall-through to SIGTERM takes a whole grace")
	require.Equal(t, sessiondir.ReasonStopped, run.record(t).Reason)
}
