package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ciRun is one `upterm ci` invocation against the E2E server, with the
// environment of a GitHub Actions step pointed at files the test can read.
type ciRun struct {
	cmd *exec.Cmd

	// output, summary and workspace are the step's own files. A CI job's
	// report is the point of this command, so the test reads what a runner
	// would have read rather than only what was printed.
	output    string
	summary   string
	workspace string

	stdout bytes.Buffer
}

// newCIRun prepares an `upterm ci` invocation. Nothing is started until Start.
func newCIRun(t *testing.T, args ...string) *ciRun {
	t.Helper()

	uptermPath, err := exec.LookPath("upterm")
	if err != nil {
		t.Skip("upterm not installed, skipping E2E test")
	}

	serverURL := os.Getenv("UPTERM_E2E_SERVER")
	if serverURL == "" {
		t.Fatal("UPTERM_E2E_SERVER environment variable is required")
	}

	// Under /tmp rather than t.TempDir(): a session's admin socket lives under
	// XDG_RUNTIME_DIR, and a Unix socket path has a hard limit near 104 bytes
	// that the temp root on macOS is already most of the way to on its own.
	runtimeDir, err := os.MkdirTemp("/tmp", "upterm-ci-e2e")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })

	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	require.NoError(t, os.MkdirAll(workspace, 0755))

	keyFile := filepath.Join(dir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyFile, []byte(HostPrivateKeyContent), 0600))

	r := &ciRun{
		output:    filepath.Join(dir, "github_output"),
		summary:   filepath.Join(dir, "github_summary"),
		workspace: workspace,
	}

	full := append([]string{
		"ci",
		"--server", serverURL,
		"--private-key", keyFile,
		"--known-hosts", filepath.Join(dir, "known_hosts"),
	}, args...)

	r.cmd = exec.Command(uptermPath, full...)
	r.cmd.Env = append(os.Environ(),
		"XDG_RUNTIME_DIR="+runtimeDir,
		"XDG_STATE_HOME="+runtimeDir,
		"XDG_CONFIG_HOME="+runtimeDir,
		"GITHUB_ACTIONS=true",
		"GITHUB_ACTOR=octocat",
		"GITHUB_WORKSPACE="+workspace,
		"GITHUB_OUTPUT="+r.output,
		"GITHUB_STEP_SUMMARY="+r.summary,
	)
	r.cmd.Stdout = &r.stdout
	r.cmd.Stderr = &r.stdout

	return r
}

func (r *ciRun) Start(t *testing.T) {
	t.Helper()
	require.NoError(t, r.cmd.Start())
	t.Cleanup(func() {
		if r.cmd.Process != nil {
			_ = r.cmd.Process.Kill()
		}
	})
}

// Wait waits for the session to end and asserts it ended successfully. A
// session that timed out or was handed back did what it was asked to; failing
// the step over either would fail the job it was supposed to let continue.
func (r *ciRun) Wait(t *testing.T) string {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()

	select {
	case err := <-done:
		require.NoError(t, err, "upterm ci exited non-zero:\n%s", r.stdout.String())
	case <-time.After(90 * time.Second):
		t.Fatalf("upterm ci never exited:\n%s", r.stdout.String())
	}

	return r.stdout.String()
}

// waitForReport waits until the session has been reported to the CI system,
// which is the point at which it is up and joinable.
func (r *ciRun) waitForReport(t *testing.T) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for {
		if b, err := os.ReadFile(r.output); err == nil && len(b) > 0 {
			return string(b)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the session was never reported to the CI system:\n%s", r.stdout.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestCIReportsTheSessionAndTimesOut(t *testing.T) {
	r := newCIRun(t, "--wait-timeout", "5s", "--", "/bin/sh")
	r.Start(t)

	output := r.waitForReport(t)

	// The step output another step consumes. The heredoc form is what makes a
	// value the runner cannot misread as further entries.
	require.Contains(t, output, "ssh-command<<ghadelimiter_")
	require.Contains(t, output, "ssh ")

	stdout := r.Wait(t)

	// The annotation someone watching the run live sees.
	require.Contains(t, stdout, "::notice title=Upterm session::ssh ")
	require.Contains(t, stdout, "no client connected within 5s")

	// The summary a human reads after the run, and the REST API reads from
	// outside the job.
	summary, err := os.ReadFile(r.summary)
	require.NoError(t, err)
	require.Contains(t, string(summary), "Upterm session")
	require.Contains(t, string(summary), "ssh ")

	// The session's own terminal must not be mirrored into a log that may be
	// public and outlives the run.
	require.NotContains(t, stdout, "$ ")
}

func TestCIEndsWhenTheContinueFileAppears(t *testing.T) {
	// A wait timeout long enough that a session ending on time proves the
	// continue file ended it.
	r := newCIRun(t, "--wait-timeout", "10m", "--", "/bin/sh")
	r.Start(t)

	r.waitForReport(t)

	continueFile := filepath.Join(r.workspace, "continue")
	require.NoError(t, os.WriteFile(continueFile, nil, 0644))

	stdout := r.Wait(t)
	require.Contains(t, stdout, "was created")
	require.Contains(t, stdout, continueFile)
}

func TestCIRefusesAnUnresolvableRestriction(t *testing.T) {
	// Fail-closed: the alternative to this error is a session that accepts
	// anyone holding a connect string that is sitting in a build log.
	r := newCIRun(t, "--limit-access-to-users", "", "--limit-access-to-actor", "--wait-timeout", "5s")
	r.cmd.Env = append(r.cmd.Env, "GITHUB_ACTOR=")

	err := r.cmd.Run()
	require.Error(t, err)

	out := r.stdout.String()
	require.Contains(t, out, "--limit-access-to-actor")
	require.Contains(t, out, "did not say who triggered this job")
	require.NotContains(t, strings.ToLower(out), "::notice", "a session that never started must not be reported as joinable")
}
