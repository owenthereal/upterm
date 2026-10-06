package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// runCurrent runs `upterm session current` with UPTERM_ADMIN_SOCKET set to
// socket ("" for none) and returns what it printed and the status main would
// exit with. The caller has run setupSessionRoots.
//
// Everything that can set this command's flags from outside is pinned, since
// the developer running the suite may have any of it:
//   - UPTERM_ADMIN_SOCKET is the flag's default, read when Root builds the
//     command; it is set inside every upterm session.
//   - UPTERM_OUTPUT binds -o through viper. Viper ignores an empty value, so
//     setting it empty is the same as unsetting it.
//   - A config.yaml with admin-socket or output would win over an empty
//     variable. XDG_CONFIG_HOME points at the test's directory, which has none.
//
// Executing the command leaves what it parsed in package variables, and
// flagOutput is shared with `session info`, whose tests call its RunE without
// building a command and so rely on it being empty. Both are put back.
func runCurrent(t *testing.T, socket string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	prevOutput, prevSocket := flagOutput, flagAdminSocket
	t.Cleanup(func() { flagOutput, flagAdminSocket = prevOutput, prevSocket })
	t.Setenv("UPTERM_ADMIN_SOCKET", socket)
	t.Setenv("UPTERM_OUTPUT", "")
	t.Setenv("XDG_CONFIG_HOME", os.Getenv("XDG_RUNTIME_DIR"))
	root := Root()
	root.SetArgs(append([]string{"session", "current"}, args...))
	// Cobra prints the error through its err writer but the usage through its
	// out writer (cobra 1.10.2: c.Println -> OutOrStderr), so both land here.
	// The command's own output goes to os.Stdout, which captureStdout takes.
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	root.SetOut(&errBuf)
	var err error
	stdout = captureStdout(t, func() { err = root.Execute() })
	return stdout, errBuf.String(), exitStatus(err)
}

// exitStatus is main.go's mapping, except that an error main would log a
// second time on its own reports -1, so a test can insist there is none.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ec ExitCodeError
	if errors.As(err, &ec) {
		return ec.Code
	}
	return -1
}

func socketIn(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), name)
}

// Outside a session the command says so with notFoundCode: nothing at all
// with -o, which is how a shell prompt or starship's `when` calls it, and one
// line for a person. Never the usage, never a second line from main.
func TestSessionCurrentOutsideSession(t *testing.T) {
	setupSessionRoots(t)

	missing := socketIn(t, "gone.sock")

	// What a host killed with SIGKILL leaves: the file, and nobody listening.
	stale := socketIn(t, "stale.sock")
	ln, err := net.Listen("unix", stale)
	require.NoError(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	_, err = os.Stat(stale)
	require.NoError(t, err, "the stale case needs the socket file to remain")

	tmpl := []string{"-o", "go-template={{.ClientCount}}"}
	json := []string{"-o", "json"}
	for _, tc := range []struct {
		name   string
		socket string
		args   []string
		stderr string
	}{
		{"no socket, template", "", tmpl, ""},
		{"no socket, json", "", json, ""},
		{"no socket, detail", "", nil, "Error: not in an upterm session: $UPTERM_ADMIN_SOCKET is not set\n"},
		{"missing socket, template", missing, tmpl, ""},
		{"missing socket, detail", missing, nil, "Error: not in an upterm session: no session answers at " + missing + "\n"},
		{"stale socket file, template", stale, tmpl, ""},
		{"stale socket file, json", stale, json, ""},
		{"stale socket file, detail", stale, nil, "Error: not in an upterm session: no session answers at " + stale + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCurrent(t, tc.socket, tc.args...)
			require.Equal(t, notFoundCode, code)
			require.Empty(t, stdout)
			require.Equal(t, tc.stderr, stderr)
		})
	}
}

// The quiet path is for "not in a session" only. A malformed -o is reported
// wherever it runs, or a typo in a prompt config would go unnoticed for as
// long as nobody happened to be sharing.
func TestSessionCurrentBadOutputOutsideSession(t *testing.T) {
	setupSessionRoots(t)
	for _, tc := range []struct {
		name   string
		format string
		stderr string
	}{
		{"format", "yaml", `Error: invalid output format "yaml": must be 'json' or 'go-template=<template>'` + "\n"},
		{"template", "go-template={{.Nope", "Error: invalid template: template: session:1: unclosed action\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCurrent(t, "", "-o", tc.format)
			require.Equal(t, 1, code)
			require.Empty(t, stdout)
			require.Equal(t, tc.stderr, stderr)
		})
	}
}

// A socket that answers but refuses, or answers that it timed out, is "could
// not ask", not "not in a session": exit 1, one line naming the socket and the
// status, in both modes.
func TestSessionCurrentRefusedIsOneLine(t *testing.T) {
	setupSessionRoots(t)

	// The stub returns the status at once, so the timeout case does not wait.
	for _, tc := range []struct {
		name   string
		socket string
		err    error
		want   string
	}{
		{"refused", "refusing.sock", status.Error(codes.PermissionDenied, "nope"), "code = PermissionDenied"},
		{"timed out", "slow.sock", status.Error(codes.DeadlineExceeded, "slow"), "code = DeadlineExceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := socketIn(t, tc.socket)
			ln, err := net.Listen("unix", socket)
			require.NoError(t, err)
			srv := grpc.NewServer()
			api.RegisterAdminServiceServer(srv, &stubAdminServer{getErr: tc.err})
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(srv.Stop)

			for _, args := range [][]string{nil, {"-o", "json"}} {
				stdout, stderr, code := runCurrent(t, socket, args...)
				require.Equal(t, 1, code, "args %v", args)
				require.Empty(t, stdout)
				require.Equal(t, 1, strings.Count(stderr, "\n"), "one line, no usage: %q", stderr)
				require.Contains(t, stderr, "failed to get session at "+socket)
				require.Contains(t, stderr, tc.want)
			}
		})
	}
}

// A session that answers with something this command cannot render is a
// failure like any other: exit 1 and one line on stderr, with nothing on
// stdout for these cases.
func TestSessionCurrentRenderFailureIsOneLine(t *testing.T) {
	setupSessionRoots(t)
	good := socketIn(t, "good.sock")
	serveStubAdmin(t, good, &api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222"})
	badHost := socketIn(t, "badhost.sock")
	serveStubAdmin(t, badHost, &api.GetSessionResponse{SessionId: "sid", Host: "://bad"})

	for _, tc := range []struct {
		name   string
		socket string
		args   []string
		want   string
	}{
		// Parses fine; fails only when executed against the data.
		{"template execution", good, []string{"-o", "go-template={{.Nope}}"}, "can't evaluate field Nope"},
		// buildSessionDetail cannot parse the host.
		{"detail", badHost, nil, "missing protocol scheme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCurrent(t, tc.socket, tc.args...)
			require.Equal(t, 1, code)
			require.Empty(t, stdout)
			require.Equal(t, 1, strings.Count(stderr, "\n"), "one line, no usage: %q", stderr)
			require.Contains(t, stderr, tc.want)
		})
	}
}

// Inside a session nothing changes: the template and the JSON both print what
// they always did, and nothing goes to stderr.
func TestSessionCurrentInSession(t *testing.T) {
	setupSessionRoots(t)
	socket := socketIn(t, "live.sock")
	serveStubAdmin(t, socket, &api.GetSessionResponse{
		SessionId:        "sid",
		ConnectedClients: []*api.Client{{}, {}},
	})

	stdout, stderr, code := runCurrent(t, socket, "-o", "go-template={{.ClientCount}}")
	require.Equal(t, 0, code)
	require.Equal(t, "2", stdout)
	require.Empty(t, stderr)

	stdout, stderr, code = runCurrent(t, socket, "-o", "json")
	require.Equal(t, 0, code)
	require.Empty(t, stderr)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got), "stdout: %q", stdout)
	require.Equal(t, "sid", got["sessionId"])
	require.EqualValues(t, 2, got["clientCount"])
}
