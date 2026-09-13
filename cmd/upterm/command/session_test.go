package command

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestBuildSessionDetailSSH(t *testing.T) {
	for _, tt := range []struct {
		host string
		want string
	}{
		{"ssh://example.com:22", "ssh sid@example.com"},
		{"ssh://example.com:2222", "ssh sid@example.com -p 2222"},
	} {
		t.Run(tt.host, func(t *testing.T) {
			detail, err := buildSessionDetail(&api.GetSessionResponse{Host: tt.host, SshUser: "sid"})
			require.NoError(t, err)
			require.Equal(t, tt.want, detail.SSHCommand)
		})
	}
}

func TestBuildSessionDetailWebSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell and OpenSSH")
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}

	const embeddedUser = "sid:MTI3LjAuMC4xOjIyMjI="
	for _, shellName := range []string{"sh", "bash", "zsh"} {
		t.Run(shellName, func(t *testing.T) {
			shell, err := exec.LookPath(shellName)
			if err != nil {
				t.Skipf("%s is not installed", shellName)
			}
			for _, tt := range []struct {
				name   string
				server string
				user   string
				want   string
			}{
				{"root", "ws://example.com:80", "sid", "ws://sid@example.com:80"},
				{"subpath", "wss://example.com/ws-uptermd/", "sid", "wss://sid@example.com/ws-uptermd/"},
				{"non-default port", "ws://example.com:8080/ws", "sid", "ws://sid@example.com:8080/ws"},
				{"ws on 443", "ws://example.com:443/ws", "sid", "ws://sid@example.com:443/ws"},
				{"wss on 80", "wss://example.com:80/ws", "sid", "wss://sid@example.com:80/ws"},
				{"escaped path", "wss://example.com/a%2Fb/team%20space/%25", "sid", "wss://sid@example.com/a%2Fb/team%20space/%25"},
				{"apostrophe", "wss://example.com/team's/session", "sid", "wss://sid@example.com/team's/session"},
				{"query", "wss://example.com/ws?a=1&b=2", "sid", "wss://sid@example.com/ws?a=1&b=2"},
				{"shell expansion", "wss://example.com/ws?x=$UPTERM_TEST_LITERAL&y=$(printf expanded)&z=`printf expanded`&q=\"'", "sid", "wss://sid@example.com/ws?x=$UPTERM_TEST_LITERAL&y=$(printf expanded)&z=`printf expanded`&q=\"'"},
				{"ssh tokens", "wss://example.com/ws?q=%h%p%r%n%%", "sid", "wss://sid@example.com/ws?q=%h%p%r%n%%"},
				{"embedded routing", "wss://example.com:443/ws", embeddedUser, "wss://" + embeddedUser + "@example.com:443/ws"},
				{"legacy routing", "wss://example.com:443/ws", "", "wss://" + embeddedUser + "@example.com:443/ws"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					detail, err := buildSessionDetail(&api.GetSessionResponse{
						Host: tt.server, SshUser: tt.user, SessionId: "sid", NodeAddr: "127.0.0.1:2222",
					})
					require.NoError(t, err)
					require.Equal(t, []string{"proxy", tt.want}, captureProxyArgs(t, shell, ssh, detail.SSHCommand))
				})
			}
		})
	}
}

// Run the displayed command through a real outer shell, OpenSSH's percent
// expansion, and its proxy shell. The stand-in upterm records argv and exits;
// no network connection or SSH server is needed.
func captureProxyArgs(t *testing.T, shell, ssh, command string) []string {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "upterm"), []byte("#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$UPTERM_TEST_ARGS\"\n"), 0o700))
	require.True(t, strings.HasPrefix(command, "ssh "))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-c",
		`exec "$UPTERM_TEST_SSH" -F /dev/null -o BatchMode=yes -o IdentityAgent=none -o IdentityFile=none `+strings.TrimPrefix(command, "ssh "))
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SHELL="+shell, "UPTERM_TEST_SSH="+ssh, "UPTERM_TEST_ARGS="+argsFile, "UPTERM_TEST_LITERAL=expanded")
	output, err := cmd.CombinedOutput()
	require.Error(t, err, "the proxy exits without an SSH handshake")
	require.NoError(t, ctx.Err(), "SSH timed out: %s", output)
	args, err := os.ReadFile(argsFile)
	require.NoError(t, err, "command: %s\nSSH output: %s", command, output)
	return strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
}

// The cases below are built from the files a real run leaves behind, using
// only the calls the host itself makes. A synthetic record would not exercise
// what is actually under test, which is what the lock and the record say
// *together*: the record alone says "ready" long after a killed session is
// gone.

// setupSessionRoots points the XDG roots at a directory short enough to hold a
// session's admin socket. t.TempDir() on macOS hands out a /var/folders path
// that overflows the 104-byte unix socket limit once the session's own
// components are appended, and its Windows equivalent is long enough to do the
// same, so the temp root is used directly there.
func setupSessionRoots(t *testing.T) {
	t.Helper()

	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = ""
	}

	dir, err := os.MkdirTemp(root, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_STATE_HOME", dir)
}

func claimSession(t *testing.T, name string) *sessiondir.Dir {
	t.Helper()

	d, err := sessiondir.Claim(context.Background(), sessiondir.ClaimOptions{
		RuntimeRoot: utils.UptermRuntimeDir(),
		StateRoot:   utils.UptermStateDir(),
		Name:        name,
		Command:     []string{"bash"},
	})
	require.NoError(t, err)
	return d
}

// releaseAtEnd gives the name back once the test is done with it, for the
// cases that deliberately keep the lock held while lookup runs.
func releaseAtEnd(t *testing.T, d *sessiondir.Dir) {
	t.Helper()
	t.Cleanup(func() { _ = d.Release(context.Background()) })
}

// buildStarting: claimed, lock held, nothing published beyond the claim.
func buildStarting(t *testing.T, name string) {
	t.Helper()
	releaseAtEnd(t, claimSession(t, name))
}

// buildReady: claimed, published ready, and an admin socket that answers.
func buildReady(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-1"
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-1",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})
}

// buildDisconnected: claimed, published disconnected by the tunnel-loss path,
// no socket answering.
func buildDisconnected(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusDisconnected
		r.SessionID = "sid-2"
	}))
}

// buildEndedAfterExit: what a normal shutdown leaves — the outcome published,
// then the name given back.
func buildEndedAfterExit(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	code := 3
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusEnding
		r.Reason = sessiondir.ReasonExited
		r.ExitCode = &code
	}))
	require.NoError(t, d.Release(context.Background()))
}

// buildEndedAfterKill: what a SIGKILL leaves — the lock free and the record
// still saying "ready", because nothing got the chance to write anything else.
// Release leaves the record behind, which is all this needs.
func buildEndedAfterKill(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
	}))
	require.NoError(t, d.Release(context.Background()))
}

type stubAdminServer struct {
	api.UnimplementedAdminServiceServer
	resp *api.GetSessionResponse
}

func (s *stubAdminServer) GetSession(context.Context, *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return s.resp, nil
}

func serveStubAdmin(t *testing.T, socket string, resp *api.GetSessionResponse) {
	t.Helper()

	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)

	srv := grpc.NewServer()
	api.RegisterAdminServiceServer(srv, &stubAdminServer{resp: resp})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

// lookupJSON returns what a caller of `session info -o json` would parse.
func lookupJSON(t *testing.T, name string) map[string]any {
	t.Helper()

	info, err := lookup(context.Background(), name)
	require.NoError(t, err)

	raw, err := json.Marshal(info)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func Test_lookup_Starting(t *testing.T) {
	setupSessionRoots(t)
	buildStarting(t, "starting")

	got := lookupJSON(t, "starting")
	require.Equal(t, sessiondir.StatusStarting, got["status"])
	require.Equal(t, "starting", got["name"])
}

func Test_lookup_ReadyWithLiveSocket(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "ready")

	got := lookupJSON(t, "ready")
	require.Equal(t, sessiondir.StatusReady, got["status"])
	require.Equal(t, "sid-1", got["sessionId"])
	require.NotEmpty(t, got["sshCommand"], "a live session that answered carries its connect string")
}

func Test_lookup_Disconnected(t *testing.T) {
	setupSessionRoots(t)
	buildDisconnected(t, "disconnected")

	got := lookupJSON(t, "disconnected")
	require.Equal(t, sessiondir.StatusDisconnected, got["status"],
		"a held name keeps the status its owner published")
}

func Test_lookup_EndedAfterNormalExit(t *testing.T) {
	setupSessionRoots(t)
	buildEndedAfterExit(t, "exited")

	got := lookupJSON(t, "exited")
	require.Equal(t, statusEnded, got["status"])
	require.Equal(t, sessiondir.ReasonExited, got["reason"])
	require.Equal(t, float64(3), got["exitCode"])
}

func Test_lookup_EndedAfterKill(t *testing.T) {
	setupSessionRoots(t)
	buildEndedAfterKill(t, "killed")

	got := lookupJSON(t, "killed")
	require.Equal(t, statusEnded, got["status"],
		"nobody holds the name, so the session is over whatever its record still says")
	require.Equal(t, sessiondir.ReasonUnknown, got["reason"],
		"a killed session left no outcome behind, and inventing one would be worse than saying so")
}

// Test_reapSessions_RemovesTheDirectoryOfADeadOwner covers the wiring rather
// than sessiondir.Reap itself: Reap was fully tested and never called, so a
// crashed host held its name until something else happened to reclaim it.
func Test_reapSessions_RemovesTheDirectoryOfADeadOwner(t *testing.T) {
	setupSessionRoots(t)

	sessions := sessiondir.SessionsRoot(utils.UptermRuntimeDir())

	// A live session, whose directory must survive: the point of a reap is
	// that it distinguishes "nobody holds this name" from "this name exists".
	live := claimSession(t, "live")
	releaseAtEnd(t, live)

	// What a SIGKILLed host leaves behind — the directory and a lock file
	// nobody holds. Built by hand because every in-process route to it either
	// keeps the lock held or removes the directory on the way out.
	stale := filepath.Join(sessions, "stale")
	require.NoError(t, os.MkdirAll(stale, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(stale, "lock"), nil, 0600))

	reapSessions(context.Background())

	_, err := os.Stat(stale)
	require.True(t, os.IsNotExist(err),
		"a session directory whose owner is gone must be reaped, got %v", err)

	_, err = os.Stat(filepath.Join(sessions, "live"))
	require.NoError(t, err, "a live session's directory must survive a reap")
}

func Test_lookup_UnknownName(t *testing.T) {
	setupSessionRoots(t)

	_, err := lookup(context.Background(), "never-claimed")
	require.ErrorContains(t, err, "no session named")
}

func Test_sessionInfo_OneShapeAcrossStates(t *testing.T) {
	setupSessionRoots(t)

	for _, tc := range []struct {
		name  string
		build func(*testing.T, string)
	}{
		{"starting", buildStarting},
		{"ready", buildReady},
		{"disconnected", buildDisconnected},
		{"exited", buildEndedAfterExit},
		{"killed", buildEndedAfterKill},
	} {
		tc.build(t, tc.name)
	}

	var want []string
	for _, name := range []string{"starting", "ready", "disconnected", "exited", "killed"} {
		info, err := lookup(context.Background(), name)
		require.NoError(t, err)

		got := canonicalKeys(t, info)
		if want == nil {
			want = got
			continue
		}
		require.Equal(t, want, got,
			"%s: a caller must not have to parse two formats depending on whether it asked while the process was running", name)
	}
	require.NotEmpty(t, want)
}

// canonicalKeys is the JSON key set of a result with every optional field
// populated. Comparing the raw key sets would only compare which fields each
// state happens to fill in; the claim under test is that there is one shape,
// not one set of values.
func canonicalKeys(t *testing.T, info sessionInfo) []string {
	t.Helper()

	info.LaunchID = "launch"
	info.SessionID = "session"
	info.Command = "command"
	info.ForceCommand = "force"
	info.SSHCommand = "ssh"
	info.ConnectedClients = []string{"client"}
	info.Reason = "reason"
	code := 0
	info.ExitCode = &code

	raw, err := json.Marshal(info)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return slices.Sorted(maps.Keys(m))
}
