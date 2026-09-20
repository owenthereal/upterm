package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testHostKeyLine returns a fresh key in authorized_keys form, for building
// fixtures whose record needs a non-empty HostKeys without caring which key
// it names — nothing in cmd/upterm/command dials with the private half.
func testHostKeyLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n")
}

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

// Test_clientDesc_NamesTheDoorEachClientCameInBy pins the prefix every client
// description now carries. The host's own terminal is a client of the session,
// and a listing that did not say so would show an operator a stranger where
// their own window is.
//
// The address is redacted under CI, so it is the prefix that is compared
// rather than the whole line.
func Test_clientDesc_NamesTheDoorEachClientCameInBy(t *testing.T) {
	guest := clientDesc(api.Client_GUEST, "1.2.3.4:5", "SSH-2.0-x", "SHA256:abc")
	require.Equal(t, "guest", strings.Fields(guest)[0])
	require.Contains(t, guest, "SSH-2.0-x SHA256:abc", "and still says what it always said")

	host := clientDesc(api.Client_HOST, "local", "SSH-2.0-upterm-attach", "SHA256:abc")
	require.Equal(t, "host", strings.Fields(host)[0])
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

// buildStarting: claimed, lock held, and a host key published — the point
// past which a daemon's attach socket is up and attachTarget's callers may
// expect one, even though nothing else beyond the claim has happened yet.
func buildStarting(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.HostKeys = []string{testHostKeyLine(t)}
	}))
}

// buildReady: claimed, published ready, and an admin socket that answers.
func buildReady(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-1"
		r.HostKeys = []string{testHostKeyLine(t)}
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-1",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})
}

// buildDisconnected: claimed, published disconnected by the tunnel-loss path,
// and an admin socket that still answers — the host keeps its command and its
// admin server running until the session ends, so the socket is as talkative
// as a ready session's.
func buildDisconnected(t *testing.T, name string) {
	t.Helper()

	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusDisconnected
		r.SessionID = "sid-2"
		r.HostKeys = []string{testHostKeyLine(t)}
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-2",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})
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

// writeRecordRaw publishes a record file directly, for the shapes the
// publisher would never produce: Dir.Update forces the socket paths on every
// write, so a record from before attach sockets existed cannot be staged
// through it.
func writeRecordRaw(t *testing.T, path string, rec sessiondir.Record) {
	t.Helper()

	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
}

type stubAdminServer struct {
	api.UnimplementedAdminServiceServer

	mu    sync.Mutex
	resps []*api.GetSessionResponse

	// onStop, if set, is called on StopSession; nil answers Unimplemented, the
	// way a daemon that predates this RPC would.
	onStop func()
}

// GetSession answers with the next response in the sequence and repeats the
// last one. A socket that changes its answer between two queries is what a
// replacement session claiming the name looks like from the outside, and
// there is no other way for a test to stage it.
func (s *stubAdminServer) GetSession(context.Context, *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.resps[0]
	if len(s.resps) > 1 {
		s.resps = s.resps[1:]
	}
	return resp, nil
}

func (s *stubAdminServer) StopSession(context.Context, *api.StopSessionRequest) (*api.StopSessionResponse, error) {
	if s.onStop == nil {
		return nil, status.Error(codes.Unimplemented, "no stop")
	}
	s.onStop()
	return &api.StopSessionResponse{}, nil
}

func serveStubAdmin(t *testing.T, socket string, resps ...*api.GetSessionResponse) {
	t.Helper()

	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)

	srv := grpc.NewServer()
	api.RegisterAdminServiceServer(srv, &stubAdminServer{resps: resps})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

// serveStubAdminWithStop is serveStubAdmin for a fixture that also answers
// StopSession.
func serveStubAdminWithStop(t *testing.T, socket string, resp *api.GetSessionResponse, onStop func()) {
	t.Helper()

	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)

	srv := grpc.NewServer()
	api.RegisterAdminServiceServer(srv, &stubAdminServer{resps: []*api.GetSessionResponse{resp}, onStop: onStop})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

// captureStdout collects what fn prints. `session info` answers on stdout, so
// which session it printed is only observable there.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// Drained concurrently: the printed detail is larger than a pipe buffer is
	// guaranteed to be, and fn writing into a full pipe nobody reads would
	// deadlock the test rather than fail it.
	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	// Registered before fn runs, because a require failure inside it calls
	// Goexit: the close below would be skipped and the copier would sit on a
	// pipe whose write end nobody ever closes. Closing twice is harmless.
	defer func() { _ = w.Close() }()

	fn()

	require.NoError(t, w.Close())
	out := <-collected
	require.NoError(t, r.Close())
	return out
}

// lookupJSON returns what a caller of `session info -o json` would parse.
func lookupJSON(t *testing.T, name string) map[string]any {
	t.Helper()

	info, _, err := lookup(context.Background(), name)
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

	_, live, err := lookup(context.Background(), "ready")
	require.NoError(t, err)
	require.NotNil(t, live, "a socket that answered for the recorded session hands its response back")
	require.Equal(t, "sid-1", live.SessionId,
		"the response a caller may print is the one that was validated")
}

// Test_lookup_CountsGuestsApartFromTheHostsOwnTerminal pins what a script
// waiting for company should watch. The host's terminal is a client of its own
// session now, so clientCount alone answers "has anyone joined?" with "yes"
// from the moment the session starts.
func Test_lookup_CountsGuestsApartFromTheHostsOwnTerminal(t *testing.T) {
	setupSessionRoots(t)

	d := claimSession(t, "counted")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-counted"
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-counted",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
		ConnectedClients: []*api.Client{
			{Addr: "local", Version: "SSH-2.0-upterm-attach", Kind: api.Client_HOST},
			{Addr: "1.2.3.4:5", Version: "SSH-2.0-x", Kind: api.Client_GUEST},
		},
	})

	got := lookupJSON(t, "counted")
	require.Equal(t, float64(2), got["clientCount"], "every attachment is a client")
	require.Equal(t, float64(1), got["guestCount"], "only one of them came in by the guest door")
}

// Test_lookup_ReachesASocketUnderAnotherRuntimeRoot is `session info`'s half
// of the cross-root case: the record is found through the shared state root,
// and the socket is dialled where the record says rather than under the
// runtime root this process happens to have. Before the record carried the
// path, a session started from cron was found and then shown as if nothing
// answered for it.
func Test_lookup_ReachesASocketUnderAnotherRuntimeRoot(t *testing.T) {
	setupSessionRoots(t)

	d := claimSession(t, "cron")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-cron"
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-cron",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})

	// The inspector's runtime root moves; the state root, and with it the
	// record, stays where the session published it.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	got := lookupJSON(t, "cron")
	require.Equal(t, sessiondir.StatusReady, got["status"])
	require.NotEmpty(t, got["sshCommand"],
		"the socket the record names answered, so the session is joinable from here too")
	require.Equal(t, d.AdminSocket(), got["adminSocket"],
		"and the answer says where it was reached")
	require.Equal(t, d.AttachSocket(), got["attachSocket"],
		"and where a terminal from this shell would attach, which is equally not under this root")

	_, live, err := lookup(context.Background(), "cron")
	require.NoError(t, err)
	require.NotNil(t, live, "the validated response is handed back for the detail view")
}

// Test_lookup_ReadyWithSocketAnsweringForAnotherSession is the case the
// returned response exists to make safe: the name is held and the socket
// answers, but for a different session than the record describes. There is
// nothing here a caller may print as this session's live detail.
func Test_lookup_ReadyWithSocketAnsweringForAnotherSession(t *testing.T) {
	setupSessionRoots(t)

	d := claimSession(t, "mismatched")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-recorded"
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-other",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})

	info, live, err := lookup(context.Background(), "mismatched")
	require.NoError(t, err)
	require.Nil(t, live, "an answer about another session is not this session's live detail")
	require.Empty(t, info.SSHCommand, "and none of it may reach the caller by another route")
	require.Equal(t, "sid-recorded", info.SessionID)
}

// Test_infoRunE_PrintsTheSessionItValidated pins what `session info` prints
// when the socket's answer changes underneath it. The lookup validates one
// response by session ID; printing a second, freshly fetched one answers "what
// is NAME?" with whatever holds the name at that instant, which after a
// replacement claim is a session the user never asked about.
func Test_infoRunE_PrintsTheSessionItValidated(t *testing.T) {
	setupSessionRoots(t)

	d := claimSession(t, "replaced")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-validated"
	}))
	serveStubAdmin(t, d.AdminSocket(),
		&api.GetSessionResponse{
			SessionId: "sid-validated",
			Host:      "ssh://127.0.0.1:2222",
			NodeAddr:  "127.0.0.1:2222",
			Command:   []string{"bash"},
		},
		// The successor that took the name over between the two queries.
		&api.GetSessionResponse{
			SessionId: "sid-replacement",
			Host:      "ssh://127.0.0.1:2222",
			NodeAddr:  "127.0.0.1:2222",
			Command:   []string{"bash"},
		},
	)

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	out := captureStdout(t, func() {
		require.NoError(t, infoRunE(cmd, []string{"replaced"}))
	})

	require.Contains(t, out, "sid-validated",
		"the session the lookup validated is the one the answer is about")
	require.NotContains(t, out, "sid-replacement",
		"a session that claimed the name after the lookup is not the answer to that lookup")

	// And it prints the status the record published, as the summary for a
	// session that has ended does and as the list's detail view does. A live
	// session is the one case that used to answer the question "how is NAME?"
	// without saying.
	require.Regexp(t, `Status:\s+`+sessiondir.StatusReady, out,
		"the record's status belongs in the detail a live session prints too")
}

// Test_lookup_Disconnected pins that a socket answering for a disconnected
// session does not make it joinable. The socket answers about a session; only
// ready says its answer is one anyone can act on, and a connect string for a
// session whose tunnel is down cannot connect.
func Test_lookup_Disconnected(t *testing.T) {
	setupSessionRoots(t)
	buildDisconnected(t, "disconnected")

	got := lookupJSON(t, "disconnected")
	require.Equal(t, sessiondir.StatusDisconnected, got["status"],
		"a held name keeps the status its owner published")
	require.NotContains(t, got, "sshCommand",
		"a socket that answers for a disconnected session does not make it joinable")

	_, live, err := lookup(context.Background(), "disconnected")
	require.NoError(t, err)
	require.Nil(t, live, "nothing the socket said may be printed as this session's live detail")
}

// Test_listSessions_KeepsADisconnectedSessionRecordOnly is the listing's half
// of the same rule: a disconnected session's socket answers, because the host
// keeps its admin server up until the session ends, and none of that answer
// may become a row that says how to join it.
func Test_listSessions_KeepsADisconnectedSessionRecordOnly(t *testing.T) {
	setupSessionRoots(t)
	buildDisconnected(t, "disconnected")

	sessions, err := listSessions(context.Background(), utils.UptermRuntimeDir(), utils.UptermStateDir())
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "disconnected", sessions[0].Name)
	require.Equal(t, sessiondir.StatusDisconnected, sessions[0].Status)
	require.Equal(t, "sid-2", sessions[0].SessionID)
	require.Empty(t, sessions[0].Host, "the socket's answer is not a row anyone can act on")
	require.Empty(t, sessions[0].SSHCommand)
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

// Test_listSessions_KeepsTheRecordRowWhenNobodyAnswersAtTheRecordedPath pins
// that a held session nobody answers for still gets a row. The record says
// where its admin socket is, and nothing is bound there. The listing walks the
// records, so the row exists; the dial goes to the recorded path and finds
// nothing, so the row is the record's and no more.
func Test_listSessions_KeepsTheRecordRowWhenNobodyAnswersAtTheRecordedPath(t *testing.T) {
	setupSessionRoots(t)

	// Claimed with no admin socket bound: the record carries the path, and
	// nobody is listening at it.
	d, err := sessiondir.Claim(context.Background(), sessiondir.ClaimOptions{
		RuntimeRoot:  utils.UptermRuntimeDir(),
		StateRoot:    utils.UptermStateDir(),
		Name:         "elsewhere",
		Command:      []string{"bash"},
		ForceCommand: []string{"tmux", "attach"},
	})
	require.NoError(t, err)
	releaseAtEnd(t, d)

	// Ready, with a session ID: without one the lookup stops at its first
	// guard and never gets as far as the socket, so the row under test would
	// be the row any unstarted session gets rather than the one this test is
	// about.
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-x"
	}))

	// Listed from a runtime root that has never seen the name. The dial does
	// not go under this root — it goes where the record says — so nothing
	// about it matters, its length included.
	otherRuntime := t.TempDir()

	sessions, err := listSessions(context.Background(), otherRuntime, utils.UptermStateDir())
	require.NoError(t, err)
	require.Len(t, sessions, 1, "a session whose socket lives under another runtime root is still live")
	require.Equal(t, "elsewhere", sessions[0].Name)
	require.Equal(t, sessiondir.StatusReady, sessions[0].Status,
		"the record is the authority on a session no socket here can answer for")
	require.Equal(t, "sid-x", sessions[0].SessionID)
	require.Equal(t, "bash", sessions[0].Command)
	require.Equal(t, "tmux attach", sessions[0].ForceCommand,
		"a record-only row must carry everything the record holds, not a subset of it")
	require.Empty(t, sessions[0].SSHCommand,
		"and no connect string may be invented for a session this environment cannot reach")
}

// Test_listSessions_ReachesASocketUnderAnotherRuntimeRoot is the case the
// record's admin_socket exists for: a host claimed under one XDG_RUNTIME_DIR —
// cron's, a systemd unit's, an ssh login's — and listed from another. The
// socket is bound where the record says, so the row carries live detail; a
// listing that built the path under its own runtime root found nothing there
// and showed the session as record-only.
func Test_listSessions_ReachesASocketUnderAnotherRuntimeRoot(t *testing.T) {
	setupSessionRoots(t)

	d := claimSession(t, "cron")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-cron"
	}))
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid-cron",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"bash"},
	})

	otherRuntime := t.TempDir()

	sessions, err := listSessions(context.Background(), otherRuntime, utils.UptermStateDir())
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "cron", sessions[0].Name)
	require.Equal(t, sessiondir.StatusReady, sessions[0].Status)
	require.Equal(t, "ssh://127.0.0.1:2222", sessions[0].Host,
		"the socket the record names answered, whatever runtime root the listing runs under")
	require.NotEmpty(t, sessions[0].SSHCommand)
	require.Equal(t, d.AdminSocket(), sessions[0].AdminSocket,
		"the row says where the session was reached, which is the recorded path")
}

// Test_listSessions_PrefersTheLiveAnswerWhenTheSessionIDMatches covers the
// other half of the same listing: the record is the floor, not the ceiling.
// Where the socket the record names answers for the session the record
// describes, the row carries what only a running session knows — and where it
// answers for a different one, none of that may reach the row, because a
// successor's connect string printed under this session's name sends whoever
// reads it to the wrong terminal.
func Test_listSessions_PrefersTheLiveAnswerWhenTheSessionIDMatches(t *testing.T) {
	t.Run("the socket answers for the recorded session", func(t *testing.T) {
		setupSessionRoots(t)
		buildReady(t, "ready")

		sessions, err := listSessions(context.Background(), utils.UptermRuntimeDir(), utils.UptermStateDir())
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.Equal(t, "ready", sessions[0].Name)
		require.Equal(t, sessiondir.StatusReady, sessions[0].Status)
		require.Equal(t, "sid-1", sessions[0].SessionID)
		require.Equal(t, "ssh://127.0.0.1:2222", sessions[0].Host)
		require.NotEmpty(t, sessions[0].SSHCommand,
			"a session that answered for itself can be joined, and the row says how")
	})

	t.Run("the socket answers for another session", func(t *testing.T) {
		setupSessionRoots(t)

		d := claimSession(t, "mismatched")
		releaseAtEnd(t, d)
		require.NoError(t, d.Update(func(r *sessiondir.Record) {
			r.Status = sessiondir.StatusReady
			r.SessionID = "sid-recorded"
		}))
		serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
			SessionId: "sid-other",
			Host:      "ssh://127.0.0.1:2222",
			NodeAddr:  "127.0.0.1:2222",
			Command:   []string{"bash"},
		})

		sessions, err := listSessions(context.Background(), utils.UptermRuntimeDir(), utils.UptermStateDir())
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.Equal(t, "sid-recorded", sessions[0].SessionID,
			"the row is about the session the record names")
		require.Empty(t, sessions[0].Host,
			"an answer about another session is not this session's live detail")
		require.Empty(t, sessions[0].SSHCommand)
	})
}

// buildAgedRecord leaves what a finished session leaves — an unheld results
// directory with the outcome in it — and backdates the record, since its own
// updated_at is what Prune dates an entry by. It returns the record's path.
func buildAgedRecord(t *testing.T, name string, age time.Duration) string {
	t.Helper()

	d := claimSession(t, name)
	path := d.RecordPath()
	require.NoError(t, d.Release(context.Background()))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var rec sessiondir.Record
	require.NoError(t, json.Unmarshal(raw, &rec))
	rec.UpdatedAt = time.Now().UTC().Add(-age)
	writeRecordRaw(t, path, rec)

	return path
}

// Test_tidySessions_PrunesOldRecords covers the wiring rather than
// sessiondir.Prune itself: Prune was fully tested and never called, so every
// record a session ever wrote outlived its retention window indefinitely.
//
// It drives tidySessions rather than listRunE because listRunE goes on to run
// the TUI, which is not what this is about.
func Test_tidySessions_PrunesOldRecords(t *testing.T) {
	setupSessionRoots(t)

	expired := buildAgedRecord(t, "expired", sessiondir.RecordRetention+time.Hour)
	recent := buildAgedRecord(t, "recent", time.Hour)

	tidySessions(context.Background())

	_, err := os.Stat(expired)
	require.True(t, os.IsNotExist(err),
		"a record older than the retention window must be pruned, got %v", err)

	_, err = os.Stat(recent)
	require.NoError(t, err, "a record still inside the window is the history this command answers from")
}

func Test_lookup_UnknownName(t *testing.T) {
	setupSessionRoots(t)

	_, _, err := lookup(context.Background(), "never-claimed")
	require.ErrorContains(t, err, "no session named")
}

// Test_sessionInfo_PublishesExactlyWhatEachStateCanAnswer pins the JSON a
// caller actually receives, state by state.
//
// The previous version of this test filled in every optional field before
// comparing, which made it tautological: it compared one struct's tags with
// the same struct's tags and would have passed however lookup behaved. What is
// worth pinning is the opposite — that each state emits the keys it can answer
// and no others, so a key appearing or vanishing is a change to the contract
// rather than a change in the weather.
func Test_sessionInfo_PublishesExactlyWhatEachStateCanAnswer(t *testing.T) {
	setupSessionRoots(t)

	// Present in every state, so a caller can read them without first working
	// out which state it got. pid is among them because Claim records it and
	// nothing ever clears it — it is what `kill` names when a session's socket
	// has stopped answering. logPath is not: only a daemon publishes one, and
	// these fixtures are claims without a daemon behind them.
	mandatory := []string{"name", "launchId", "status", "clientCount", "guestCount", "pid"}

	for _, tc := range []struct {
		name  string
		build func(*testing.T, string)
		want  []string
	}{
		{
			// No session ID yet, so there is nothing to ask the admin socket
			// and no connect string to hand back. The socket's path is
			// published all the same: the name is held, so there is one.
			name:  "starting",
			build: buildStarting,
			want:  []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason", "adminSocket", "attachSocket"},
		},
		{
			// The one state whose socket answers, and the only one that can
			// carry a connect string.
			name:  "ready",
			build: buildReady,
			want:  []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason", "sessionId", "sshCommand", "adminSocket", "attachSocket"},
		},
		{
			// A session ID and a socket that answers, because the host keeps
			// its admin server up through a tunnel loss: the ID stays, and
			// the live detail may not, since only ready is joinable.
			name:  "disconnected",
			build: buildDisconnected,
			want:  []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason", "sessionId", "adminSocket", "attachSocket"},
		},
		{
			// The only state that can carry an exit code, because it is the
			// only one whose command reported one — and, like every ended
			// session, no socket path, since there is nothing left to dial.
			name:  "exited",
			build: buildEndedAfterExit,
			want:  []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason", "exitCode"},
		},
		{
			// Killed before it could publish an outcome: the same shape as a
			// clean exit, minus the code nobody recorded.
			name:  "killed",
			build: buildEndedAfterKill,
			want:  []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.build(t, tc.name)

			got := lookupJSON(t, tc.name)
			require.Equal(t,
				slices.Sorted(slices.Values(tc.want)),
				slices.Sorted(maps.Keys(got)),
				"the keys %s publishes are part of the contract", tc.name)

			for _, key := range mandatory {
				require.Contains(t, got, key,
					"%s must answer %q whatever else it can say", tc.name, key)
			}

			// No case here was signalled, so nothing may claim it was: signal
			// and exitCode are the two fields automation branches on.
			require.NotContains(t, got, "signal",
				"%s was not signalled and must not say it was", tc.name)
		})
	}
}

func Test_stopSession(t *testing.T) {
	t.Run("stops a ready session and reports the outcome", func(t *testing.T) {
		setupSessionRoots(t)
		d := claimSession(t, "ready-1")
		require.NoError(t, d.Update(func(r *sessiondir.Record) {
			r.Status = sessiondir.StatusReady
			r.SessionID = "sid-1"
			r.HostKeys = []string{testHostKeyLine(t)}
		}))
		released := make(chan struct{})
		var releasedAt time.Time
		serveStubAdminWithStop(t, d.AdminSocket(), &api.GetSessionResponse{SessionId: "sid-1", Host: "ssh://127.0.0.1:2222"}, func() {
			// What the daemon does: publish stopped and give the name back —
			// delayed, so the assertion below can tell a caller that returns
			// the instant the RPC is acknowledged from one that actually
			// waited for the release. Reading out after <-released alone
			// cannot: stopSession writes its message before either goroutine
			// is scheduled again, so a version that skipped the wait would
			// still have the right bytes in out by the time this looks.
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = d.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusEnding; r.Reason = sessiondir.ReasonStopped })
				_ = d.Release(context.Background())
				releasedAt = time.Now()
				close(released)
			}()
		})
		var out bytes.Buffer
		require.NoError(t, stopSession(context.Background(), "ready-1", &out))
		returnedAt := time.Now()
		<-released
		require.False(t, returnedAt.Before(releasedAt),
			"stopSession must not return before the name was released")
		require.Contains(t, out.String(), "session ready-1 stopped")
	})
	t.Run("a session that has ended is already done", func(t *testing.T) {
		setupSessionRoots(t)
		buildEndedAfterExit(t, "gone-1")
		var out bytes.Buffer
		require.NoError(t, stopSession(context.Background(), "gone-1", &out))
		require.Contains(t, out.String(), "has already ended")
	})
	t.Run("a held name whose socket does not answer names the pid", func(t *testing.T) {
		setupSessionRoots(t)
		d := claimSession(t, "mute-1")
		releaseAtEnd(t, d)
		require.NoError(t, d.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.SessionID = "sid" }))
		var out bytes.Buffer
		err := stopSession(context.Background(), "mute-1", &out)
		require.ErrorContains(t, err, "not answering on its admin socket")
		require.ErrorContains(t, err, fmt.Sprintf("pid %d", os.Getpid()))
	})
	t.Run("a daemon that predates the RPC says so rather than blaming its socket", func(t *testing.T) {
		setupSessionRoots(t)
		d := claimSession(t, "old-1")
		releaseAtEnd(t, d)
		require.NoError(t, d.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.SessionID = "sid" }))
		// serveStubAdmin leaves onStop nil, so StopSession answers
		// Unimplemented — what a daemon from before this branch does.
		serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222"})
		var out bytes.Buffer
		err := stopSession(context.Background(), "old-1", &out)
		require.ErrorContains(t, err, "predates 'session stop'")
		require.ErrorContains(t, err, fmt.Sprintf("pid %d", os.Getpid()),
			"the operator has to be able to end it themselves")
		require.NotContains(t, err.Error(), "not answering on its admin socket",
			"the socket answered; it is the method that is missing")
	})
	t.Run("a daemon that predates the RPC says so even while it is still starting", func(t *testing.T) {
		setupSessionRoots(t)
		// Claimed and left at StatusStarting, which is what a daemon that has
		// not published ready yet looks like — and the two conditions overlap:
		// an upterm from before `session stop` can be in exactly this state.
		d := claimSession(t, "old-start-1")
		releaseAtEnd(t, d)
		// Asserted, not assumed: the overlap is the whole case, and a Claim
		// that published some other status would quietly turn this into a
		// duplicate of the sibling above while still passing.
		require.Equal(t, sessiondir.StatusStarting, d.Record().Status,
			"the case is a predating daemon that is also still starting")
		serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222"})
		var out bytes.Buffer
		err := stopSession(context.Background(), "old-start-1", &out)
		require.ErrorContains(t, err, "predates 'session stop'")
		require.NotContains(t, err.Error(), "try again in a moment",
			"retrying can never reach a method that does not exist there")
	})
	t.Run("a session still starting says so", func(t *testing.T) {
		setupSessionRoots(t)
		d := claimSession(t, "start-1")
		releaseAtEnd(t, d)
		var out bytes.Buffer
		err := stopSession(context.Background(), "start-1", &out)
		require.ErrorContains(t, err, "still starting")
		require.ErrorContains(t, err, fmt.Sprintf("pid %d", os.Getpid()))
	})
	t.Run("an unknown name", func(t *testing.T) {
		setupSessionRoots(t)
		var out bytes.Buffer
		require.ErrorContains(t, stopSession(context.Background(), "nope", &out), `no session named "nope"`)
	})
	t.Run("a stop the daemon acknowledged but did not finish is reported, bounded", func(t *testing.T) {
		old := stopWaitTimeout
		stopWaitTimeout = 300 * time.Millisecond
		t.Cleanup(func() { stopWaitTimeout = old })
		setupSessionRoots(t)
		d := claimSession(t, "stuck-1")
		releaseAtEnd(t, d)
		require.NoError(t, d.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.SessionID = "sid" }))
		serveStubAdminWithStop(t, d.AdminSocket(), &api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222"}, func() {})
		var out bytes.Buffer
		err := stopSession(context.Background(), "stuck-1", &out)
		require.ErrorContains(t, err, "still running after")
	})
}
