package command

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/protobuf/proto"
)

// The public relay's key, and the fingerprint its operator publishes for it.
const (
	publicRelayKey         = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4"
	publicRelayFingerprint = "SHA256:9ajV8JqMe6jJE/s3TYjb/9xw7T0pfJ2+gADiBIJWDPE"
)

// embeddedSSHUser is the SSH user an embedded-mode relay routes the example
// session by: its ID and, encoded, the node 10.0.0.5:2222 it is on.
const embeddedSSHUser = exampleSessionID + ":MTAuMC4wLjU6MjIyMg=="

// The daemon reports the relay key its check trusted, as the known_hosts line
// for the relay as it dialled it, and how it came to trust it: the line was
// already there, or it took the key on first use, asking or not.
func TestTheDaemonReportsTheRelayKeyItTrusted(t *testing.T) {
	key, err := host.NewHostKey()
	require.NoError(t, err)
	relay := fakerelay.Start(t, key, fakerelay.RandomID)
	line := knownhosts.Line([]string{relay.Addr}, key.PublicKey())

	for _, tc := range []struct {
		name       string
		knownHosts string
		stdin      string
		args       []string
		trust      string
	}{
		{"a key its known_hosts has", line + "\n", "", nil, "known"},
		{"a key accepted when it asked", "", "yes\n", nil, "prompted"},
		{"a key accepted without asking", "", "", []string{"--skip-host-key-check"}, "auto-accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "known_hosts")
			require.NoError(t, os.WriteFile(file, []byte(tc.knownHosts), 0o600))
			_, sess := hostedSession(t, relay, strings.NewReader(tc.stdin), "", nil, append([]string{"--known-hosts", file}, tc.args...)...)
			require.Equal(t, line, sess.GetRelayKnownHosts())
			require.Equal(t, tc.trust, sess.GetRelayKeyTrust())
		})
	}
}

// servedReady claims name, publishes it ready, and answers for it on its admin
// socket with resp, as its daemon would.
func servedReady(t *testing.T, name string, resp *api.GetSessionResponse) {
	t.Helper()
	d := claimSession(t, name)
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = resp.GetSessionId()
	}))
	resp.LaunchId = d.LaunchID()
	serveStubAdmin(t, d.AdminSocket(), resp)
}

// relayAnswer is what a daemon on relay answers, with sshUser, having trusted
// the relay key on line in the way trust says; an empty line is a daemon that
// doesn't say.
func relayAnswer(relay, sshUser, line, trust string) *api.GetSessionResponse {
	resp := &api.GetSessionResponse{SessionId: exampleSessionID, Host: relay, SshUser: sshUser, Command: []string{"bash"},
		Name: proto.String("home"), Status: proto.String(sessiondir.StatusReady)}
	if line != "" {
		resp.RelayKnownHosts, resp.RelayKeyTrust = proto.String(line), proto.String(trust)
	}
	return resp
}

// requireTextGolden compares got with testdata/ssh-config/NAME.txt.
func requireTextGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", "ssh-config", name+".txt"))
	require.NoError(t, err)
	// Git may check the file out with CRLF line endings.
	require.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), got)
}

// What `session ssh-config` prints, for each kind of relay and each way the
// host can have come to trust its key.
func TestSSHConfigGolden(t *testing.T) {
	for _, tc := range []struct {
		golden string
		resp   *api.GetSessionResponse
		args   []string
	}{
		{"public-relay", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "known"), nil},
		// A self-hosted relay routing in embedded mode, which reaches the
		// session by its node as well as its ID.
		{"embedded-relay", relayAnswer("ssh://relay.example.com", embeddedSSHUser, "@cert-authority relay.example.com "+publicRelayKey, "known"), nil},
		{"port", relayAnswer("ssh://relay.example.com:2222", exampleSessionID, "@cert-authority [relay.example.com]:2222 "+publicRelayKey, "known"), nil},
		{"ipv6", relayAnswer("ssh://[::1]:2222", exampleSessionID, "[::1]:2222 "+publicRelayKey, "known"), nil},
		{"wss", relayAnswer("wss://uptermd.upterm.dev", exampleSessionID, "@cert-authority [uptermd.upterm.dev]:443 "+publicRelayKey, "known"), nil},
		{"ws-embedded-relay", relayAnswer("ws://relay.example.com:8080", embeddedSSHUser, "@cert-authority [relay.example.com]:8080 "+publicRelayKey, "known"), nil},
		{"prompted", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "prompted"), nil},
		{"auto-accepted", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "auto-accepted"), nil},
		{"unreported", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "", ""), nil},
		// A way of trusting the key this version doesn't know is not read as
		// one that vouches for it.
		{"unknown-trust", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "pinned-elsewhere"), nil},
		{"alias", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "known"), []string{"--alias", "laptop-home"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			servedReady(t, "home", tc.resp)
			stdout, stderr, code := runCLI(t, append([]string{"session", "ssh-config", "home"}, tc.args...)...)
			require.Equal(t, 0, code, stderr)
			require.Empty(t, stderr)
			requireTextGolden(t, tc.golden, stdout)
		})
	}
}

// The block's user is the one the session's ssh line connects as, whichever
// relay it is on, and a daemon from before it sent one is read the same way.
func TestSSHConfigUserIsTheSSHLines(t *testing.T) {
	for _, resp := range []*api.GetSessionResponse{
		{SessionId: exampleSessionID, Host: "ssh://uptermd.upterm.dev:22", SshUser: exampleSessionID},
		{SessionId: exampleSessionID, Host: "ssh://relay.example.com:22", SshUser: embeddedSSHUser},
		{SessionId: exampleSessionID, Host: "ssh://relay.example.com:22", NodeAddr: "10.0.0.5:2222"},
	} {
		detail, err := buildSessionDetail(resp)
		require.NoError(t, err)
		user, _, ok := strings.Cut(strings.TrimPrefix(detail.SSHCommand, "ssh "), "@")
		require.True(t, ok, detail.SSHCommand)
		block, err := sshConfigFor(resp, "home")
		require.NoError(t, err)
		require.Contains(t, block+"\n", "\n  User "+configValue(user)+"\n", "the ssh line's user is %s", user)
	}
}

// The session has to be one guests can connect to now, and the alias one
// ssh can be given; otherwise there is nothing to print, and upterm says why.
func TestSSHConfigRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T)
		args  []string
		code  int
		want  string
	}{
		{"no session has the name", func(*testing.T) {}, nil, 4, `upterm: no session named "home"`},
		{"it has ended", func(t *testing.T) {
			endHeld(t, claimSession(t, "home"))
		}, nil, 1, "upterm: session home has ended"},
		{"it is still starting", func(t *testing.T) { buildStarting(t, "home") }, nil, 1,
			"upterm: session home is starting, so guests can't connect to it now; 'upterm session info home' says why"},
		{"it is disconnected", func(t *testing.T) { buildDisconnected(t, "home") }, nil, 1,
			"upterm: session home is disconnected, so guests can't connect to it now; 'upterm session info home' says why"},
		// The claim records this process as the session's.
		{"it doesn't answer", func(t *testing.T) { readyHeld(t, "home", "sid") }, nil, 1,
			"upterm: session home isn't answering on its admin socket (" + pidOf(&sessiondir.Record{Pid: os.Getpid()}) + ")"},
		{"an alias ssh can't take", func(t *testing.T) { buildReady(t, "home") }, []string{"--alias", "my home"}, 1,
			`upterm: invalid --alias "my home": use letters, digits, '.', '_' and '-', starting with a letter or digit`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			tc.setup(t)
			stdout, stderr, code := runCLI(t, append([]string{"session", "ssh-config", "home"}, tc.args...)...)
			require.Equal(t, tc.code, code)
			require.Empty(t, stdout)
			require.Equal(t, tc.want+"\n", stderr)
		})
	}
}

// sshConfigKeys are the keys the session JSON gained for ssh's config.
var sshConfigKeys = []string{"sshConfig", "knownHosts", "relayKeyTrust"}

// requireGoldenWith is requireGolden for JSON that is the golden's, unchanged,
// and beside it the ssh config keys added gives, with exactly those values:
// for an array, one map per element, in order. The golden is the JSON as it
// was before those keys existed, so a pass shows that every key a script read
// before is still there, with the value it had.
func requireGoldenWith(t *testing.T, name, got string, added ...map[string]any) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(got), &v), got)
	objects := []any{v}
	if list, ok := v.([]any); ok {
		objects = list
	}
	require.Len(t, objects, len(added))
	for i, o := range objects {
		obj := o.(map[string]any)
		for _, k := range sshConfigKeys {
			want, ok := added[i][k]
			if !ok {
				require.NotContains(t, obj, k, "element %d", i)
				continue
			}
			require.Equal(t, want, obj[k], "element %d's %s", i, k)
			delete(obj, k)
		}
	}
	rest, err := json.Marshal(v)
	require.NoError(t, err)
	requireGolden(t, name, string(rest))
}

// The JSON says a first-use pin's caveat with it, as the command does: a
// script that adds knownHosts to a file adds the comment that says so.
func TestSessionJSONCarriesAFirstUsePinsCaveat(t *testing.T) {
	line := "@cert-authority uptermd.upterm.dev " + publicRelayKey
	m := currentJSON(t, relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, line, "prompted"))
	require.Equal(t, "prompted", m["relayKeyTrust"])
	require.Equal(t, "# The host's known_hosts didn't have this key when it first connected; the\n"+
		"# host accepted it when upterm asked. Before you add it, compare its\n"+
		"# fingerprint with the one the relay's operator publishes:\n"+
		"#   "+publicRelayFingerprint+"\n"+line, m["knownHosts"])
	require.Equal(t, "Host home\n  HostName uptermd.upterm.dev\n  User "+exampleSessionID, m["sshConfig"])
}

// The banner --detach prints shows the same block for a door: a session with
// a login or forced command, or anything granted without asking. Other
// sessions, and every session in the foreground, are shown as before.
func TestTheDetachBannerShowsADoorsSSHConfig(t *testing.T) {
	prevDetach, prevAccept := flagDetach, flagAccept
	t.Cleanup(func() { flagDetach, flagAccept = prevDetach, prevAccept })
	flagAccept = true

	asked := func(edit func(*api.GetSessionResponse)) *api.GetSessionResponse {
		resp := relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "@cert-authority uptermd.upterm.dev "+publicRelayKey, "known")
		resp.FileTransfer, resp.FileTransferApprovalRequired = proto.String("all"), proto.Bool(true)
		resp.GuestShell, resp.Execution, resp.TcpForwarding = proto.String("shared"), proto.String("approval"), proto.String("loopback-approval")
		if edit != nil {
			edit(resp)
		}
		return resp
	}
	for _, tc := range []struct {
		name   string
		resp   *api.GetSessionResponse
		detach bool
		door   bool
	}{
		{"a login command", asked(func(r *api.GetSessionResponse) { r.LoginCommand = []string{"herdr"} }), true, true},
		{"a forced command", asked(func(r *api.GetSessionResponse) { r.ForceCommand = []string{"herdr"} }), true, true},
		{"commands granted", asked(func(r *api.GetSessionResponse) { r.Execution = proto.String("granted") }), true, true},
		{"loopback forwards granted", asked(func(r *api.GetSessionResponse) { r.TcpForwarding = proto.String("loopback") }), true, true},
		{"forwards anywhere granted", asked(func(r *api.GetSessionResponse) { r.TcpForwarding = proto.String("all") }), true, true},
		{"file transfers granted", asked(func(r *api.GetSessionResponse) { r.FileTransferApprovalRequired = proto.Bool(false) }), true, true},
		{"nothing granted", asked(nil), true, false},
		{"no file transfers to grant", asked(func(r *api.GetSessionResponse) {
			r.FileTransfer, r.FileTransferApprovalRequired = proto.String("off"), proto.Bool(false)
		}), true, false},
		{"a door in the foreground", asked(func(r *api.GetSessionResponse) { r.LoginCommand = []string{"herdr"} }), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flagDetach = tc.detach
			out := captureStdout(t, func() { require.NoError(t, displaySession(context.Background(), tc.resp, "home")) })
			block, err := sshConfigText(tc.resp, "home")
			require.NoError(t, err)
			if !tc.door {
				require.NotContains(t, out, "SSH config")
				require.NotContains(t, out, "Host home")
				return
			}
			want := "➤ SSH config:\n"
			for _, line := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
				want += "    " + line + "\n"
			}
			require.Contains(t, out, want)
		})
	}
}

// --detach -o json carries the block as sshConfig, with the pin, and keeps
// every key it had.
func TestDetachJSONCarriesTheSSHConfig(t *testing.T) {
	stdout := detachJSON(t, func(r *api.GetSessionResponse) {
		r.LoginCommand = []string{"herdr"}
		r.RelayKnownHosts = proto.String("[127.0.0.1]:2222 " + publicRelayKey)
		r.RelayKeyTrust = proto.String("known")
	})
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &m))
	require.Equal(t, "Host s\n  HostName 127.0.0.1\n  User u\n  Port 2222", m["sshConfig"])
	require.Equal(t, "[127.0.0.1]:2222 "+publicRelayKey, m["knownHosts"])
	require.Equal(t, "known", m["relayKeyTrust"])
}

// The command's help says where each part goes, and where else the block is.
func TestSSHConfigHelp(t *testing.T) {
	c := findCommand(t, "upterm session ssh-config")
	long := oneSpaced(c.Long)
	for _, want := range []string{
		"Put the Host block in ~/.ssh/config on each device you connect from.",
		"Add the known_hosts lines to ~/.ssh/known_hosts on each device, once.",
		"'upterm session info NAME -o json' has the same block as sshConfig, and the known_hosts lines as knownHosts, beside how the host came to trust the key (relayKeyTrust).",
	} {
		require.Contains(t, long, want)
	}
	require.Equal(t, "The name to give the session in ~/.ssh/config, for ssh ALIAS (default: the session's name)", c.Flag("alias").Usage)
}
