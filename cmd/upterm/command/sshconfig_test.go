package command

import (
	"context"
	"encoding/base64"
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

// otherAuthorityKey is a certificate authority's key that isn't the relay's
// own, for a relay whose host certificate another key signs.
const otherAuthorityKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIYDCWOa+7MWp4LZrLkQTrf5TgLXSKGwzT15aRto2m3t"

// embeddedSSHUser is the SSH user an embedded-mode relay routes the example
// session by: its ID and, encoded, the node 10.0.0.5:2222 it is on.
const embeddedSSHUser = exampleSessionID + ":MTAuMC4wLjU6MjIyMg=="

// punctuatedSSHUser holds the punctuation a User may have beyond what the
// session ID and the embedded relay's user already use.
const punctuatedSSHUser = "a1.b_c~d+e-f"

// unwritableSSHUsers are SSH users a relay could give that ssh_config doesn't
// read as one word. Written into a Host block, each would add lines of the
// relay's choosing to it, or leave a block that makes ssh refuse the whole
// file it is pasted into.
var unwritableSSHUsers = []struct{ name, user string }{
	{"a newline", exampleSessionID + "\n  ProxyCommand nc relay.example.com 22"},
	{"a double quote", exampleSessionID + `"`},
	{"a leading #", "#" + exampleSessionID},
	{"a percent sign", exampleSessionID + "%h"},
	{"a space", exampleSessionID + " " + exampleSessionID},
}

// unwritableRelays are relay addresses whose URL, as a Host block's
// ProxyCommand would carry it, holds a character outside the few that double
// quotes keep literal both in a POSIX shell and on Windows: a '%' (here an
// IPv6 zone's), a '$', and a quote mark of either kind. sshLine is the ssh
// line of a session on each, which keeps its own quoting.
var unwritableRelays = []struct{ name, relay, sshLine string }{
	{"a percent sign", "ws://[fe80::1%25en0]:8080",
		`ssh -o ProxyCommand='upterm proxy '\''ws://d3k5fia7m4us73ehblug@[fe80::1%%25en0]:8080'\''' d3k5fia7m4us73ehblug@fe80::1%en0:8080`},
	{"a dollar sign", "wss://relay.example.com/$HOME",
		`ssh -o ProxyCommand='upterm proxy '\''wss://d3k5fia7m4us73ehblug@relay.example.com/$HOME'\''' d3k5fia7m4us73ehblug@relay.example.com:443`},
	{"a single quote", "wss://relay.example.com/it's",
		`ssh -o ProxyCommand='upterm proxy '\''wss://d3k5fia7m4us73ehblug@relay.example.com/it'\''\'\'''\''s'\''' d3k5fia7m4us73ehblug@relay.example.com:443`},
	{"a double quote", `wss://re"lay.example.com`,
		`ssh -o ProxyCommand='upterm proxy '\''wss://d3k5fia7m4us73ehblug@re"lay.example.com'\''' d3k5fia7m4us73ehblug@re"lay.example.com:443`},
}

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
		{"public-relay", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "known"), nil},
		// A self-hosted relay routing in embedded mode, which reaches the
		// session by its node as well as its ID.
		{"embedded-relay", relayAnswer("ssh://relay.example.com", embeddedSSHUser, "relay.example.com "+publicRelayKey, "known"), nil},
		{"port", relayAnswer("ssh://relay.example.com:2222", exampleSessionID, "[relay.example.com]:2222 "+publicRelayKey, "known"), nil},
		{"ipv6", relayAnswer("ssh://[::1]:2222", exampleSessionID, "[::1]:2222 "+publicRelayKey, "known"), nil},
		{"wss", relayAnswer("wss://uptermd.upterm.dev", exampleSessionID, "[uptermd.upterm.dev]:443 "+publicRelayKey, "known"), nil},
		{"ws-embedded-relay", relayAnswer("ws://relay.example.com:8080", embeddedSSHUser, "[relay.example.com]:8080 "+publicRelayKey, "known"), nil},
		// A relay whose host certificate another key signs, for the host the
		// session dialled, which the host trusted as that certificate's
		// authority.
		{"authority", relayAnswer("ssh://relay.example.com", exampleSessionID, "@cert-authority relay.example.com "+otherAuthorityKey, "known"), nil},
		{"prompted", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "prompted"), nil},
		{"auto-accepted", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "auto-accepted"), nil},
		{"unreported", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "", ""), nil},
		// A way of trusting the key this version doesn't know is not read as
		// known.
		{"unknown-trust", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "pinned-elsewhere"), nil},
		{"alias", relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "known"), []string{"--alias", "laptop-home"}},
		// A user with the rest of the punctuation a User may have.
		{"punctuation", relayAnswer("ssh://uptermd.upterm.dev:22", punctuatedSSHUser, "uptermd.upterm.dev "+publicRelayKey, "known"), nil},
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

// The ssh line's ProxyCommand keeps the single quotes it has always had: the
// line is quoted for a POSIX shell, and sshCommand is a value scripts read.
// Only the Host block's ProxyCommand is in double quotes. Each row's line is
// the one a session on its relay has always had, for the ws and wss relays of
// the goldens and for the relay addresses the block isn't written for.
func TestTheSSHLineKeepsItsQuotes(t *testing.T) {
	rows := []struct{ name, relay, user, sshLine string }{
		{"wss", "wss://uptermd.upterm.dev", exampleSessionID,
			`ssh -o ProxyCommand='upterm proxy '\''wss://d3k5fia7m4us73ehblug@uptermd.upterm.dev'\''' d3k5fia7m4us73ehblug@uptermd.upterm.dev:443`},
		{"ws-embedded-relay", "ws://relay.example.com:8080", embeddedSSHUser,
			`ssh -o ProxyCommand='upterm proxy '\''ws://d3k5fia7m4us73ehblug:MTAuMC4wLjU6MjIyMg==@relay.example.com:8080'\''' d3k5fia7m4us73ehblug:MTAuMC4wLjU6MjIyMg==@relay.example.com:8080`},
	}
	for _, r := range unwritableRelays {
		rows = append(rows, struct{ name, relay, user, sshLine string }{"a relay address with " + r.name, r.relay, exampleSessionID, r.sshLine})
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			servedReady(t, "home", relayAnswer(tc.relay, tc.user, "[relay.example.com]:443 "+publicRelayKey, "known"))
			require.Equal(t, tc.sshLine, cliJSON(t, "session", "info", "home", "-o", "json")["sshCommand"])
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

// The session has to be one guests can connect to now, on a relay ssh can
// reach, and the alias one ssh can be given; otherwise there is nothing to
// print, and upterm says why.
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
		{"a relay ssh can't reach", func(t *testing.T) {
			servedReady(t, "home", relayAnswer("https://relay.example.com", exampleSessionID, "relay.example.com "+publicRelayKey, "known"))
		}, nil, 1, "upterm: the session's relay https://relay.example.com is not one ssh can reach"},
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

// A relay's SSH user that ssh_config doesn't read as one word is never
// written into a Host block: `session ssh-config` refuses, naming the session
// as it was given, and never the value. The same goes for the user upterm
// makes from the session's ID for a relay that doesn't send one.
func TestSSHConfigRefusesAnSSHUserItWontWrite(t *testing.T) {
	type refusal struct {
		name, arg string
		resp      *api.GetSessionResponse
	}
	var refusals []refusal
	for _, u := range unwritableSSHUsers {
		for _, arg := range []string{"home", exampleSessionID} {
			refusals = append(refusals, refusal{u.name + "/by " + arg, arg,
				relayAnswer("ssh://uptermd.upterm.dev:22", u.user, "uptermd.upterm.dev "+publicRelayKey, "known")})
		}
	}
	madeFromTheID := relayAnswer("ssh://uptermd.upterm.dev:22", "", "uptermd.upterm.dev "+publicRelayKey, "known")
	madeFromTheID.SessionId = "#" + exampleSessionID
	refusals = append(refusals, refusal{"a user made from the session's ID", "home", madeFromTheID})

	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			servedReady(t, "home", tc.resp)
			stdout, stderr, code := runCLI(t, "session", "ssh-config", tc.arg)
			require.Equal(t, 1, code, stderr)
			require.Empty(t, stdout)
			require.Equal(t, "upterm: the relay gave session "+tc.arg+" an SSH user that upterm won't write into an ssh config\n", stderr)
		})
	}
}

// Nor is a relay address whose URL a Host block's ProxyCommand couldn't hold
// in double quotes as it is: `session ssh-config` refuses, naming the session
// as it was given, and never the address.
func TestSSHConfigRefusesARelayAddressItWontWrite(t *testing.T) {
	for _, r := range unwritableRelays {
		for _, arg := range []string{"home", exampleSessionID} {
			t.Run(r.name+"/by "+arg, func(t *testing.T) {
				setupSessionRoots(t)
				withConfig(t, "")
				servedReady(t, "home", relayAnswer(r.relay, exampleSessionID, "[relay.example.com]:443 "+publicRelayKey, "known"))
				stdout, stderr, code := runCLI(t, "session", "ssh-config", arg)
				require.Equal(t, 1, code, stderr)
				require.Empty(t, stdout)
				require.Equal(t, "upterm: the relay address for session "+arg+" has characters that upterm won't write into an ssh config\n", stderr)
			})
		}
	}
}

// The users a Host block takes are the ones relays give: a session ID, an
// embedded relay's ID and node, the node in URL-safe base64 with its '='
// padding, and the rest of the punctuation sshUserRe allows. Nothing else is
// written, an empty user included: sshUser never makes one, but a block with
// one would have a User line that ssh refuses.
func TestSSHConfigWritesOnlyTheSSHUsersRelaysGive(t *testing.T) {
	for _, user := range []string{
		exampleSessionID,
		embeddedSSHUser,
		exampleSessionID + ":" + base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff}),
		punctuatedSSHUser,
	} {
		require.True(t, sshUserRe.MatchString(user), "%q", user)
	}
	require.False(t, sshUserRe.MatchString(""), "an empty user")
	for _, u := range unwritableSSHUsers {
		require.False(t, sshUserRe.MatchString(u.user), u.name)
	}
}

// The URLs a Host block's ProxyCommand takes are those of the relays upterm
// hosts dial: a host name or a bracketed IPv6 address, a port, a path, and the
// user, an embedded relay's ID and node in URL-safe base64 included. Nothing
// else is, so that nothing between the double quotes is read as more than
// itself: not '%', which ssh reads as a token, nor '$', '`', '\', '!', either
// quote mark, whitespace, or any other character a shell gives a meaning.
func TestSSHConfigWritesOnlyProxyURLsDoubleQuotesKeepLiteral(t *testing.T) {
	for _, u := range []string{
		"wss://" + exampleSessionID + "@uptermd.upterm.dev",
		"ws://" + embeddedSSHUser + "@relay.example.com:8080",
		"ws://" + exampleSessionID + ":" + base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff}) + "@[::1]:8080/",
		"wss://" + punctuatedSSHUser + "@relay.example.com/~upterm",
	} {
		require.True(t, proxyURLRe.MatchString(u), u)
	}
	for _, c := range []string{"%", "$", "`", `\`, "'", `"`, "!", " ", "\t", "\n", "#", "?", "&", ";", "|", "^", "<", ">", "(", ")", "*"} {
		require.False(t, proxyURLRe.MatchString("wss://"+exampleSessionID+"@relay.example.com/"+c), "%q", c)
	}
}

// cliJSON is what the command line args prints as one JSON object, or for
// a list, its only element.
func cliJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	stdout, stderr, code := runCLI(t, args...)
	require.Equal(t, 0, code, stderr)
	var v any
	require.NoError(t, json.Unmarshal([]byte(stdout), &v), stdout)
	if list, ok := v.([]any); ok {
		require.Len(t, list, 1, stdout)
		v = list[0]
	}
	return v.(map[string]any)
}

// The JSON doesn't carry such a block either, for the relay's SSH user or for
// its address: sshConfig is left out wherever it would be, and the relay's key
// is reported as it is for any session. A user a relay gives that ssh_config
// does read as one word is written as it is.
func TestSessionJSONLeavesOutAnSSHConfigItWontWrite(t *testing.T) {
	// The JSON of each command that reports sshConfig, for a session named
	// home whose daemon answers with resp.
	commands := []struct {
		name string
		json func(t *testing.T, resp *api.GetSessionResponse) map[string]any
	}{
		{"session current", currentJSON},
		{"session info", func(t *testing.T, resp *api.GetSessionResponse) map[string]any {
			setupSessionRoots(t)
			withConfig(t, "")
			servedReady(t, "home", resp)
			return cliJSON(t, "session", "info", "home", "-o", "json")
		}},
		{"session list", func(t *testing.T, resp *api.GetSessionResponse) map[string]any {
			setupSessionRoots(t)
			withConfig(t, "")
			servedReady(t, "home", resp)
			return cliJSON(t, "session", "list", "-o", "json")
		}},
	}
	const pin = "uptermd.upterm.dev " + publicRelayKey
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			for _, u := range unwritableSSHUsers {
				t.Run(u.name, func(t *testing.T) {
					m := c.json(t, relayAnswer("ssh://uptermd.upterm.dev:22", u.user, pin, "known"))
					require.NotContains(t, m, "sshConfig")
					require.Equal(t, pin, m["knownHosts"])
					require.Equal(t, "known", m["relayKeyTrust"])
				})
			}
			for _, r := range unwritableRelays {
				t.Run("a relay address with "+r.name, func(t *testing.T) {
					m := c.json(t, relayAnswer(r.relay, exampleSessionID, pin, "known"))
					require.NotContains(t, m, "sshConfig")
					require.Equal(t, pin, m["knownHosts"])
					require.Equal(t, "known", m["relayKeyTrust"])
				})
			}
			t.Run("a punctuated user", func(t *testing.T) {
				m := c.json(t, relayAnswer("ssh://uptermd.upterm.dev:22", punctuatedSSHUser, pin, "known"))
				require.Equal(t, "Host home\n  HostName uptermd.upterm.dev\n  User "+punctuatedSSHUser, m["sshConfig"])
			})
		})
	}

	// --detach -o json, from the daemon it started.
	t.Run("host --detach", func(t *testing.T) {
		const pin = "[127.0.0.1]:2222 " + publicRelayKey
		detached := func(t *testing.T, edit func(*api.GetSessionResponse)) map[string]any {
			stdout := detachJSON(t, func(r *api.GetSessionResponse) {
				edit(r)
				r.RelayKnownHosts, r.RelayKeyTrust = proto.String(pin), proto.String("known")
			})
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &m), stdout)
			return m
		}
		for _, u := range unwritableSSHUsers {
			t.Run(u.name, func(t *testing.T) {
				m := detached(t, func(r *api.GetSessionResponse) { r.SshUser = u.user })
				require.NotContains(t, m, "sshConfig")
				require.Equal(t, pin, m["knownHosts"])
				require.Equal(t, "known", m["relayKeyTrust"])
			})
		}
		for _, rel := range unwritableRelays {
			t.Run("a relay address with "+rel.name, func(t *testing.T) {
				m := detached(t, func(r *api.GetSessionResponse) { r.Host = rel.relay })
				require.NotContains(t, m, "sshConfig")
				require.Equal(t, pin, m["knownHosts"])
				require.Equal(t, "known", m["relayKeyTrust"])
			})
		}
		t.Run("a punctuated user", func(t *testing.T) {
			m := detached(t, func(r *api.GetSessionResponse) { r.SshUser = punctuatedSSHUser })
			require.Equal(t, "Host s\n  HostName 127.0.0.1\n  User "+punctuatedSSHUser+"\n  Port 2222", m["sshConfig"])
		})
	})
}

// A daemon that gives no name has its block named by the session's ID, which
// is the relay's: only when it is a name --alias could give.
func TestCurrentJSONNamesTheBlockByTheSessionIDOnlyWhenSSHTakesIt(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		want     string // empty for no sshConfig
	}{
		{"an ID", exampleSessionID, "Host " + exampleSessionID + "\n  HostName uptermd.upterm.dev\n  User " + exampleSessionID},
		{"an ID with a newline", exampleSessionID + "\nHost *", ""},
		{"an ID with a leading #", "#" + exampleSessionID, ""},
		{"an ID with a space", exampleSessionID + " *", ""},
		{"an ID that is a pattern", "*", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "known")
			resp.SessionId, resp.Name = tc.id, nil
			m := currentJSON(t, resp)
			if tc.want == "" {
				require.NotContains(t, m, "sshConfig")
			} else {
				require.Equal(t, tc.want, m["sshConfig"])
			}
			require.Equal(t, "uptermd.upterm.dev "+publicRelayKey, m["knownHosts"])
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
	line := "uptermd.upterm.dev " + publicRelayKey
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
		resp := relayAnswer("ssh://uptermd.upterm.dev:22", exampleSessionID, "uptermd.upterm.dev "+publicRelayKey, "known")
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

// A door's banner leaves its ssh config out when the relay's SSH user or its
// address isn't one it writes, rather than show a block that would add the
// relay's lines to a config, or hand upterm proxy something other than the
// relay's URL.
func TestTheDetachBannerLeavesOutAnSSHConfigItWontWrite(t *testing.T) {
	prevDetach, prevAccept := flagDetach, flagAccept
	t.Cleanup(func() { flagDetach, flagAccept = prevDetach, prevAccept })
	flagDetach, flagAccept = true, true

	type refusal struct {
		name string
		resp *api.GetSessionResponse
	}
	var refusals []refusal
	for _, u := range unwritableSSHUsers {
		refusals = append(refusals, refusal{u.name, relayAnswer("ssh://uptermd.upterm.dev:22", u.user, "uptermd.upterm.dev "+publicRelayKey, "known")})
	}
	for _, r := range unwritableRelays {
		refusals = append(refusals, refusal{"a relay address with " + r.name, relayAnswer(r.relay, exampleSessionID, "[relay.example.com]:443 "+publicRelayKey, "known")})
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			tc.resp.LoginCommand = []string{"herdr"}
			out := captureStdout(t, func() { require.NoError(t, displaySession(context.Background(), tc.resp, "home")) })
			require.Contains(t, out, "Session: "+exampleSessionID+"\n", "the banner is printed")
			require.NotContains(t, out, "SSH config")
			require.NotContains(t, out, "Host home")
			require.NotContains(t, out, "known_hosts")
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
		"Its User is the session's SSH user, which changes whenever the session restarts, and on a relay that routes by node, also when the session comes back on another node: run this again then, and replace the block.",
		"Add the known_hosts lines to ~/.ssh/known_hosts on each device, once.",
		"With no comment above it, a line already in the host's known_hosts matched the key, which makes it only as good as that line.",
		"'upterm session info NAME -o json' has the same block as sshConfig, and the known_hosts lines as knownHosts, beside how the host came to trust the key (relayKeyTrust).",
	} {
		require.Contains(t, long, want)
	}
	require.Equal(t, "The name to give the session in ~/.ssh/config, for ssh ALIAS (default: the session's name)", c.Flag("alias").Usage)
}
