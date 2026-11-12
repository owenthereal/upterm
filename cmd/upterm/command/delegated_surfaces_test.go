package command

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// A delegated session as these tests stage it. The routing ID is one that
// can appear in no other text, so that a line holding it is one that printed
// it.
const (
	testDelegatedService = "https://authority.example"
	testDelegatedAccount = "11111111-1111-4111-8111-111111111111"
	testDelegatedLogin   = "22222222-2222-4222-8222-222222222222"
	testExternalID       = "33333333-3333-4333-8333-333333333333"
	testSupersededID     = "44444444-4444-4444-8444-444444444444"
	testRoutingID        = "rtidrtidrtidrtidrtid"
	testGuestAddress     = "claim-work"
)

// testDelegation is the delegation a delegated host records for a run placed
// on relay, its display naming authority.
func testDelegation(authority, relay string) *sessiondir.Delegation {
	return &sessiondir.Delegation{
		DelegationAssociation: sessiondir.DelegationAssociation{
			Service: testDelegatedService, Account: testDelegatedAccount, Login: testDelegatedLogin,
		},
		DelegationDisplay: sessiondir.DelegationDisplay{
			Authority: authority,
			Links:     []sessiondir.DelegationLink{{Label: "Dashboard", URL: "https://authority.example/s"}},
			Notes:     []string{"Guests sign in first."},
		},
		ExternalSessionID: testExternalID,
		RoutingID:         testRoutingID,
		Relay:             relay,
		GuestAddress:      testGuestAddress,
	}
}

// The relay a delegated session's daemon says it is connected to, which is
// none of the relays its record names, so that a surface that built a way
// in from the daemon's answer rather than from the record would be caught.
const (
	testAnswerNode = "node-1.example.net:2201"
	testAnswerHost = "ssh://" + testAnswerNode
)

// delegatedAnswer is what a delegated session's daemon answers: the session
// at its guest address, under the routing ID, at the daemon's own node. It
// says open, which a delegated session's daemon never does, so that a reader
// that took it at its word would be caught.
func delegatedAnswer(name string) *api.GetSessionResponse {
	return &api.GetSessionResponse{
		SessionId: testRoutingID, Host: testAnswerHost, NodeAddr: testAnswerNode, SshUser: testGuestAddress,
		Command: []string{"bash"}, Open: true, Name: proto.String(name), Status: proto.String(sessiondir.StatusReady),
		DelegatedAddress: proto.String(testGuestAddress),
	}
}

// heldDelegated claims name for a delegated session with delegation d, its
// record saying status, and, when answer is set, serves its admin socket as
// its daemon would, for the launch that holds it.
func heldDelegated(t *testing.T, name string, d *sessiondir.Delegation, status string, answer *api.GetSessionResponse) *sessiondir.Dir {
	t.Helper()
	dir := claimSession(t, name)
	releaseAtEnd(t, dir)
	require.NoError(t, dir.Update(func(r *sessiondir.Record) {
		r.Status = status
		r.SessionID = d.RoutingID
		r.HostKeys = []string{testHostKeyLine(t)}
		r.Delegation = d
	}))
	if answer != nil {
		answer.LaunchId = dir.LaunchID()
		answer.Status = proto.String(status)
		serveStubAdmin(t, dir.AdminSocket(), answer)
	}
	return dir
}

// jsonObject is the JSON object in out.
func jsonObject(t *testing.T, out string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &m), out)
	return m
}

// delegatedDetach runs a detached upterm host -o json --accept of the
// session "s" whose record is dir's, against a daemon that reports it as
// delegated on relay at address, under the routing ID the relay gave it,
// and returns what it printed.
func delegatedDetach(t *testing.T, dir *sessiondir.Dir, relay, address string) (stdout, stderr string) {
	t.Helper()
	spawn, d := newScriptedDaemon(t)
	d.launchID, d.sessionID = dir.LaunchID(), testRoutingID
	d.open = true
	d.amend = func(r *api.GetSessionResponse) {
		r.Host, r.SshUser = "ssh://"+relay, address
		r.DelegatedAddress = proto.String(address)
	}
	var out, errOut bytes.Buffer
	s := newSession(t, spawn, nil, &out, &errOut)
	s.detach, s.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.start() }()
	require.NoError(t, s.run(context.Background()))
	return out.String(), errOut.String()
}

// The texts that name a delegated session's authority, each as the record of
// the session says it, with the authority's name and with none.
func TestDelegatedTextsNameTheAuthority(t *testing.T) {
	for _, tc := range []struct{ authority, mid, start string }{
		{"Example Authority", "Example Authority", "Example Authority"},
		{"", "the session's authority", "The session's authority"},
	} {
		t.Run(tc.start, func(t *testing.T) {
			setupSessionRoots(t)
			d := testDelegation(tc.authority, "relay.example.com:22")
			dir := heldDelegated(t, "work", d, sessiondir.StatusDisconnected, nil)
			require.NoError(t, dir.Update(func(r *sessiondir.Record) {
				r.TunnelReason = sessiondir.TunnelReasonWithdrawn
				dd := *r.Delegation
				dd.Decision = sessiondir.DecisionWithdrawn
				r.Delegation = &dd
			}))
			rec := dir.Record()

			// session info's summary, which says who decides its guests.
			var summary bytes.Buffer
			writeSessionSummary(&summary, infoFromRecord(&rec, rec.Status), 0)
			require.Contains(t, summary.String(), tuiRow("Access:", "decided by "+tc.mid))

			// The hint rows.
			require.Equal(t, "the relay refused this session's registration with "+tc.mid+"; upterm keeps retrying, slowly.",
				tui.StatusHint(tui.SessionDetail{Status: sessiondir.StatusReconnecting, TunnelReason: sessiondir.TunnelReasonAuthorityRefused, Delegation: rec.Delegation}))
			require.Equal(t, tc.start+" withdrew remote access. The command is still running locally.",
				tui.StatusHint(tui.SessionDetail{Status: rec.Status, TunnelReason: rec.TunnelReason, Delegation: rec.Delegation}))
			require.Equal(t, tc.start+" withdrew remote access. The command is still running locally as work. "+
				"Use upterm attach work to return, or upterm session stop work to stop it.",
				tui.StatusHint(tui.SessionDetail{Name: "work", Status: rec.Status, TunnelReason: rec.TunnelReason, Delegation: rec.Delegation}))

			// ~? once withdrawn.
			lines := renderStatus(statusView{Name: "work", Reason: rec.TunnelReason, Delegation: rec.Delegation}, '~', false)
			require.Equal(t, "upterm: session work: 0 guests; "+tc.mid+" withdrew remote access. The command is still running locally as work.", lines[0])
			require.Equal(t, "upterm: Use upterm attach work to return, or upterm session stop work to stop it.", lines[1])

			// The end-of-attach lines, and the desktop notices made of them.
			withdrawn, stopped := delegatedEndLines(context.Background(), delegatedAnswer("work"), "work", dir.LaunchID())
			require.Equal(t, []string{
				"upterm: " + tc.start + " withdrew remote access. The command is still running locally as work.",
				"Use upterm attach work to return, or upterm session stop work to stop it.",
			}, withdrawn)
			require.Empty(t, stopped)
			n := decisionNotice(rec.Delegation, "work", host.DecisionWithdrawn)
			require.Equal(t, notification{tc.start + " withdrew remote access",
				"The command is still running locally as work.\nUse upterm attach work to return, or upterm session stop work to stop it."}, n)

			require.NoError(t, dir.Update(func(r *sessiondir.Record) {
				r.Status, r.TunnelReason = sessiondir.StatusEnding, ""
				dd := *r.Delegation
				dd.Decision = sessiondir.DecisionStopped
				r.Delegation = &dd
			}))
			withdrawn, stopped = delegatedEndLines(context.Background(), delegatedAnswer("work"), "work", dir.LaunchID())
			require.Empty(t, withdrawn)
			require.Equal(t, "upterm: "+tc.start+" stopped the session. Terminating the hosted command.", stopped)
			n = decisionNotice(rec.Delegation, "work", host.DecisionStopped)
			require.Equal(t, notification{tc.start + " stopped the session", "Terminating the hosted command."}, n)

			// The banner, with its Access row.
			prevAccept := flagAccept
			t.Cleanup(func() { flagAccept = prevAccept })
			flagAccept = true
			require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.Delegation = d }))
			out := captureStdout(t, func() {
				require.NoError(t, displaySession(context.Background(), delegatedAnswer("work"), "work"))
			})
			require.Equal(t, "Session: claim-work\n\n"+
				tuiRow("Name:", "work")+
				tuiRow("Command:", "bash")+
				tuiRow("Relay:", testAnswerHost)+
				tuiRow("Access:", "decided by "+tc.mid)+
				"\n➤ SSH:\n    ssh claim-work@relay.example.com\n"+
				"➤ URI:\n    ssh://claim-work@relay.example.com\n"+
				"➤ Dashboard: https://authority.example/s\n"+
				"Guests sign in first.\n", out)
		})
	}
}

// tuiRow is one labelled row of the detail view.
func tuiRow(label, value string) string {
	return label + strings.Repeat(" ", tui.LabelWidth-len(label)) + value + "\n"
}

// wantDelegation is the delegation object every surface prints, the
// connect strings for relay included.
func wantDelegation(sshCommand, uri string) map[string]any {
	return map[string]any{
		"authority": "Example Authority", "service": testDelegatedService, "account": testDelegatedAccount,
		"login": testDelegatedLogin, "externalSessionId": testExternalID, "guestAddress": testGuestAddress,
		"sshCommand": sshCommand, "uri": uri,
		"links":               []any{map[string]any{"label": "Dashboard", "url": "https://authority.example/s"}},
		"notes":               []any{"Guests sign in first."},
		"supersededSessionId": testSupersededID, "decision": sessiondir.DecisionStopped,
	}
}

// Each JSON surface carries a delegated session's object, read from its
// record, beside the keys every session has: the routing ID as sessionId, no
// open session, and access the authority's.
func TestDelegatedJSONObject(t *testing.T) {
	for _, tc := range []struct{ relay, ssh, uri string }{
		{"relay.example.com:22", "ssh claim-work@relay.example.com", "ssh://claim-work@relay.example.com"},
		{"relay.example.com:2222", "ssh claim-work@relay.example.com -p 2222", "ssh://claim-work@relay.example.com:2222"},
	} {
		t.Run(tc.relay, func(t *testing.T) {
			setupSessionRoots(t)
			d := testDelegation("Example Authority", tc.relay)
			d.SupersededSessionID, d.Decision = testSupersededID, sessiondir.DecisionStopped
			dir := heldDelegated(t, "work", d, sessiondir.StatusReady, delegatedAnswer("work"))
			want := wantDelegation(tc.ssh, tc.uri)
			// sessionId is the session's ID, which for a delegated session
			// is its routing ID: the one its daemon reports, as the relay
			// gave it.
			check := func(surface string, got map[string]any) {
				t.Helper()
				require.Equal(t, want, got["delegation"], surface)
				require.NotContains(t, got, "open", surface+": no delegated session is open")
				require.Equal(t, tui.AccessDelegated, got["access"], surface)
				require.Equal(t, testRoutingID, got["sessionId"], surface)
			}

			stdout, stderr, code := runCLI(t, "session", "info", "work", "-o", "json")
			require.Equal(t, 0, code, stderr)
			check("session info", jsonObject(t, stdout))

			stdout, stderr, code = runCLI(t, "session", "list", "-o", "json")
			require.Equal(t, 0, code, stderr)
			var listed []map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &listed), stdout)
			require.Len(t, listed, 1)
			check("session list", listed[0])

			stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
			require.Equal(t, 0, code, stderr)
			check("session current", jsonObject(t, stdout))

			// The detached host's, with --accept: no open-session warning,
			// whatever the daemon says.
			releaseOnce(dir)
			s := claimSession(t, "s")
			releaseAtEnd(t, s)
			require.NoError(t, s.Update(func(r *sessiondir.Record) {
				r.Status, r.SessionID, r.Delegation = sessiondir.StatusReady, testRoutingID, d
			}))
			stdout, stderr = delegatedDetach(t, s, tc.relay, testGuestAddress)
			check("host --detach", jsonObject(t, stdout))
			require.Empty(t, stderr, "no open-session warning for a session its authority decides")
		})
	}
}

// A delegation with nothing optional in it says so the same way on every
// JSON surface: no session it superseded and no decision, rather than empty
// ones, and links and notes as empty lists, never null.
func TestDelegatedJSONObjectWithNothingOptional(t *testing.T) {
	setupSessionRoots(t)
	d := testDelegation("Example Authority", "relay.example.com:22")
	d.Links, d.Notes = nil, nil
	dir := heldDelegated(t, "work", d, sessiondir.StatusReady, delegatedAnswer("work"))
	check := func(surface string, got map[string]any) {
		t.Helper()
		delegation, ok := got["delegation"].(map[string]any)
		require.True(t, ok, "%s: %v", surface, got)
		require.NotContains(t, delegation, "supersededSessionId", surface)
		require.NotContains(t, delegation, "decision", surface)
		require.Equal(t, []any{}, delegation["links"], surface)
		require.Equal(t, []any{}, delegation["notes"], surface)
	}

	stdout, stderr, code := runCLI(t, "session", "info", "work", "-o", "json")
	require.Equal(t, 0, code, stderr)
	check("session info", jsonObject(t, stdout))

	stdout, stderr, code = runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code, stderr)
	var listed []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &listed), stdout)
	require.Len(t, listed, 1)
	check("session list", listed[0])

	stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
	require.Equal(t, 0, code, stderr)
	check("session current", jsonObject(t, stdout))

	releaseOnce(dir)
	s := claimSession(t, "s")
	releaseAtEnd(t, s)
	require.NoError(t, s.Update(func(r *sessiondir.Record) {
		r.Status, r.SessionID, r.Delegation = sessiondir.StatusReady, testRoutingID, d
	}))
	stdout, _ = delegatedDetach(t, s, "relay.example.com:22", testGuestAddress)
	check("host --detach", jsonObject(t, stdout))
}

// The URI's user is percent-encoded byte by byte: every byte outside RFC
// 3986's unreserved set, and none inside it.
func TestDelegatedURIEncodesTheUser(t *testing.T) {
	require.Equal(t, "a%2Bb", uriUser("a+b"))
	unreserved := regexp.MustCompile(`^[A-Za-z0-9._~-]$`)
	for b := range 256 {
		s := string([]byte{byte(b)})
		want := s
		if !unreserved.MatchString(s) {
			want = "%" + strings.ToUpper(strconv.FormatInt(int64(b)|0x100, 16)[1:])
		}
		require.Equal(t, want, uriUser(s), "byte %#x", b)
		if got, err := url.PathUnescape(uriUser(s)); err == nil {
			require.Equal(t, s, got, "byte %#x round-trips", b)
		}
	}
}

// normalizedJSON is out with what changes from run to run put back to fixed
// values: the launch, the directory the session's sockets are in, and the pid.
// A path under that directory is matched as JSON quotes it, which on Windows
// doubles every backslash, and written back as /ROOT and the rest of the path
// with '/' between its parts, as the goldens have it on every platform.
func normalizedJSON(t *testing.T, out, launchID string) string {
	t.Helper()
	out = strings.ReplaceAll(out, launchID, "LAUNCH")
	quoted, err := json.Marshal(os.Getenv("XDG_RUNTIME_DIR"))
	require.NoError(t, err)
	root := strings.Trim(string(quoted), `"`)
	out = regexp.MustCompile(regexp.QuoteMeta(root)+`[^"]*`).ReplaceAllStringFunc(out, func(path string) string {
		return "/ROOT" + strings.ReplaceAll(strings.TrimPrefix(path, root), `\\`, "/")
	})
	return regexp.MustCompile(`"pid": [0-9]+`).ReplaceAllString(out, `"pid": 1`)
}

// ordinaryAnswer is what an ordinary session's daemon answers, with every
// field a current daemon sends.
func ordinaryAnswer() *api.GetSessionResponse {
	return &api.GetSessionResponse{
		SessionId: "sid-1", Host: "ssh://127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", SshUser: "sid-1",
		Command: []string{"bash"}, Open: true, Name: proto.String("plain"), Status: proto.String(sessiondir.StatusReady),
		Reconnect: proto.String(sessiondir.ReconnectSupported), TunnelReason: proto.String(""),
		StartConfirmed: proto.Bool(false), ReadOnly: proto.Bool(false), FileTransfer: proto.String("all"),
		FileTransferApprovalRequired: proto.Bool(true), LocalForwarding: proto.Bool(false),
		GuestShell: proto.String("shared"), Execution: proto.String("approval"), TcpForwarding: proto.String("loopback-approval"),
		ApprovalMethod: proto.String("terminal"), JoinState: &api.JoinState{},
		RelayKnownHosts: proto.String("[127.0.0.1]:2222 " + publicRelayKey), RelayKeyTrust: proto.String("known"),
	}
}

// What an ordinary session's four JSON surfaces print is what they printed
// before delegated sessions, byte for byte: the same keys, the same values.
func TestJSONStaysASuperset(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "plain")
	releaseAtEnd(t, dir)
	require.NoError(t, dir.Update(func(r *sessiondir.Record) {
		r.Status, r.SessionID, r.Reconnect = sessiondir.StatusReady, "sid-1", sessiondir.ReconnectSupported
		r.HostKeys = []string{testHostKeyLine(t)}
	}))
	answer := ordinaryAnswer()
	answer.LaunchId = dir.LaunchID()
	serveStubAdmin(t, dir.AdminSocket(), answer)

	stdout, stderr, code := runCLI(t, "session", "info", "plain", "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, wantOrdinaryInfo, normalizedJSON(t, stdout, dir.LaunchID()))

	stdout, stderr, code = runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, wantOrdinaryList, normalizedJSON(t, stdout, dir.LaunchID()))

	stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, wantOrdinaryCurrent, normalizedJSON(t, stdout, dir.LaunchID()))

	releaseOnce(dir)
	s := claimSession(t, "s")
	releaseAtEnd(t, s)
	require.NoError(t, s.Update(func(r *sessiondir.Record) { r.Status, r.SessionID = sessiondir.StatusReady, "sid-1" }))
	spawn, d := newScriptedDaemon(t)
	d.launchID, d.open = s.LaunchID(), true
	var out, errOut bytes.Buffer
	ss := newSession(t, spawn, nil, &out, &errOut)
	ss.detach, ss.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.start() }()
	require.NoError(t, ss.run(context.Background()))
	require.Equal(t, wantOrdinaryDetach, normalizedJSON(t, out.String(), s.LaunchID()))
	require.Equal(t, openSessionWarning+"\n", errOut.String(), "an open session is still warned about")
}

// The JSON the surfaces printed for TestJSONStaysASuperset's session before
// delegated sessions, normalized as normalizedJSON does.
const (
	wantOrdinaryInfo = `{
  "name": "plain",
  "launchId": "LAUNCH",
  "status": "ready",
  "sessionId": "sid-1",
  "adminSocket": "/ROOT/upterm/sessions/plain/admin.sock",
  "attachSocket": "/ROOT/upterm/sessions/plain/attach.sock",
  "pid": 1,
  "command": "bash",
  "sshCommand": "ssh sid-1@127.0.0.1 -p 2222",
  "joinCommand": "upterm join ssh://sid-1@127.0.0.1:2222",
  "sshConfig": "Host plain\n  HostName 127.0.0.1\n  User sid-1\n  Port 2222",
  "host": "ssh://127.0.0.1:2222",
  "clientCount": 0,
  "guestCount": 0,
  "countsKnown": true,
  "reason": "unknown",
  "open": true,
  "access": "anyone",
  "startConfirmed": false,
  "readOnly": false,
  "fileTransfer": "all",
  "fileTransferApprovalRequired": true,
  "localForwarding": false,
  "guestShell": "shared",
  "execution": "approval",
  "tcpForwarding": "loopback-approval",
  "approvalMethod": "terminal",
  "knownHosts": "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4",
  "relayKeyTrust": "known",
  "joinStateSource": "daemon",
  "reconnect": "supported"
}
`
	wantOrdinaryList = `[
  {
    "name": "plain",
    "launchId": "LAUNCH",
    "status": "ready",
    "sessionId": "sid-1",
    "adminSocket": "/ROOT/upterm/sessions/plain/admin.sock",
    "attachSocket": "/ROOT/upterm/sessions/plain/attach.sock",
    "pid": 1,
    "command": "bash",
    "sshCommand": "ssh sid-1@127.0.0.1 -p 2222",
    "joinCommand": "upterm join ssh://sid-1@127.0.0.1:2222",
    "sshConfig": "Host plain\n  HostName 127.0.0.1\n  User sid-1\n  Port 2222",
    "host": "ssh://127.0.0.1:2222",
    "clientCount": 0,
    "guestCount": 0,
    "countsKnown": true,
    "reason": "unknown",
    "open": true,
    "access": "anyone",
    "startConfirmed": false,
    "readOnly": false,
    "fileTransfer": "all",
    "fileTransferApprovalRequired": true,
    "localForwarding": false,
    "guestShell": "shared",
    "execution": "approval",
    "tcpForwarding": "loopback-approval",
    "approvalMethod": "terminal",
    "knownHosts": "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4",
    "relayKeyTrust": "known",
    "joinStateSource": "daemon",
    "reconnect": "supported"
  }
]
`
	wantOrdinaryCurrent = `{
  "sessionId": "sid-1",
  "clientCount": 0,
  "host": "ssh://127.0.0.1:2222",
  "command": "bash",
  "forceCommand": "",
  "guestCount": 0,
  "countsKnown": true,
  "access": "anyone",
  "launchId": "LAUNCH",
  "open": true,
  "joinStateSource": "daemon",
  "name": "plain",
  "status": "ready",
  "reconnect": "supported",
  "startConfirmed": false,
  "readOnly": false,
  "fileTransfer": "all",
  "fileTransferApprovalRequired": true,
  "localForwarding": false,
  "guestShell": "shared",
  "execution": "approval",
  "tcpForwarding": "loopback-approval",
  "approvalMethod": "terminal",
  "knownHosts": "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4",
  "relayKeyTrust": "known",
  "sshCommand": "ssh sid-1@127.0.0.1 -p 2222",
  "joinCommand": "upterm join ssh://sid-1@127.0.0.1:2222",
  "sshConfig": "Host plain\n  HostName 127.0.0.1\n  User sid-1\n  Port 2222"
}
`
	wantOrdinaryDetach = `{
  "name": "s",
  "launchId": "LAUNCH",
  "status": "ready",
  "sessionId": "sid-1",
  "adminSocket": "/run/a.sock",
  "attachSocket": "/run/t.sock",
  "logPath": "/var/log/upterm.log",
  "pid": 1,
  "command": "bash",
  "sshCommand": "ssh u@127.0.0.1 -p 2222",
  "joinCommand": "upterm join ssh://u@127.0.0.1:2222",
  "sshConfig": "Host s\n  HostName 127.0.0.1\n  User u\n  Port 2222",
  "host": "ssh://127.0.0.1:2222",
  "clientCount": 0,
  "guestCount": 0,
  "countsKnown": false,
  "reason": "unknown",
  "open": true,
  "access": "anyone",
  "joinStateSource": "daemon"
}
`
)

// Wherever a person reads a delegated session, it is named by its guest
// address, never by its routing ID: the banner's title, the list's SESSION
// ID column, session info's and session current's views and ~?'s lines.
func TestHumanOutputShowsTheGuestAddress(t *testing.T) {
	setupSessionRoots(t)
	prevAccept := flagAccept
	t.Cleanup(func() { flagAccept = prevAccept })
	flagAccept = true
	d := testDelegation("Example Authority", "relay.example.com:2222")
	dir := heldDelegated(t, "work", d, sessiondir.StatusReady, delegatedAnswer("work"))
	noRoutingID := func(surface, out string) {
		t.Helper()
		require.NotContains(t, out, testRoutingID, surface)
	}

	banner := captureStdout(t, func() {
		require.NoError(t, displaySession(context.Background(), delegatedAnswer("work"), "work"))
	})
	require.True(t, strings.HasPrefix(banner, "Session: claim-work\n"), banner)
	noRoutingID("banner", banner)

	stdout, stderr, code := runCLI(t, "session", "list")
	require.Equal(t, 0, code, stderr)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	require.Len(t, lines, 2, stdout)
	require.Equal(t, []string{"work", "ready", testGuestAddress, "bash", testAnswerHost}, strings.Fields(lines[1]))
	noRoutingID("session list", stdout)

	stdout, stderr, code = runCLI(t, "session", "info", "work")
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "Session: claim-work\n"), stdout)
	require.Contains(t, stdout, "    ssh claim-work@relay.example.com -p 2222\n")
	noRoutingID("session info", stdout)

	stdout, stderr, code = runCurrent(t, dir.AdminSocket())
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "Session: claim-work\n"), stdout)
	noRoutingID("session current", stdout)

	status := statusLines(context.Background(), statusSource{Name: "work", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~'}, nil)
	require.Contains(t, status, "upterm: guests join with: ssh claim-work@relay.example.com -p 2222")
	noRoutingID("~?", strings.Join(status, "\n"))

	// Once withdrawn, session info's summary says so, still without the ID.
	require.NoError(t, dir.Update(func(r *sessiondir.Record) {
		r.Status, r.TunnelReason = sessiondir.StatusDisconnected, sessiondir.TunnelReasonWithdrawn
	}))
	stdout, stderr, code = runCLI(t, "session", "info", "work")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, oneSpaced(stdout), "Example Authority withdrew remote access.")
	noRoutingID("session info, withdrawn", stdout)
}

// fallbackBanner is the banner of the delegated session "work" whose record
// doesn't confirm the daemon's answer: titled with its name, with who decides
// its guests, and with no address and no way in.
var fallbackBanner = "Session: work\n\n" +
	tuiRow("Name:", "work") +
	tuiRow("Command:", "bash") +
	tuiRow("Relay:", testAnswerHost) +
	tuiRow("Access:", "decided by the session's authority")

// noDelegatedView fails unless out, what a surface printed, offers neither
// guest address, nor any way in; and, where it is a person's to read rather
// than JSON, which keeps the session's ID, not the routing ID either.
func noDelegatedView(t *testing.T, surface, out string, addresses ...string) {
	t.Helper()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") && !strings.HasPrefix(strings.TrimSpace(out), "[") {
		addresses = append(addresses, testRoutingID)
	}
	for _, a := range addresses {
		require.NotContains(t, out, a, surface)
	}
	for _, way := range []string{"➤", "sshCommand", "joinCommand", "sshConfig", `"uri"`, "guests join with"} {
		require.NotContains(t, out, way, surface)
	}
}

// When a delegated session's daemon answers with a guest address its record
// doesn't hold, the two describe no one session: every surface falls back
// to the session's name, with neither address and no way in.
func TestDisagreeingDaemonGetsNoDelegatedView(t *testing.T) {
	setupSessionRoots(t)
	prevAccept := flagAccept
	t.Cleanup(func() { flagAccept = prevAccept })
	flagAccept = true
	const other = "claim-other"
	d := testDelegation("Example Authority", "relay.example.com:22")
	answer := delegatedAnswer("work")
	answer.DelegatedAddress, answer.SshUser = proto.String(other), other
	dir := heldDelegated(t, "work", d, sessiondir.StatusReady, answer)

	banner := captureStdout(t, func() {
		require.NoError(t, displaySession(context.Background(), answer, "work"), "the session starts all the same")
	})
	require.Equal(t, fallbackBanner, banner)

	stdout, stderr, code := runCLI(t, "session", "info", "work")
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "Session: work\n"), stdout)
	require.Contains(t, stdout, tuiRow("Access:", "decided by the session's authority"))
	noDelegatedView(t, "session info", stdout, testGuestAddress, other)

	stdout, stderr, code = runCLI(t, "session", "list")
	require.Equal(t, 0, code, stderr)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	require.Len(t, lines, 2, stdout)
	require.Equal(t, []string{"work", "ready", "bash", testAnswerHost}, strings.Fields(lines[1]))
	noDelegatedView(t, "session list", stdout, testGuestAddress, other)

	stdout, stderr, code = runCurrent(t, dir.AdminSocket())
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "Session: work\n"), stdout)
	noDelegatedView(t, "session current", stdout, testGuestAddress, other)

	for surface, args := range map[string][]string{
		"session info -o json": {"session", "info", "work", "-o", "json"},
		"session list -o json": {"session", "list", "-o", "json"},
	} {
		stdout, stderr, code := runCLI(t, args...)
		require.Equal(t, 0, code, stderr)
		require.NotContains(t, stdout, `"delegation"`, surface)
		require.Contains(t, stdout, `"access": "delegated"`, surface)
		noDelegatedView(t, surface, stdout, testGuestAddress, other)
	}
	stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, `"delegation"`)
	require.Contains(t, stdout, `"access": "delegated"`)
	noDelegatedView(t, "session current -o json", stdout, testGuestAddress, other)

	status := statusLines(context.Background(), statusSource{Name: "work", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~'}, nil)
	noDelegatedView(t, "~?", strings.Join(status, "\n"), testGuestAddress, other)

	// And the detached host's, whose daemon starts it at an address its
	// record doesn't hold.
	releaseOnce(dir)
	s := claimSession(t, "s")
	releaseAtEnd(t, s)
	require.NoError(t, s.Update(func(r *sessiondir.Record) {
		r.Status, r.SessionID, r.Delegation = sessiondir.StatusReady, testRoutingID, d
	}))
	stdout, stderr = delegatedDetach(t, s, "relay.example.com:22", other)
	require.Empty(t, stderr, "no open-session warning for a delegated session")
	require.NotContains(t, stdout, `"delegation"`)
	require.Contains(t, stdout, `"access": "delegated"`)
	noDelegatedView(t, "host --detach -o json", stdout, testGuestAddress, other)
}

// session list's row of a delegated session that isn't joinable says what
// its JSON says: where its daemon answers for its launch with a guest address
// its record doesn't hold, the session is listed by its name alone, with
// neither address; where the daemon doesn't answer, or agrees, or answers for
// another launch, a successor's that doesn't speak for this record, the
// record's address stays. A starting record has no session ID yet, so the
// answer is tied to it by its launch.
func TestListRowOfAnUnjoinableDelegatedSession(t *testing.T) {
	const other = "claim-other"
	for _, status := range []string{sessiondir.StatusStarting, sessiondir.StatusDisconnected} {
		for _, tc := range []struct {
			name    string
			address string // the daemon's guest address; none where it doesn't answer
			another bool   // the daemon answers for another launch
		}{
			{"disagreeing", other, false},
			{"not answering", "", false},
			{"agreeing", testGuestAddress, false},
			{"another launch's daemon, disagreeing", other, true},
		} {
			t.Run(status+"/"+tc.name, func(t *testing.T) {
				setupSessionRoots(t)
				d := testDelegation("Example Authority", "relay.example.com:22")
				var answer *api.GetSessionResponse
				if tc.address != "" {
					answer = delegatedAnswer("work")
					answer.DelegatedAddress, answer.SshUser = proto.String(tc.address), tc.address
					if status == sessiondir.StatusStarting {
						answer.SessionId = ""
					}
				}
				served := answer
				if tc.another {
					served = nil
				}
				dir := heldDelegated(t, "work", d, status, served)
				if tc.another {
					answer.LaunchId, answer.Status = "another-launch", proto.String(status)
					serveStubAdmin(t, dir.AdminSocket(), answer)
				}
				require.NoError(t, dir.Update(func(r *sessiondir.Record) {
					if status == sessiondir.StatusStarting {
						r.SessionID = ""
					} else {
						r.TunnelReason = sessiondir.TunnelReasonWithdrawn
					}
				}))

				stdout, stderr, code := runCLI(t, "session", "list")
				require.Equal(t, 0, code, stderr)
				lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
				require.Len(t, lines, 2, stdout)
				listJSON, stderr, code := runCLI(t, "session", "list", "-o", "json")
				require.Equal(t, 0, code, stderr)
				if tc.address == other && !tc.another {
					require.Equal(t, []string{"work", status, "bash"}, strings.Fields(lines[1]), stdout)
					noDelegatedView(t, "session list", stdout, testGuestAddress, other)
					require.NotContains(t, listJSON, `"delegation"`, "the JSON drops it too")
					return
				}
				require.Equal(t, []string{"work", status, testGuestAddress, "bash"}, strings.Fields(lines[1]), stdout)
				require.NotContains(t, stdout, testRoutingID)
				require.Contains(t, listJSON, `"delegation"`, "the JSON keeps it too")
			})
		}
	}
}

// A banner offers a delegated session's ways in only from a record that
// confirms the daemon's answer, by the routing ID as well as by the guest
// address; one that doesn't is the fallback, and the session starts.
func TestBannerOfAnUnconfirmedRecordIsTheFallback(t *testing.T) {
	setupSessionRoots(t)
	prevAccept := flagAccept
	t.Cleanup(func() { flagAccept = prevAccept })
	flagAccept = true
	d := testDelegation("Example Authority", "relay.example.com:22")
	d.RoutingID = "otherotherotherother"
	heldDelegated(t, "work", d, sessiondir.StatusReady, nil)
	banner := captureStdout(t, func() {
		require.NoError(t, displaySession(context.Background(), delegatedAnswer("work"), "work"))
	})
	require.Equal(t, fallbackBanner, banner)
}

// session current reads the record of the launch its daemon answers for: a
// record of another launch under the name, with the same guest address,
// confirms nothing, and the view is the fallback.
func TestSessionCurrentReadsItsOwnLaunchsRecord(t *testing.T) {
	setupSessionRoots(t)
	d := testDelegation("Example Authority", "relay.example.com:22")
	dir := heldDelegated(t, "work", d, sessiondir.StatusReady, nil)
	answer := delegatedAnswer("work")
	answer.LaunchId = "another-launch"
	serveStubAdmin(t, dir.AdminSocket(), answer)

	stdout, stderr, code := runCurrent(t, dir.AdminSocket())
	require.Equal(t, 0, code, stderr)
	require.True(t, strings.HasPrefix(stdout, "Session: work\n"), stdout)
	noDelegatedView(t, "session current", stdout, testGuestAddress)

	stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, `"delegation"`)
	noDelegatedView(t, "session current -o json", stdout, testGuestAddress)
}

// A record from another build may hold a guest address or a relay the host
// would have refused a placement for: one with a control character in it, or
// a relay with more than a host:port, which a pasted ssh command would take
// as options. No surface offers a way in from it, and nothing any of them
// prints of it acts on the terminal.
func TestAMalformedDelegationOffersNoWayIn(t *testing.T) {
	for _, tc := range []struct{ name, address, relay string }{
		{"control characters", "claim\x1bwork", "relay\a.example.com:22"},
		{"options after the port", testGuestAddress, "relay.example.com:22 -oProxyCommand=x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			prevAccept := flagAccept
			t.Cleanup(func() { flagAccept = prevAccept })
			flagAccept = true
			d := testDelegation("Example Authority", tc.relay)
			d.GuestAddress = tc.address
			answer := delegatedAnswer("work")
			answer.DelegatedAddress, answer.SshUser = proto.String(tc.address), tc.address
			dir := heldDelegated(t, "work", d, sessiondir.StatusReady, answer)
			noWayIn := func(surface, out string) {
				t.Helper()
				for _, r := range out {
					require.False(t, r != '\n' && unicode.IsControl(r), "%s: %q holds a control character", surface, out)
				}
				for _, way := range []string{"➤ SSH:", "➤ URI:", "guests join with", "@relay", "ProxyCommand"} {
					require.NotContains(t, out, way, surface)
				}
			}
			// The JSON's delegation is still there, without its connect
			// strings.
			noConnectStrings := func(surface string, got map[string]any) {
				t.Helper()
				delegation, ok := got["delegation"].(map[string]any)
				require.True(t, ok, "%s: %v", surface, got)
				require.NotContains(t, delegation, "sshCommand", surface)
				require.NotContains(t, delegation, "uri", surface)
			}

			banner := captureStdout(t, func() {
				require.NoError(t, displaySession(context.Background(), answer, "work"))
			})
			noWayIn("banner", banner)
			require.Contains(t, banner, tuiRow("Access:", "decided by Example Authority"), "the banner is the delegated session's")

			for surface, args := range map[string][]string{
				"session info": {"session", "info", "work"},
				"session list": {"session", "list"},
			} {
				stdout, stderr, code := runCLI(t, args...)
				require.Equal(t, 0, code, stderr)
				noWayIn(surface, stdout)
			}
			stdout, stderr, code := runCurrent(t, dir.AdminSocket())
			require.Equal(t, 0, code, stderr)
			noWayIn("session current", stdout)

			stdout, stderr, code = runCLI(t, "session", "info", "work", "-o", "json")
			require.Equal(t, 0, code, stderr)
			noConnectStrings("session info -o json", jsonObject(t, stdout))
			stdout, stderr, code = runCLI(t, "session", "list", "-o", "json")
			require.Equal(t, 0, code, stderr)
			var listed []map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &listed), stdout)
			require.Len(t, listed, 1)
			noConnectStrings("session list -o json", listed[0])
			stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
			require.Equal(t, 0, code, stderr)
			noConnectStrings("session current -o json", jsonObject(t, stdout))

			status := statusLines(context.Background(), statusSource{Name: "work", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~'}, nil)
			noWayIn("~?", strings.Join(status, "\n"))
		})
	}
}

// delegatedConnect offers connect strings only for a guest address and a
// relay the host would place a run at, by the grammar it checks a placement
// with; an IPv6 relay's URI keeps its brackets.
func TestDelegatedConnectNeedsWhatAPlacementWould(t *testing.T) {
	for _, relay := range []string{
		"relay.example.com:22 -oProxyCommand=x",
		"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:022", ":22",
		"Relay.Example:22", "relay..example:22", "-relay.example:22", "relay example:22",
		"[fe80::1%en0]:22", "ssh://relay.example:22", "[relay.example.com]:22",
	} {
		ssh, uri := delegatedConnect(testDelegation("", relay))
		require.Empty(t, ssh, "relay %q", relay)
		require.Empty(t, uri, "relay %q", relay)
	}
	for _, address := range []string{"", "-work", ".work", "wo rk", "work@relay", "work;rm", "wörk", strings.Repeat("w", 256)} {
		d := testDelegation("", "relay.example.com:22")
		d.GuestAddress = address
		ssh, uri := delegatedConnect(d)
		require.Empty(t, ssh, "guest address %q", address)
		require.Empty(t, uri, "guest address %q", address)
	}

	long := strings.Repeat("w", 255)
	for _, tc := range []struct{ address, relay, ssh, uri string }{
		{testGuestAddress, "relay.example.com:22", "ssh claim-work@relay.example.com", "ssh://claim-work@relay.example.com"},
		{testGuestAddress, "relay.example.com:2222", "ssh claim-work@relay.example.com -p 2222", "ssh://claim-work@relay.example.com:2222"},
		{testGuestAddress, "127.0.0.1:2222", "ssh claim-work@127.0.0.1 -p 2222", "ssh://claim-work@127.0.0.1:2222"},
		{testGuestAddress, "[::1]:22", "ssh claim-work@::1", "ssh://claim-work@[::1]"},
		{testGuestAddress, "[2001:db8::1]:22", "ssh claim-work@2001:db8::1", "ssh://claim-work@[2001:db8::1]"},
		{testGuestAddress, "[2001:db8::1]:2222", "ssh claim-work@2001:db8::1 -p 2222", "ssh://claim-work@[2001:db8::1]:2222"},
		{"work_1.dev+a", "relay.example.com:22", "ssh work_1.dev+a@relay.example.com", "ssh://work_1.dev%2Ba@relay.example.com"},
		{long, "relay.example.com:22", "ssh " + long + "@relay.example.com", "ssh://" + long + "@relay.example.com"},
	} {
		d := testDelegation("", tc.relay)
		d.GuestAddress = tc.address
		ssh, uri := delegatedConnect(d)
		require.Equal(t, tc.ssh, ssh, tc.relay)
		require.Equal(t, tc.uri, uri, tc.relay)
	}
}

// A delegated session whose daemon is gone reads as any dead daemon's does,
// whatever its record says: not answering, and with no way in offered. The
// record's delegation is still reported, without its connect strings, and
// its start lock is free.
func TestDeadDelegatedDaemonReadsAsNotAnswering(t *testing.T) {
	t.Run("killed", func(t *testing.T) {
		setupSessionRoots(t)
		d := testDelegation("Example Authority", "relay.example.com:22")
		dir := claimSession(t, "work")
		require.NoError(t, dir.Update(func(r *sessiondir.Record) {
			r.Status, r.SessionID, r.Delegation = sessiondir.StatusReady, testRoutingID, d
		}))
		require.NoError(t, dir.Release(context.Background()))

		stdout, stderr, code := runCLI(t, "session", "list")
		require.Equal(t, 0, code, stderr)
		require.Empty(t, stdout)

		stdout, stderr, code = runCLI(t, "session", "info", "work", "-o", "json")
		require.Equal(t, 0, code, stderr)
		info := jsonObject(t, stdout)
		require.Equal(t, statusEnded, info["status"])
		delegation, ok := info["delegation"].(map[string]any)
		require.True(t, ok, stdout)
		require.Equal(t, testGuestAddress, delegation["guestAddress"])
		require.NotContains(t, delegation, "sshCommand")
		require.NotContains(t, delegation, "uri")
		require.NotContains(t, info, "sshCommand")

		stdout, stderr, code = runCLI(t, "session", "info", "work")
		require.Equal(t, 0, code, stderr)
		require.NotContains(t, stdout, "ssh ")
		require.NotContains(t, stdout, "ssh://")
		require.NotContains(t, stdout, testRoutingID)

		live, err := sessiondir.LiveDelegatedSessions(context.Background(), utils.UptermStateDir())
		require.NoError(t, err)
		require.Empty(t, live)

		// The start lock of its name, which a start took and was killed
		// holding, never letting it go, is free again.
		holdStartLockUntilKilled(t, utils.UptermStateDir(), d.Service, d.Account, "work")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		lock, err := sessiondir.LockDelegatedStart(ctx, utils.UptermStateDir(), d.Service, d.Account, "work")
		require.NoError(t, err, "the start lock of a dead start is free")
		require.NoError(t, lock.Release())
	})

	t.Run("held, not answering", func(t *testing.T) {
		setupSessionRoots(t)
		d := testDelegation("Example Authority", "relay.example.com:22")
		heldDelegated(t, "work", d, sessiondir.StatusReady, nil)

		stdout, stderr, code := runCLI(t, "session", "list")
		require.Equal(t, 0, code, stderr)
		lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
		require.Len(t, lines, 2, stdout)
		require.Equal(t, []string{"work", "ready", testGuestAddress, "bash"}, strings.Fields(lines[1]))

		for _, args := range [][]string{{"session", "info", "work", "-o", "json"}, {"session", "list", "-o", "json"}} {
			stdout, stderr, code := runCLI(t, args...)
			require.Equal(t, 0, code, stderr)
			out := strings.TrimSpace(stdout)
			if strings.HasPrefix(out, "[") {
				out = strings.TrimSuffix(strings.TrimPrefix(out, "["), "]")
			}
			info := jsonObject(t, out)
			require.Equal(t, joinStateFromRecord, info["joinStateSource"], args)
			require.NotContains(t, info, "access", "nothing answered to say who can join")
			require.NotContains(t, info, "sshCommand")
			delegation, ok := info["delegation"].(map[string]any)
			require.True(t, ok, stdout)
			require.Equal(t, testGuestAddress, delegation["guestAddress"])
			require.NotContains(t, delegation, "sshCommand", args)
			require.NotContains(t, delegation, "uri", args)
		}

		stdout, stderr, code = runCLI(t, "session", "info", "work")
		require.Equal(t, 0, code, stderr)
		require.Contains(t, oneSpaced(stdout), "Status: ready (not answering)")
		require.NotContains(t, stdout, "ssh ")
		require.NotContains(t, stdout, "ssh://")
		require.NotContains(t, stdout, testRoutingID)
	})
}

// The environment that tells TestHoldDelegatedStartLockHelper which start
// lock to hold.
const (
	holdLockRootEnv    = "UPTERM_TEST_HOLD_START_LOCK_ROOT"
	holdLockServiceEnv = "UPTERM_TEST_HOLD_START_LOCK_SERVICE"
	holdLockAccountEnv = "UPTERM_TEST_HOLD_START_LOCK_ACCOUNT"
	holdLockNameEnv    = "UPTERM_TEST_HOLD_START_LOCK_NAME"
)

// TestHoldDelegatedStartLockHelper is the start holdStartLockUntilKilled
// runs: this test binary, re-executed with a start lock's state root,
// service, account and name in its environment. It takes the lock, says so
// on its stdout, and holds it, never releasing it, until it is killed or its
// parent closes its stdin.
func TestHoldDelegatedStartLockHelper(t *testing.T) {
	root := os.Getenv(holdLockRootEnv)
	if root == "" {
		return
	}
	lock, err := sessiondir.LockDelegatedStart(context.Background(), root,
		os.Getenv(holdLockServiceEnv), os.Getenv(holdLockAccountEnv), os.Getenv(holdLockNameEnv))
	if err != nil {
		fmt.Println("failed:", err)
		os.Exit(1)
	}
	fmt.Println("held")
	_, _ = io.Copy(io.Discard, os.Stdin)
	// Reachable until here: a lock's file collected sooner would be closed,
	// and the lock let go, by its finalizer.
	runtime.KeepAlive(lock)
	os.Exit(0)
}

// holdStartLockUntilKilled has another process take the start lock of name,
// of account on service, under stateRoot, checks that no other start can
// take it while that one holds it, then kills that process, which never
// lets the lock go, and waits for it to be gone.
func holdStartLockUntilKilled(t *testing.T, stateRoot, service, account, name string) {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestHoldDelegatedStartLockHelper$")
	child.Env = append(os.Environ(), holdLockRootEnv+"="+stateRoot, holdLockServiceEnv+"="+service,
		holdLockAccountEnv+"="+account, holdLockNameEnv+"="+name)
	stdin, err := child.StdinPipe()
	require.NoError(t, err)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	waited := false
	t.Cleanup(func() {
		_ = stdin.Close()
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})

	said := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if line := sc.Text(); line == "held" || strings.HasPrefix(line, "failed:") {
				said <- line
				return
			}
		}
		said <- "the holder ended without taking the lock"
	}()
	select {
	case line := <-said:
		require.Equal(t, "held", line)
	case <-time.After(30 * time.Second):
		t.Fatal("the holder never took the start lock")
	}

	// Held: a start that waits for it gives up.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = sessiondir.LockDelegatedStart(ctx, stateRoot, service, account, name)
	cancel()
	require.Error(t, err, "the holder holds the start lock")

	require.NoError(t, child.Process.Kill())
	_ = child.Wait()
	waited = true
}

// Telling the desktop what the authority decided never holds up whoever
// tells it: a notification can take as long as the desktop likes, or
// forever on a host with none.
func TestNotifierDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	notified := make(chan string, 2)
	swapNotify(t, func(title, _ string, _ any) error {
		notified <- title
		<-release
		return nil
	})
	d := testDelegation("Example Authority", "relay.example.com:22")
	said := decisionNotifier("home", func() *sessiondir.Delegation { return d }, discardLogger())
	for _, dec := range []host.Decision{host.DecisionStopped, host.DecisionWithdrawn} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			said(dec)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("telling the desktop about decision %d blocked its caller", dec)
		}
	}
	got := map[string]bool{}
	for range 2 {
		select {
		case title := <-notified:
			got[title] = true
		case <-time.After(5 * time.Second):
			t.Fatal("the desktop was never told")
		}
	}
	require.Equal(t, map[string]bool{"Example Authority stopped the session": true, "Example Authority withdrew remote access": true}, got)
}

// What a foreground delegated host says as its terminal lets go, from what
// the record of its launch confirms: the authority's stop in place of the
// generic one, and its withdrawal of a session that goes on running.
func TestDelegatedEndLines(t *testing.T) {
	const (
		withdrawal = "upterm: Example Authority withdrew remote access. The command is still running locally as s.\r\n" +
			"Use upterm attach s to return, or upterm session stop s to stop it."
		detached     = "upterm: detached; the session continues. Reattach with upterm attach s, or stop it with upterm session stop s"
		disconnected = "upterm: this terminal was disconnected (see /var/log/upterm.log); the session is still running. Reattach with upterm attach s"
	)
	stopped := attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseStopped}}
	stoppedByAuthority := func(r *sessiondir.Record) { r.Delegation.Decision = sessiondir.DecisionStopped }
	for _, tc := range []struct {
		name   string
		record func(*sessiondir.Record)
		res    attach.Result
		want   string
		// another is set where the launch this host started isn't the one
		// whose record holds the name: that record says nothing of it.
		another bool
		// disagreeing is set where the daemon creates the session at a
		// guest address its record doesn't hold: the record's authority is
		// not named, only what was decided.
		disagreeing bool
	}{
		{name: "stopped by the authority, the daemon disagreeing", record: stoppedByAuthority, res: stopped,
			want: "upterm: The session's authority stopped the session. Terminating the hosted command.", disagreeing: true},
		{name: "detached once withdrawn, the daemon disagreeing", record: withdrawnRecord, res: attach.Result{Reason: attach.Detached},
			want: detached + "\r\n" + strings.Replace(withdrawal, "Example Authority", "The session's authority", 1), disagreeing: true},
		{name: "stopped by the authority", record: stoppedByAuthority, res: stopped,
			want: "upterm: Example Authority stopped the session. Terminating the hosted command."},
		{name: "stopped locally", record: func(*sessiondir.Record) {}, res: stopped, want: "upterm: the session was stopped"},
		{name: "detached once withdrawn", record: withdrawnRecord, res: attach.Result{Reason: attach.Detached}, want: detached + "\r\n" + withdrawal},
		{name: "disconnected once withdrawn", record: withdrawnRecord, res: attach.Result{Reason: attach.Disconnected}, want: disconnected + "\r\n" + withdrawal},
		{name: "detached and not withdrawn", record: func(*sessiondir.Record) {}, res: attach.Result{Reason: attach.Detached}, want: detached},
		{name: "exited once withdrawn", record: withdrawnRecord, res: attach.Result{Reason: attach.Exited, Status: 3, Cause: attach.Cause{Kind: attach.CauseExited}},
			want: "upterm: the session ended with status 3"},
		{name: "stopped by the authority, by another launch's record", record: stoppedByAuthority, res: stopped,
			want: "upterm: the session was stopped", another: true},
		{name: "detached once withdrawn, by another launch's record", record: withdrawnRecord, res: attach.Result{Reason: attach.Detached},
			want: detached, another: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			require.NoError(t, dir.Update(func(r *sessiondir.Record) {
				r.Status = sessiondir.StatusReady
				r.Delegation = testDelegation("Example Authority", "relay.example.com:22")
				tc.record(r)
			}))
			spawn, d := newScriptedDaemon(t)
			d.launchID = dir.LaunchID()
			if tc.another {
				d.launchID = "another-launch"
			}
			address := testGuestAddress
			if tc.disagreeing {
				address = "claim-other"
			}
			d.amend = func(r *api.GetSessionResponse) { r.DelegatedAddress = proto.String(address) }
			attached := make(chan string, 1)
			result := make(chan attach.Result, 1)
			var stdout, stderr bytes.Buffer
			s := newSession(t, spawn, fakeClient(attached, result), &stdout, &stderr)
			d.startup(t, "s")
			go func() {
				<-attached
				d.start()
				result <- tc.res
			}()
			_ = s.run(context.Background())
			require.Equal(t, "\r\n"+tc.want+"\r\n", stderr.String())
		})
	}
}

func withdrawnRecord(r *sessiondir.Record) {
	r.Status = sessiondir.StatusDisconnected
	r.TunnelReason = sessiondir.TunnelReasonWithdrawn
	r.Delegation.Decision = sessiondir.DecisionWithdrawn
}

// How a withdrawn delegated session reads where its state is shown: the hint
// under its status, and the attached terminal's ~?, both say what its end
// line says.
func TestDelegatedWithdrawnIsSaid(t *testing.T) {
	d := testDelegation("Example Authority", "relay.example.com:22")
	const notice = "Example Authority withdrew remote access. The command is still running locally as home. " +
		"Use upterm attach home to return, or upterm session stop home to stop it."
	require.Equal(t, notice, tui.StatusHint(tui.SessionDetail{Name: "home", Status: sessiondir.StatusDisconnected, TunnelReason: sessiondir.TunnelReasonWithdrawn, Delegation: d}))
	require.Equal(t, "the relay refused this session's registration with Example Authority; upterm keeps retrying, slowly.",
		tui.StatusHint(tui.SessionDetail{Name: "home", Status: sessiondir.StatusReconnecting, TunnelReason: sessiondir.TunnelReasonAuthorityRefused, Delegation: d}))

	lines := renderStatus(statusView{Name: "home", Reason: sessiondir.TunnelReasonWithdrawn, Delegation: d}, '~', false)
	require.Equal(t, "upterm: session home: 0 guests; Example Authority withdrew remote access. The command is still running locally as home.", lines[0])
	require.Equal(t, "upterm: Use upterm attach home to return, or upterm session stop home to stop it.", lines[1])
	require.NotContains(t, strings.Join(lines, "\n"), "can't reconnect")
}

// --detach's line for a delegated session that isn't ready names the
// authority its record holds only where the daemon's answer confirms the
// record, and "the session's authority" otherwise, as the end lines do. The
// name is written as the record gives it, at the start of a sentence too:
// only the phrase that stands for a missing one, and a hint that doesn't
// start with the name, are capitalized there.
func TestDetachLineNamesTheAuthorityItsDaemonConfirms(t *testing.T) {
	const refused, withdrew = "registration with ", " withdrew remote access. The command is still running locally."
	for _, tc := range []struct {
		name, authority, address, status, reason, hint string
	}{
		{"refused", "Example Authority", testGuestAddress, sessiondir.StatusReconnecting, sessiondir.TunnelReasonAuthorityRefused,
			"The relay refused this session's " + refused + "Example Authority; upterm keeps retrying, slowly."},
		{"refused, the daemon disagreeing", "Example Authority", "claim-other", sessiondir.StatusReconnecting, sessiondir.TunnelReasonAuthorityRefused,
			"The relay refused this session's " + refused + "the session's authority; upterm keeps retrying, slowly."},
		{"withdrawn", "Example Authority", testGuestAddress, sessiondir.StatusDisconnected, sessiondir.TunnelReasonWithdrawn,
			"Example Authority" + withdrew},
		{"withdrawn, the daemon disagreeing", "Example Authority", "claim-other", sessiondir.StatusDisconnected, sessiondir.TunnelReasonWithdrawn,
			"The session's authority" + withdrew},
		{"withdrawn by a name in lower case", "example.dev", testGuestAddress, sessiondir.StatusDisconnected, sessiondir.TunnelReasonWithdrawn,
			"example.dev" + withdrew},
		{"withdrawn by an authority with no name", "", testGuestAddress, sessiondir.StatusDisconnected, sessiondir.TunnelReasonWithdrawn,
			"The session's authority" + withdrew},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			require.NoError(t, dir.Update(func(r *sessiondir.Record) {
				r.Status, r.SessionID, r.TunnelReason = tc.status, testRoutingID, tc.reason
				r.Delegation = testDelegation(tc.authority, "relay.example.com:22")
			}))
			spawn, d := newScriptedDaemon(t)
			d.launchID, d.sessionID = dir.LaunchID(), testRoutingID
			d.amend = func(r *api.GetSessionResponse) {
				r.Host, r.SshUser = "ssh://relay.example.com:22", tc.address
				r.DelegatedAddress = proto.String(tc.address)
			}
			var stdout, stderr bytes.Buffer
			s := newSession(t, spawn, nil, &stdout, &stderr)
			s.detach = true
			dec := d.startup(t, "s")
			go func() { <-dec; d.startWith(tc.status) }()
			require.NoError(t, s.run(context.Background()))
			require.Equal(t, "Session s is running in the background. "+tc.hint+
				" Attach with upterm attach s; stop it with upterm session stop s.\n", stdout.String())
		})
	}
}

// A desktop notice of the authority's decision is titled with the whole of
// the authority's name, whatever full stops it holds, and what it decided;
// the body is the rest.
func TestDecisionNoticeIsTitledWithTheWholeName(t *testing.T) {
	const withdrawnBody = "The command is still running locally as work.\nUse upterm attach work to return, or upterm session stop work to stop it."
	for _, tc := range []struct {
		d     *sessiondir.Delegation
		start string
	}{
		{testDelegation("Example Inc. Sharing", "relay.example.com:22"), "Example Inc. Sharing"},
		{testDelegation("Example Inc.", "relay.example.com:22"), "Example Inc."},
		{testDelegation("", "relay.example.com:22"), "The session's authority"},
		{nil, "The session's authority"},
	} {
		t.Run(tc.start, func(t *testing.T) {
			require.Equal(t, notification{tc.start + " stopped the session", "Terminating the hosted command."},
				decisionNotice(tc.d, "work", host.DecisionStopped))
			require.Equal(t, notification{tc.start + " withdrew remote access", withdrawnBody},
				decisionNotice(tc.d, "work", host.DecisionWithdrawn))
		})
	}
}

// session ssh-config writes no Host block for a delegated session whose
// daemon answers with a guest address its record doesn't hold: the daemon's
// own block is a way in the record doesn't confirm. A confirmed delegated
// session's block, and an ordinary session's, are what they always were.
func TestSSHConfigOfADelegatedSessionItsDaemonDisagreesWith(t *testing.T) {
	for _, address := range []string{testGuestAddress, "claim-other"} {
		t.Run(address, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			answer := delegatedAnswer("work")
			answer.DelegatedAddress, answer.SshUser = proto.String(address), address
			answer.RelayKnownHosts, answer.RelayKeyTrust = proto.String("[node-1.example.net]:2201 "+publicRelayKey), proto.String("known")
			heldDelegated(t, "work", testDelegation("Example Authority", "relay.example.com:22"), sessiondir.StatusReady, answer)

			stdout, stderr, code := runCLI(t, "session", "ssh-config", "work")
			if address != testGuestAddress {
				require.Equal(t, 1, code, stderr)
				require.Empty(t, stdout)
				require.Equal(t, "upterm: session work's record and its process give different guest addresses, so upterm won't write an ssh config for it\n", stderr)
				return
			}
			require.Equal(t, 0, code, stderr)
			want, err := sshConfigText(answer, "work")
			require.NoError(t, err)
			require.Equal(t, want, stdout)
		})
	}

	t.Run("an ordinary session", func(t *testing.T) {
		setupSessionRoots(t)
		withConfig(t, "")
		dir := claimSession(t, "plain")
		releaseAtEnd(t, dir)
		require.NoError(t, dir.Update(func(r *sessiondir.Record) {
			r.Status, r.SessionID = sessiondir.StatusReady, "sid-1"
			r.HostKeys = []string{testHostKeyLine(t)}
		}))
		answer := ordinaryAnswer()
		answer.LaunchId = dir.LaunchID()
		serveStubAdmin(t, dir.AdminSocket(), answer)

		stdout, stderr, code := runCLI(t, "session", "ssh-config", "plain")
		require.Equal(t, 0, code, stderr)
		want, err := sshConfigText(answer, "plain")
		require.NoError(t, err)
		require.Equal(t, want, stdout)
	})
}

// withdrawnSession is the delegated session "work" once its authority
// withdrew its remote access, its daemon answering for it.
func withdrawnSession(t *testing.T) *sessiondir.Dir {
	t.Helper()
	setupSessionRoots(t)
	d := testDelegation("Example Authority", "relay.example.com:22")
	dir := heldDelegated(t, "work", d, sessiondir.StatusDisconnected, delegatedAnswer("work"))
	require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.TunnelReason = sessiondir.TunnelReasonWithdrawn }))
	return dir
}

// ~? of a withdrawn session, read from its record and its daemon, says who
// withdrew its remote access and how to return to it, and offers no way in.
func TestStatusLinesOfAWithdrawnSession(t *testing.T) {
	dir := withdrawnSession(t)
	lines := statusLines(context.Background(), statusSource{Name: "work", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~'}, nil)
	require.Equal(t, "upterm: session work: 0 guests; Example Authority withdrew remote access. The command is still running locally as work.", lines[0])
	require.Equal(t, "upterm: Use upterm attach work to return, or upterm session stop work to stop it.", lines[1])
	require.NotContains(t, strings.Join(lines, "\n"), "guests join with")
}

// session current of a withdrawn session offers no way in, as its view or as
// JSON, though its record confirms the daemon's answer.
func TestSessionCurrentOfAWithdrawnSessionOffersNoWayIn(t *testing.T) {
	dir := withdrawnSession(t)
	stdout, stderr, code := runCurrent(t, dir.AdminSocket())
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, "➤ SSH:")
	require.NotContains(t, stdout, "➤ URI:")
	require.Contains(t, stdout, "➤ Dashboard:", "the record confirms the answer")

	stdout, stderr, code = runCurrent(t, dir.AdminSocket(), "-o", "json")
	require.Equal(t, 0, code, stderr)
	got := jsonObject(t, stdout)
	delegation, ok := got["delegation"].(map[string]any)
	require.True(t, ok, stdout)
	require.NotContains(t, delegation, "sshCommand")
	require.NotContains(t, delegation, "uri")
	require.NotContains(t, got, "sshCommand")
}

// A record whose name is no longer held speaks for no session: a foreground
// host's end lines say nothing of its withdrawal, and a banner made from it
// is the fallback.
func TestAReleasedRecordSpeaksForNoSession(t *testing.T) {
	t.Run("end lines", func(t *testing.T) {
		setupSessionRoots(t)
		dir := claimSession(t, "s")
		require.NoError(t, dir.Update(func(r *sessiondir.Record) {
			r.Delegation = testDelegation("Example Authority", "relay.example.com:22")
			withdrawnRecord(r)
		}))
		withdrawn, _ := delegatedEndLines(context.Background(), delegatedAnswer("s"), "s", dir.LaunchID())
		require.NotEmpty(t, withdrawn, "while the name is held")
		releaseOnce(dir)
		withdrawn, _ = delegatedEndLines(context.Background(), delegatedAnswer("s"), "s", dir.LaunchID())
		require.Empty(t, withdrawn)
	})
	t.Run("banner", func(t *testing.T) {
		setupSessionRoots(t)
		prevAccept := flagAccept
		t.Cleanup(func() { flagAccept = prevAccept })
		flagAccept = true
		dir := heldDelegated(t, "work", testDelegation("Example Authority", "relay.example.com:22"), sessiondir.StatusReady, nil)
		releaseOnce(dir)
		banner := captureStdout(t, func() {
			require.NoError(t, displaySession(context.Background(), delegatedAnswer("work"), "work"))
		})
		require.Equal(t, fallbackBanner, banner)
	})
}
