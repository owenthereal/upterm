package command

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// The keys `session info -o json` has always published for a ready session
// are all still there, with the values they had: reason stays "unknown" while
// the session runs. countsKnown is new, and says the counts beside it came
// from the daemon.
func TestTodaysKeysKeepTheirPresence(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "r")
	got := lookupJSON(t, "r")
	for _, k := range []string{"name", "launchId", "status", "clientCount", "guestCount", "pid", "command", "reason", "adminSocket", "attachSocket", "joinStateSource", "sessionId", "sshCommand", "joinCommand"} {
		require.Contains(t, got, k)
	}
	require.Equal(t, "unknown", got["reason"])
	require.Equal(t, true, got["countsKnown"])
}

// noRecords puts a file where the state directory would be, so that nothing
// the test runs can read a session's record.
func noRecords(t *testing.T) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.WriteFile(state, nil, 0o600))
	t.Setenv("XDG_STATE_HOME", state)
}

// currentJSONAt is what `session current -o json` prints for a session whose
// daemon answers at socket with resp, run where no record can be read: the
// command answers from the socket alone.
func currentJSONAt(t *testing.T, socket string, resp *api.GetSessionResponse) map[string]any {
	t.Helper()
	noRecords(t)
	serveStubAdmin(t, socket, resp)
	stdout, stderr, code := runCurrent(t, socket, "-o", "json")
	require.Equal(t, 0, code, stderr)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &m), stdout)
	return m
}

// currentJSON is currentJSONAt on a socket of its own.
func currentJSON(t *testing.T, resp *api.GetSessionResponse) map[string]any {
	t.Helper()
	setupSessionRoots(t)
	return currentJSONAt(t, socketIn(t, "a.sock"), resp)
}

// The complete key sets, for a daemon from before the optional fields and
// for one that sends every one of them with nothing in it: the five keys
// `session current` always printed are there even when empty, and what the
// daemon doesn't say is left out rather than printed as false or "".
func TestCurrentKeySetsForAnOldAndAZeroValuedDaemon(t *testing.T) {
	setupSessionRoots(t)
	keys := func(socket string, resp *api.GetSessionResponse) []string {
		t.Helper()
		return slices.Sorted(maps.Keys(currentJSONAt(t, socketIn(t, socket), resp)))
	}
	// A daemon from before the optional fields, with empty strings everywhere
	// (and an empty authorized-key list, so access is "anyone").
	require.Equal(t, []string{"access", "clientCount", "command", "countsKnown", "forceCommand", "guestCount", "host", "sessionId"},
		keys("old.sock", &api.GetSessionResponse{}))
	// A new daemon whose optional booleans are false and strings empty but
	// set. A false is a fact and is printed; an empty string is the daemon
	// saying it has nothing to report, as it does for the reason while the
	// tunnel is up, and is left out like a field it never sent.
	f := false
	require.Equal(t, []string{"access", "clientCount", "command", "countsKnown", "fileTransferApprovalRequired", "forceCommand", "guestCount", "host", "localForwarding", "readOnly", "sessionId", "startConfirmed"},
		keys("new.sock", &api.GetSessionResponse{
			Name: proto.String(""), Status: proto.String(""), Reconnect: proto.String(""), TunnelReason: proto.String(""), FileTransfer: proto.String(""),
			StartConfirmed: &f, ReadOnly: &f, FileTransferApprovalRequired: &f, LocalForwarding: &f,
		}))
}

// A join timeout counting is reported from the daemon's answer, by the rules
// `session info` uses, with no record to read.
func TestCurrentReportsACountingJoinTimeoutWithoutRecords(t *testing.T) {
	deadline := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	m := currentJSON(t, &api.GetSessionResponse{SessionId: "sid", Host: "ssh://h:22", Open: true,
		JoinState: &api.JoinState{TimeoutNanos: int64(10 * time.Minute), DeadlineUnixNano: deadline.UnixNano()}})
	require.Equal(t, true, m["open"])
	require.Equal(t, "anyone", m["access"])
	require.Equal(t, "daemon", m["joinStateSource"])
	require.Equal(t, "10m", m["joinTimeout"])
	require.Equal(t, "2026-10-13T12:00:00Z", m["joinDeadline"])
	require.NotContains(t, m, "firstGuestJoinedAt")
}

func TestCurrentReportsAClaimedSessionWithoutRecords(t *testing.T) {
	// A guest has joined: the claim rule drops the timeout and deadline, even
	// when stale values arrive with it.
	joined := time.Date(2026, 10, 13, 11, 59, 0, 0, time.UTC)
	m := currentJSON(t, &api.GetSessionResponse{SessionId: "sid", Host: "ssh://h:22",
		JoinState: &api.JoinState{TimeoutNanos: int64(10 * time.Minute), DeadlineUnixNano: joined.Add(time.Minute).UnixNano(), FirstGuestJoinedUnixNano: joined.UnixNano()}})
	require.Equal(t, "2026-10-13T11:59:00Z", m["firstGuestJoinedAt"])
	require.Equal(t, "daemon", m["joinStateSource"])
	require.NotContains(t, m, "joinTimeout")
	require.NotContains(t, m, "joinDeadline")
}

// The connect strings are printed only when the daemon's status says guests
// can use them, which is `session info`'s rule: a disconnected session keeps
// a connect string that can't connect, and a daemon that doesn't report its
// status doesn't say whether its can.
func TestCurrentPrintsTheConnectStringsOnlyForAJoinableSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   bool
	}{
		{"ready", proto.String(sessiondir.StatusReady), true},
		{"reconnecting", proto.String(sessiondir.StatusReconnecting), true},
		{"disconnected", proto.String(sessiondir.StatusDisconnected), false},
		{"a daemon that doesn't report its status", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := currentJSON(t, &api.GetSessionResponse{SessionId: "sid", SshUser: "sid", Host: "ssh://127.0.0.1:2222", Status: tc.status})
			if tc.want {
				require.Equal(t, "ssh sid@127.0.0.1 -p 2222", m["sshCommand"])
				require.Equal(t, "upterm join ssh://sid@127.0.0.1:2222", m["joinCommand"])
				return
			}
			require.NotContains(t, m, "sshCommand")
			require.NotContains(t, m, "joinCommand")
		})
	}
}

// The template sees every field, by its Go name: the five it always had, and
// the new ones beside them.
func TestCurrentTemplateSeesTheNewFieldsByTheirGoNames(t *testing.T) {
	setupSessionRoots(t)
	socket := socketIn(t, "a.sock")
	serveStubAdmin(t, socket, &api.GetSessionResponse{
		SessionId:        "sid",
		Host:             "ssh://127.0.0.1:2222",
		ConnectedClients: []*api.Client{{Kind: api.Client_HOST}, {Kind: api.Client_GUEST}},
		Name:             proto.String("build"),
	})
	stdout, stderr, code := runCurrent(t, socket, "-o", "go-template={{.SessionID}} {{.ClientCount}} {{.Host}} {{.Name}} {{.GuestCount}} {{.CountsKnown}} {{.Access}}")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, "sid 2 ssh://127.0.0.1:2222 build 1 true anyone", stdout)
}

// -o is checked before anything is looked up, so a format that can't be
// answered fails the same for a session that exists and one that doesn't.
func TestInfoChecksTheFormatBeforeTheLookup(t *testing.T) {
	prevOutput := flagOutput
	t.Cleanup(func() { flagOutput = prevOutput })
	setupSessionRoots(t)
	stdout, stderr, code := runCLI(t, "session", "info", "nosuch", "-o", "yaml")
	require.Equal(t, 1, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: invalid output format \"yaml\": must be 'json'\n", stderr)
}

// Every time `session info` prints is in UTC: the record keeps whatever zone
// its writer was in.
func TestEveryTimestampIsUTC(t *testing.T) {
	setupSessionRoots(t)
	buildReconnectingAt(t, "r", false, time.Date(2026, 10, 13, 5, 0, 0, 0, time.FixedZone("PDT", -7*3600)))
	got := lookupJSON(t, "r")
	require.Equal(t, "2026-10-13T12:00:00Z", got["tunnelLostAt"])
	require.Equal(t, "2026-10-13T13:01:00Z", got["nextAttemptAt"])
}

func TestVersionJSONIsTheBuildInfo(t *testing.T) {
	setupSessionRoots(t)
	withBuildInfo(t)
	stdout, stderr, code := runCLI(t, "version", "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.Empty(t, stderr)
	requireGolden(t, "version", stdout)
}

func TestVersionRejectsAnOutputFormatItDoesNotKnow(t *testing.T) {
	setupSessionRoots(t)
	stdout, stderr, code := runCLI(t, "version", "-o", "yaml")
	require.Equal(t, 1, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: invalid output format \"yaml\": must be 'json'\n", stderr)
}

// The format is the command line's alone: an output key or UPTERM_OUTPUT is
// for the commands that take it from there, and must neither turn the version
// into JSON nor make it fail.
func TestVersionFormatIsNotTakenFromEnvOrConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"UPTERM_OUTPUT", func(t *testing.T) { t.Setenv("UPTERM_OUTPUT", "json") }},
		{"an output key in the config", func(t *testing.T) { withConfig(t, "output: json\n") }},
		{"an output key the version would refuse", func(t *testing.T) { withConfig(t, "output: yaml\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withBuildInfo(t)
			withConfig(t, "")
			t.Setenv("UPTERM_OUTPUT", "")
			tc.setup(t)
			stdout, stderr, code := runCLI(t, "version")
			require.Equal(t, 0, code, stderr)
			require.Empty(t, stderr)
			require.Equal(t, "Upterm version 1.2.3\nGit commit: abc1234\nBuild date: 2026-10-13T00:00:00Z\n", stdout)
		})
	}
}

// withBuildInfo gives the binary a known version, commit and build date for
// the rest of t.
func withBuildInfo(t *testing.T) {
	t.Helper()
	prevVersion, prevCommit, prevDate := version.Version, version.GitCommit, version.Date
	t.Cleanup(func() { version.Version, version.GitCommit, version.Date = prevVersion, prevCommit, prevDate })
	version.Version, version.GitCommit, version.Date = "1.2.3", "abc1234", "2026-10-13T00:00:00Z"
}

// The goldens below are each command's JSON for a fixture, with every value
// that differs from run to run replaced by what it stands for: a launch ID, a
// pid, a socket or log path. The fixtures' times are fixed, so times are
// compared as printed.

// goldenPlaceholders are the keys whose values differ from run to run, and
// what a golden has in their place. Only a key that is present is replaced,
// so a golden still says which keys there are.
var goldenPlaceholders = map[string]string{
	"launchId":     "LAUNCH",
	"pid":          "PID",
	"adminSocket":  "PATH",
	"attachSocket": "PATH",
	"logPath":      "PATH",
}

// requireGolden compares a command's JSON with testdata/json/NAME.json, once
// the values that differ from run to run are replaced. The golden has its keys
// sorted, so the order a command prints them in is not compared: no script
// can rely on it.
func requireGolden(t *testing.T, name, got string) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(got), &v), got)
	var normalized bytes.Buffer
	enc := json.NewEncoder(&normalized)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(withPlaceholders(v)))

	want, err := os.ReadFile(filepath.Join("testdata", "json", name+".json"))
	require.NoError(t, err)
	// Git may check the file out with CRLF line endings.
	require.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), normalized.String())
}

func withPlaceholders(v any) any {
	switch v := v.(type) {
	case []any:
		for i := range v {
			v[i] = withPlaceholders(v[i])
		}
	case map[string]any:
		for k, x := range v {
			if p, ok := goldenPlaceholders[k]; ok {
				v[k] = p
				continue
			}
			v[k] = withPlaceholders(x)
		}
	}
	return v
}

// newDaemonAnswer is what a daemon that sends every field answers for launch,
// ready, with the host's own terminal and a guest attached, an allowlist, and
// a join timeout the guest's join disabled.
func newDaemonAnswer(launch string) *api.GetSessionResponse {
	joined := time.Date(2026, 10, 13, 11, 59, 0, 0, time.UTC)
	return &api.GetSessionResponse{
		SessionId: "sid-1",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		SshUser:   "sid-1",
		Command:   []string{"bash"},
		LaunchId:  launch,
		ConnectedClients: []*api.Client{
			{Kind: api.Client_HOST, Addr: "local", Version: "SSH-2.0-upterm-attach", PublicKeyFingerprint: "SHA256:host"},
			{Kind: api.Client_GUEST, Addr: "203.0.113.7:50000", Version: "SSH-2.0-OpenSSH_9.6", PublicKeyFingerprint: "SHA256:alice"},
		},
		AuthorizedKeys:               []*api.AuthorizedKey{{Comment: "github:alice", PublicKeyFingerprints: []string{"SHA256:alice"}}},
		JoinState:                    &api.JoinState{FirstGuestJoinedUnixNano: joined.UnixNano()},
		Name:                         proto.String("build"),
		Status:                       proto.String(sessiondir.StatusReady),
		Reconnect:                    proto.String(sessiondir.ReconnectSupported),
		TunnelReason:                 proto.String(""),
		StartConfirmed:               proto.Bool(true),
		ReadOnly:                     proto.Bool(false),
		FileTransfer:                 proto.String("all"),
		FileTransferApprovalRequired: proto.Bool(true),
		LocalForwarding:              proto.Bool(false),
	}
}

func TestInfoJSONGoldenReady(t *testing.T) {
	setupSessionRoots(t)
	d := claimSession(t, "build")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-1"
		r.Reconnect = sessiondir.ReconnectSupported
	}))
	serveStubAdmin(t, d.AdminSocket(), newDaemonAnswer(d.LaunchID()))

	stdout, stderr, code := runCLI(t, "session", "info", "build", "-o", "json", "--hide-client-ip")
	require.Equal(t, 0, code, stderr)
	requireGolden(t, "info-ready", stdout)
}

func TestInfoJSONGoldenEnded(t *testing.T) {
	setupSessionRoots(t)
	lost := time.Date(2026, 10, 13, 5, 0, 0, 0, time.FixedZone("PDT", -7*3600))
	d := claimSession(t, "build")
	code := 3
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusEnding
		r.SessionID = "sid-1"
		r.Reason = sessiondir.ReasonExited
		r.ExitCode = &code
		r.Reconnect = sessiondir.ReconnectSupported
		r.TunnelLostAt = lost
		r.TunnelReason = sessiondir.TunnelReasonNetwork
		r.TunnelError = "dial tcp 127.0.0.1:2222: connect: connection refused"
		r.NextAttemptAt = lost.Add(30 * time.Second)
	}))
	require.NoError(t, d.Release(context.Background()))

	stdout, stderr, exit := runCLI(t, "session", "info", "build", "-o", "json")
	require.Equal(t, 0, exit, stderr)
	requireGolden(t, "info-ended", stdout)
}

func TestCurrentJSONGolden(t *testing.T) {
	setupSessionRoots(t)
	socket := socketIn(t, "a.sock")
	serveStubAdmin(t, socket, newDaemonAnswer("launch-1"))
	stdout, stderr, code := runCurrent(t, socket, "-o", "json", "--hide-client-ip")
	require.Equal(t, 0, code, stderr)
	requireGolden(t, "current", stdout)
}

// An answer from a daemon from before the optional fields: what 0.38.0 sends.
func TestCurrentJSONGoldenOldDaemon(t *testing.T) {
	setupSessionRoots(t)
	socket := socketIn(t, "a.sock")
	serveStubAdmin(t, socket, &api.GetSessionResponse{
		SessionId: "sid-1",
		Host:      "ssh://127.0.0.1:2222",
		NodeAddr:  "127.0.0.1:2222",
		SshUser:   "sid-1",
		Command:   []string{"bash"},
		LaunchId:  "launch-1",
		ConnectedClients: []*api.Client{
			{Kind: api.Client_HOST, Addr: "local", Version: "SSH-2.0-upterm-attach", PublicKeyFingerprint: "SHA256:host"},
		},
		JoinState: &api.JoinState{},
	})
	stdout, stderr, code := runCurrent(t, socket, "-o", "json", "--hide-client-ip")
	require.Equal(t, 0, code, stderr)
	requireGolden(t, "current-old-daemon", stdout)
}

func TestDetachJSONGolden(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s")
	releaseAtEnd(t, dir)
	require.NoError(t, dir.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.Reconnect = sessiondir.ReconnectSupported
	}))
	spawn, d := newScriptedDaemon(t)
	d.launchID = dir.LaunchID()
	d.amend = func(r *api.GetSessionResponse) {
		r.StartConfirmed = proto.Bool(false)
		r.ReadOnly = proto.Bool(false)
		r.FileTransfer = proto.String("all")
		r.FileTransferApprovalRequired = proto.Bool(false)
		r.LocalForwarding = proto.Bool(false)
	}
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach, s.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.start() }()
	require.NoError(t, s.run(context.Background()))
	requireGolden(t, "detach", stdout.String())
}

func TestListJSONGolden(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "answering")
	buildStarting(t, "starting")
	stdout, stderr, code := runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code, stderr)
	requireGolden(t, "list", stdout)
}
