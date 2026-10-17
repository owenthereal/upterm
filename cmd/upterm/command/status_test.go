package command

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

const keysLineWithSuspend = "upterm: keys: ~. detach  ~^Z suspend  ~~ send ~  ~? this list"

// fiveGuests is five client rows, as clientDesc writes them.
func fiveGuests() []string {
	return []string{
		"guest 1.2.3.4 SSH-2.0-OpenSSH_10.3 SHA256:aaaa",
		"guest 1.2.3.5 SSH-2.0-OpenSSH_10.3 SHA256:bbbb",
		"guest 1.2.3.6 SSH-2.0-upterm-join SHA256:cccc",
		"guest 1.2.3.7 SSH-2.0-OpenSSH_10.3 SHA256:dddd",
		"guest 1.2.3.8 SSH-2.0-OpenSSH_10.3 SHA256:eeee",
	}
}

func TestStatusUnavailableStillShowsTheKeys(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s")
	releaseAtEnd(t, dir)
	silent := filepath.Join(t.TempDir(), "admin.sock") // nothing listens
	start := time.Now()
	lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: dir.LaunchID(), AdminSocket: silent, Escape: '~', Suspend: true}, nil)
	require.Less(t, time.Since(start), 2*time.Second)
	require.Equal(t, []string{"upterm: session status unavailable", keysLineWithSuspend}, lines)
}

// A daemon that takes the connection and then says nothing is bounded the
// same way, and is no more a guess at zero guests than one that isn't there.
func TestStatusFromADaemonThatNeverAnswersIsBounded(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s")
	releaseAtEnd(t, dir)
	require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady }))
	ln, err := net.Listen("unix", dir.AdminSocket())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() }) // held open, never answered
		}
	}()

	start := time.Now()
	lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~', Suspend: true}, nil)
	require.Less(t, time.Since(start), 2*time.Second)
	require.Equal(t, []string{"upterm: session status unavailable", keysLineWithSuspend}, lines)
}

// A lookup the bound has given up on is still running, parked where a step
// that ignores its context parks, and ~? pressed again does not start another
// behind it: every one of those would hold a goroutine and what it holds for
// as long as the first does. The answer is at once the one a lookup that
// timed out gives, and the terminal looks again once the first has returned.
func TestStatusStartsNoSecondLookupWhileOneIsStillRunning(t *testing.T) {
	setupSessionRoots(t)
	var calls atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	testHookStatusLookup = func() {
		calls.Add(1)
		<-release
	}
	t.Cleanup(func() { testHookStatusLookup = nil })
	t.Cleanup(unblock)

	logs := &capturingHandler{}
	status := terminalStatus(statusSource{Name: "s", Escape: '~', Suspend: true}, slog.New(logs))
	unavailable := []string{"upterm: session status unavailable", keysLineWithSuspend}

	// The first lookup parks, and the bound frees the terminal from it.
	require.Equal(t, unavailable, status(context.Background()))
	require.Equal(t, int32(1), calls.Load())

	start := time.Now()
	lines := status(context.Background())
	require.Less(t, time.Since(start), statusLookupTimeout/2, "the second answer does not wait for a lookup of its own")
	require.Equal(t, unavailable, lines)
	require.Equal(t, int32(1), calls.Load(), "no second lookup was started")
	recs := logs.captured()
	require.Len(t, recs, 2)
	require.Equal(t, slog.LevelDebug, recs[1].Level)
	require.Equal(t, "s", recs[1].Attrs["session"])
	require.Contains(t, recs[1].Attrs["reason"], "still running")

	unblock()
	require.Eventually(t, func() bool {
		status(context.Background())
		return calls.Load() == 2
	}, 5*time.Second, 10*time.Millisecond, "a lookup runs again once the parked one has returned")
}

// The record says how the relay is; the daemon says who is connected and how
// to join. The session's own terminals are not guests.
func TestStatusLinesForAReadySession(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		t.Run(map[bool]string{false: "addresses shown", true: "addresses hidden"}[hidden], func(t *testing.T) {
			withClientIPs(t, hidden)
			setupSessionRoots(t)
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.SessionID = "sid-1" }))
			serveStubAdmin(t, dir.AdminSocket(), &api.GetSessionResponse{
				SessionId: "sid-1", LaunchId: dir.LaunchID(), SshUser: "sid-1",
				Host: "ssh://uptermd.example.com:22", NodeAddr: "127.0.0.1:2222",
				ConnectedClients: []*api.Client{
					{Kind: api.Client_HOST, Addr: "local", Version: "SSH-2.0-upterm-attach", PublicKeyFingerprint: "SHA256:host"},
					{Kind: api.Client_GUEST, Addr: "1.2.3.4:5", Version: "SSH-2.0-OpenSSH_10.3", PublicKeyFingerprint: "SHA256:abcd"},
					{Kind: api.Client_GUEST, Addr: "5.6.7.8:9", Version: "SSH-2.0-upterm-join", PublicKeyFingerprint: "SHA256:ef01"},
				},
			})

			addr1, addr2 := "1.2.3.4:5", "5.6.7.8:9"
			if hidden {
				addr1, addr2 = "[redacted]", "[redacted]"
			}
			lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~', Suspend: true}, nil)
			require.Equal(t, []string{
				"upterm: session s: 2 guests; the relay is connected",
				"upterm:   guest " + addr1 + " SSH-2.0-OpenSSH_10.3 SHA256:abcd",
				"upterm:   guest " + addr2 + " SSH-2.0-upterm-join SHA256:ef01",
				"upterm: guests join with: upterm join ssh://sid-1@uptermd.example.com",
				keysLineWithSuspend,
			}, lines)
		})
	}
}

// The record's outage is what the reconnecting lines say, retries as
// attempts.
func TestStatusLinesForAReconnectingSession(t *testing.T) {
	withClientIPs(t, false)
	setupSessionRoots(t)
	out := buildReconnecting(t, "s", true)
	rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), "s")
	require.NoError(t, err)

	lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: rec.LaunchID, AdminSocket: rec.AdminSocket, Escape: '~', Suspend: true}, nil)
	require.Len(t, lines, 4)
	require.Equal(t, "upterm: session s: 0 guests; the relay is disconnected since "+tui.ClockTime(out.lostAt)+" (network)", lines[0])
	require.Regexp(t, `^upterm: guests can't join while the relay is disconnected; next try in 3[56][0-9]{2} s$`, lines[1])
	require.Equal(t, "upterm: guests join with: upterm join ssh://sid-3@127.0.0.1:2222", lines[2])
	require.Equal(t, keysLineWithSuspend, lines[3])
}

// upterm attach reads --hide-client-ip, UPTERM_HIDE_CLIENT_IP and the config's
// hide-client-ip as every other command that prints a guest's address does,
// so ~? in an attached terminal hides what the host chose to hide.
func TestAttachStatusHidesClientIPsAsConfigured(t *testing.T) {
	for _, tc := range []struct{ name, env, config string }{
		{"from the environment", "true", ""},
		{"from the config", "", "hide-client-ip: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withClientIPs(t, false)
			withConfig(t, tc.config)
			t.Setenv("UPTERM_HIDE_CLIENT_IP", tc.env)
			attach, _, err := Root().Find([]string{"attach"})
			require.NoError(t, err)
			_, _, err = bindFlagsToEnv(attach)
			require.NoError(t, err)

			setupSessionRoots(t)
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusReady; r.SessionID = "sid-1" }))
			serveStubAdmin(t, dir.AdminSocket(), &api.GetSessionResponse{
				SessionId: "sid-1", LaunchId: dir.LaunchID(), SshUser: "sid-1",
				Host: "ssh://uptermd.example.com:22", NodeAddr: "127.0.0.1:2222",
				ConnectedClients: []*api.Client{
					{Kind: api.Client_GUEST, Addr: "1.2.3.4:5", Version: "SSH-2.0-OpenSSH_10.3", PublicKeyFingerprint: "SHA256:abcd"},
				},
			})

			lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: dir.LaunchID(), AdminSocket: dir.AdminSocket(), Escape: '~', Suspend: true}, nil)
			require.Contains(t, lines, "upterm:   guest [redacted] SSH-2.0-OpenSSH_10.3 SHA256:abcd")
			require.NotContains(t, strings.Join(lines, "\n"), "1.2.3.4")
		})
	}
}

// A status that is unavailable says why in the log, with the session's name:
// the lines say only that it is, and nothing else would.
func TestStatusSaysWhyItIsUnavailableInTheLog(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  func(t *testing.T) statusSource
		why  string
	}{
		{"no record", func(t *testing.T) statusSource {
			return statusSource{Name: "s", LaunchID: "l", AdminSocket: filepath.Join(t.TempDir(), "admin.sock")}
		}, "no record"},
		{"another launch", func(t *testing.T) statusSource {
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			return statusSource{Name: "s", LaunchID: "another-launch", AdminSocket: dir.AdminSocket()}
		}, "another launch"},
		{"a daemon that isn't there", func(t *testing.T) statusSource {
			dir := claimSession(t, "s")
			releaseAtEnd(t, dir)
			return statusSource{Name: "s", LaunchID: dir.LaunchID(), AdminSocket: filepath.Join(t.TempDir(), "admin.sock")}
		}, "asking the daemon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			src := tc.src(t)
			logs := &capturingHandler{}

			lines := statusLines(context.Background(), src, slog.New(logs))
			require.Equal(t, "upterm: session status unavailable", lines[0])
			recs := logs.captured()
			require.Len(t, recs, 1)
			require.Equal(t, slog.LevelDebug, recs[0].Level)
			require.Equal(t, "s", recs[0].Attrs["session"])
			require.Contains(t, recs[0].Attrs["reason"], tc.why)
		})
	}
}

// The name can pass to another launch while this terminal is attached: what
// holds it now is not the session this terminal is in.
func TestStatusOfAnotherLaunchIsUnavailable(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "s")
	rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), "s")
	require.NoError(t, err)

	lines := statusLines(context.Background(), statusSource{Name: "s", LaunchID: "another-launch", AdminSocket: rec.AdminSocket, Escape: '~'}, nil)
	require.Equal(t, []string{"upterm: session status unavailable", "upterm: keys: ~. detach  ~~ send ~  ~? this list"}, lines)
}

func TestManyGuestsAreSummarised(t *testing.T) {
	lines := renderStatus(statusView{Name: "s", Guests: fiveGuests(), RelayUp: true, Join: "upterm join ssh://id@relay"}, '~', true)
	require.Contains(t, lines, "upterm:   and 2 more: upterm session info s")
	require.Equal(t, []string{
		"upterm: session s: 5 guests; the relay is connected",
		"upterm:   guest 1.2.3.4 SSH-2.0-OpenSSH_10.3 SHA256:aaaa",
		"upterm:   guest 1.2.3.5 SSH-2.0-OpenSSH_10.3 SHA256:bbbb",
		"upterm:   guest 1.2.3.6 SSH-2.0-upterm-join SHA256:cccc",
		"upterm:   and 2 more: upterm session info s",
		"upterm: guests join with: upterm join ssh://id@relay",
		keysLineWithSuspend,
	}, lines)
}

func TestRenderStatusStates(t *testing.T) {
	lost := time.Date(2026, 10, 13, 9, 8, 7, 0, time.Local)
	for _, tc := range []struct {
		name string
		v    statusView
		want []string
	}{
		{"connected, one guest", statusView{Name: "s", Guests: fiveGuests()[:1], RelayUp: true, Join: "upterm join ssh://id@relay"}, []string{
			"upterm: session s: 1 guest; the relay is connected",
			"upterm:   guest 1.2.3.4 SSH-2.0-OpenSSH_10.3 SHA256:aaaa",
			"upterm: guests join with: upterm join ssh://id@relay",
			keysLineWithSuspend,
		}},
		{"reconnecting", statusView{Name: "s", CanReconnect: true, LostAt: lost, NextAt: time.Now().Add(90 * time.Second), Reason: "network", Join: "upterm join ssh://id@relay"}, []string{
			"upterm: session s: 0 guests; the relay is disconnected since 09:08:07 (network)",
			"upterm: guests can't join while the relay is disconnected; next try in 90 s",
			"upterm: guests join with: upterm join ssh://id@relay",
			keysLineWithSuspend,
		}},
		{"reconnecting, the next try under way", statusView{Name: "s", CanReconnect: true, LostAt: lost, NextAt: time.Now().Add(-time.Second), Reason: "network"}, []string{
			"upterm: session s: 0 guests; the relay is disconnected since 09:08:07 (network)",
			"upterm: guests can't join while the relay is disconnected",
			keysLineWithSuspend,
		}},
		{"lost, the relay can't reconnect", statusView{Name: "s", Guests: fiveGuests()[:2]}, []string{
			"upterm: session s: 2 guests; the relay connection is lost, and this relay can't reconnect; restart the session to share it again",
			"upterm:   guest 1.2.3.4 SSH-2.0-OpenSSH_10.3 SHA256:aaaa",
			"upterm:   guest 1.2.3.5 SSH-2.0-OpenSSH_10.3 SHA256:bbbb",
			keysLineWithSuspend,
		}},
		{"unavailable", statusView{Name: "s", Unavailable: true, Guests: fiveGuests(), RelayUp: true}, []string{
			"upterm: session status unavailable",
			keysLineWithSuspend,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, renderStatus(tc.v, '~', true))
		})
	}
}

// The keys line lists what works here: the escape character in use, and ^Z
// only where this terminal can be suspended.
func TestStatusKeysLineIsTheTerminalsOwn(t *testing.T) {
	v := statusView{Unavailable: true}
	require.Equal(t, "upterm: keys: ^. detach  ^^Z suspend  ^^ send ^  ^? this list", renderStatus(v, '^', true)[1])
	require.Equal(t, "upterm: keys: ~. detach  ~~ send ~  ~? this list", renderStatus(v, '~', false)[1])
}
