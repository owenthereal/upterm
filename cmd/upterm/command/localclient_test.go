package command

import (
	"io"
	"log/slog"
	"testing"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/icon"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// swapNotify has fn see what would be sent as a desktop notification, for the
// length of the test. It is also what keeps a test from raising real
// notifications on whoever is running the suite.
func swapNotify(t *testing.T, fn func(title, message string, appIcon any) error) {
	t.Helper()
	orig := notify
	notify = fn
	t.Cleanup(func() { notify = orig })
}

// Both notification sites, because filtering only the join would announce a
// departure with no arrival: the host's own terminal leaving, and — once
// upterm attach exists — every detach of it.
//
// The notifier is driven, not only the predicate, so that a site which
// stopped asking is caught.
func TestNotificationsNameTheSessionAndSayGuest(t *testing.T) {
	require.False(t, shouldNotifyClient(&api.Client{Kind: api.Client_HOST}))
	require.True(t, shouldNotifyClient(&api.Client{Kind: api.Client_GUEST}))

	var titles []string
	swapNotify(t, func(title, _ string, _ any) error { titles = append(titles, title); return nil })
	cb := guestNotifier("build")

	cb.joined(&api.Client{Kind: api.Client_HOST})
	cb.left(&api.Client{Kind: api.Client_HOST})
	require.Empty(t, titles, "the host's own terminal is not a guest to announce")

	cb.joined(&api.Client{Kind: api.Client_GUEST})
	cb.left(&api.Client{Kind: api.Client_GUEST})
	require.Equal(t, []string{"A guest joined build", "A guest left build"}, titles,
		"a guest is announced both ways")
}

func TestGuestNotificationsCarryTheClientRow(t *testing.T) {
	var bodies []string
	swapNotify(t, func(_, body string, _ any) error { bodies = append(bodies, body); return nil })
	c := &api.Client{Kind: api.Client_GUEST, Addr: "198.51.100.7:4242", Version: "SSH-2.0-OpenSSH_9.9", PublicKeyFingerprint: "SHA256:abc"}

	guestNotifier("build").joined(c)
	guestNotifier("build").left(c)
	require.Equal(t, []string{clientDesc(c), clientDesc(c)}, bodies)
}

func TestTunnelNotificationsFollowTheState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event host.TunnelEvent
		want  notification
	}{
		{"lost, and the relay can reconnect", host.TunnelEvent{Up: false, CanReconnect: true},
			notification{"build lost the relay", "Guests can't join while the relay is disconnected; upterm is retrying."}},
		{"lost, and the relay can't reconnect", host.TunnelEvent{Up: false, CanReconnect: false},
			notification{"build lost the relay", "This relay can't reconnect it; guests can't join until you restart the session."}},
		{"back, the same connect string", host.TunnelEvent{Up: true},
			notification{"build is back on the relay", "Guests can join again with the same command."}},
		{"back, the connect string changed", host.TunnelEvent{Up: true, RouteChanged: true},
			notification{"build is back on the relay", "Its connect string changed; upterm session info build shows the new one."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tunnelNotification("build", tc.event))
		})
	}
}

func TestTunnelNotifierRaisesTheNotification(t *testing.T) {
	type sent struct {
		title, body string
		icon        any
	}
	var got []sent
	swapNotify(t, func(title, body string, appIcon any) error {
		got = append(got, sent{title, body, appIcon})
		return nil
	})

	tunnelNotifier("build")(host.TunnelEvent{Up: true})
	require.Equal(t, []sent{{"build is back on the relay", "Guests can join again with the same command.", icon.Upterm}}, got)
}
