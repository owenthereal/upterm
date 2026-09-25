package command

import (
	"io"
	"log/slog"
	"testing"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLocalDisconnectMessageNamesTheLogAndTheReattachCommand(t *testing.T) {
	msg := localDisconnectMessage("build-shell", "/var/log/upterm.log", attach.Result{Reason: attach.Disconnected})
	require.Contains(t, msg, "build-shell")
	require.Contains(t, msg, "/var/log/upterm.log")
	require.Contains(t, msg, "upterm attach build-shell")
	require.Empty(t, localDisconnectMessage("x", "/l", attach.Result{Reason: attach.Exited}), "nothing to say when the command simply ended")
	require.Empty(t, localDisconnectMessage("x", "/l", attach.Result{Reason: attach.Detached}), "nothing to say when the terminal went away")
}

// Both notification sites, because filtering only the join would announce a
// departure with no arrival: the host's own terminal leaving, and — once
// upterm attach exists — every detach of it.
//
// The callbacks are driven, not only the predicate, so that a site which
// stopped asking is caught. Swapping notify is also what keeps this from
// raising real desktop notifications on whoever is running the suite.
func TestClientNotificationSkipsHostClients(t *testing.T) {
	require.False(t, shouldNotifyClient(&api.Client{Kind: api.Client_HOST}))
	require.True(t, shouldNotifyClient(&api.Client{Kind: api.Client_GUEST}))

	var sent []string
	orig := notify
	notify = func(title, message string, appIcon any) error {
		sent = append(sent, title)
		return nil
	}
	t.Cleanup(func() { notify = orig })

	clientJoinedCallback(&api.Client{Kind: api.Client_HOST})
	clientLeftCallback(&api.Client{Kind: api.Client_HOST})
	require.Empty(t, sent, "the host's own terminal is not a client to announce")

	clientJoinedCallback(&api.Client{Kind: api.Client_GUEST})
	clientLeftCallback(&api.Client{Kind: api.Client_GUEST})
	require.Equal(t, []string{"Upterm Client Joined", "Upterm Client Left"}, sent,
		"a guest is still announced both ways")
}
