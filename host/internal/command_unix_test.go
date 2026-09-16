//go:build !windows

package internal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
)

// inheritedTerm is what the test's own environment carries, so that a case
// asserting the host's TERM won is asserting that it beat something.
const inheritedTerm = "upterm-inherited-term"

// Test_Command_TermIsAppendedSoItBeatsTheInheritedOne covers wiring that is
// load-bearing and was untested: --term reaches the command, and it does so by
// being appended to the environment rather than prepended. exec.Cmd keeps the
// last duplicate key, so a prepended TERM would be silently overridden by the
// inherited one and the flag would do nothing at all.
func Test_Command_TermIsAppendedSoItBeatsTheInheritedOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		term string
		want string
	}{
		{name: "the host names a term", term: "vt100", want: "TERM=vt100"},
		{name: "the host names none", term: "", want: "TERM=" + inheritedTerm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", inheritedTerm)

			writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
			out := &recordingWriter{}
			require.NoError(t, writers.Append(out))

			cmd := newCommand(
				"sh", []string{"-c", "echo TERM=$TERM"},
				nil, termsize.Default, false, tc.term,
				emitter.New(1), writers, testLogger(t),
			)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err := cmd.Start(ctx, termsize.Size{})
			require.NoError(t, err)
			require.NoError(t, cmd.Run())

			require.Contains(t, string(out.bytes()), tc.want)
		})
	}
}

// Test_Command_SessionEnvBeatsTheInheritedOne pins the same rule for the
// variables that tell a script which session it is running in. A host started
// inside another upterm session -- or one whose variables were forwarded by
// the README's tmux tip -- inherits somebody else's UPTERM_SESSION_NAME and
// UPTERM_ADMIN_SOCKET, and `upterm session info` run inside the inner session
// would then report the outer one.
func Test_Command_SessionEnvBeatsTheInheritedOne(t *testing.T) {
	t.Setenv(upterm.HostSessionNameEnvVar, "outer-session")
	t.Setenv(upterm.HostAdminSocketEnvVar, "/outer/admin.sock")

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	out := &recordingWriter{}
	require.NoError(t, writers.Append(out))

	cmd := newCommand(
		"sh", []string{"-c", fmt.Sprintf("echo NAME=$%s SOCKET=$%s",
			upterm.HostSessionNameEnvVar, upterm.HostAdminSocketEnvVar)},
		[]string{
			upterm.HostSessionNameEnvVar + "=inner-session",
			upterm.HostAdminSocketEnvVar + "=/inner/admin.sock",
		},
		termsize.Default, false, "",
		emitter.New(1), writers, testLogger(t),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := cmd.Start(ctx, termsize.Size{})
	require.NoError(t, err)
	require.NoError(t, cmd.Run())

	require.Contains(t, string(out.bytes()), "NAME=inner-session SOCKET=/inner/admin.sock",
		"the session's own environment must beat the one it inherited")
}
