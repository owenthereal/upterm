//go:build !windows

package host

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// answeredRun is what one Run did with the relay's answer to its first
// registration: what it returned, the session it reported and the warnings it
// gave before that, its log, and the record it left.
type answeredRun struct {
	err      error
	created  *api.GetSessionResponse
	warnings []RelayWarning
	log      string
	// record is the record file as Run left it, byte for byte.
	record []byte
}

// runAnswered runs a Host against a relay that answers its registration with
// resp. A session Run reports is declined, so the run ends there whether or
// not the answer was taken.
func runAnswered(t *testing.T, resp *server.CreateSessionResponse) answeredRun {
	t.Helper()
	return runAgainst(t, func(*server.CreateSessionRequest) (bool, []byte) {
		b, err := proto.Marshal(resp)
		if err != nil {
			return false, []byte(err.Error())
		}
		return true, b
	})
}

// runAgainst runs a Host against a relay that replies to its registration as
// answer does, and declines any session Run reports.
func runAgainst(t *testing.T, answer func(*server.CreateSessionRequest) (ok bool, body []byte)) answeredRun {
	t.Helper()
	// Short, for the unix sockets a claimed name's directory holds.
	root, err := os.MkdirTemp("/tmp", "up-answer-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_STATE_HOME", root)

	relayKey, err := NewHostKey()
	require.NoError(t, err)
	relay := fakerelay.Start(t, relayKey, answer)
	identity, err := NewHostKey()
	require.NoError(t, err)

	var (
		run        answeredRun
		recordPath string
		logs       lockedBuffer
	)
	h := &Host{
		Host:                   "ssh://" + relay.Addr,
		Name:                   "answer",
		Command:                []string{"sh"},
		Signers:                []ssh.Signer{identity},
		HostKeyCallback:        ssh.InsecureIgnoreHostKey(),
		Logger:                 slog.New(slog.NewTextHandler(&logs, nil)),
		SessionClaimedCallback: func(dir *sessiondir.Dir) { recordPath = dir.RecordPath() },
		RelayWarningCallback:   func(w RelayWarning) { run.warnings = append(run.warnings, w) },
		SessionCreatedCallback: func(_ context.Context, s *api.GetSessionResponse) error {
			run.created = s
			return ErrSessionAbandoned
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run.err = h.Run(ctx)
	run.log = logs.String()
	require.NotEmpty(t, recordPath, "Run never claimed the name")
	run.record, err = os.ReadFile(recordPath)
	require.NoError(t, err)
	return run
}

// parsedRecord is the record a run left, as `upterm session info` reads it.
func (r answeredRun) parsedRecord(t *testing.T) sessiondir.Record {
	t.Helper()
	var rec sessiondir.Record
	require.NoError(t, json.Unmarshal(r.record, &rec))
	return rec
}

// A relay chooses the session ID and the SSH user, and both go into the
// commands people paste into a shell: the banner's ssh, scp, sftp and upterm
// join lines, and the JSON that carries the ssh and join lines. An answer
// with anything in either beyond the few characters upterm puts in a command
// starts no session: Run says so, reports and records nothing of it, and
// never repeats the value, whose "evil" mark is in neither the log nor the
// record.
func TestRunRefusesARelayAnswerWithCharactersUptermWontPutInACommand(t *testing.T) {
	const refused = "the relay's answer has an SSH user or session ID upterm won't put in a command; not starting the session"
	valid := utils.GenerateSessionID()
	for _, bad := range unsafeAnswerValues {
		for _, at := range []struct {
			name string
			resp *server.CreateSessionResponse
		}{
			{"in the SSH user", &server.CreateSessionResponse{SessionID: valid, NodeAddr: "127.0.0.1:2222", SshUser: bad.value}},
			{"in the session ID", &server.CreateSessionResponse{SessionID: bad.value, NodeAddr: "127.0.0.1:2222", SshUser: valid}},
		} {
			t.Run(bad.name+" "+at.name, func(t *testing.T) {
				run := runAnswered(t, at.resp)
				require.EqualError(t, run.err, refused)
				require.Nil(t, run.created, "the session was reported")
				require.Empty(t, run.warnings, "warned about a session that never started")
				require.NotContains(t, run.log, "evil", "the log repeats the relay's value")
				require.NotContains(t, string(run.record), "evil", "the record holds the relay's value")
				rec := run.parsedRecord(t)
				require.Empty(t, rec.SessionID, "the record names the session")
				require.Equal(t, sessiondir.ReasonStartupFailed, rec.Reason)
			})
		}
	}
}

// An answer upterm will put in a command is taken. Relays answer with a
// session ID of 20 letters and digits, random or derived from the host's key,
// which a relay that routes by ID gives as the user too; with an embedded
// relay's ID:base64url(node), its '=' padding included; and, older relays,
// with an empty user, from which the CLI builds ID:base64url(node). No relay
// answers with the rest of the punctuation the check allows, which is taken
// all the same.
func TestRunTakesAnAnswerUptermWillPutInACommand(t *testing.T) {
	id := utils.GenerateSessionID()
	const node = "127.0.0.1:2222"
	embedded := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(id, node)
	require.Contains(t, embedded, "=", "the node's base64url is padded")
	for _, tc := range []struct {
		name string
		resp *server.CreateSessionResponse
	}{
		{"a random session ID, as the user too", &server.CreateSessionResponse{SessionID: id, NodeAddr: node, SshUser: id}},
		{"an embedded relay's ID:base64url(node)", &server.CreateSessionResponse{SessionID: id, NodeAddr: node, SshUser: embedded}},
		{"the rest of the allowed punctuation", &server.CreateSessionResponse{SessionID: "a1.b_c+d-e", NodeAddr: node, SshUser: "a1.b_c+d-e"}},
		{"an empty SSH user with a valid ID", &server.CreateSessionResponse{SessionID: id, NodeAddr: node}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runAnswered(t, tc.resp)
			require.ErrorIs(t, run.err, ErrSessionAbandoned, "Run stopped before it reported the session")
			require.NotNil(t, run.created)
			require.Equal(t, tc.resp.SessionID, run.created.GetSessionId())
			require.Equal(t, tc.resp.SshUser, run.created.GetSshUser())
			require.Equal(t, tc.resp.SessionID, run.parsedRecord(t).SessionID)
		})
	}
}

// A relay that refuses the registration says why in words of its own
// choosing, and Run's error carries them to the host's terminal. They arrive
// as plain text: an escape sequence in them, such as an OSC 52 write to the
// clipboard, would be the terminal's to act on, and the host's next paste
// would run what the relay chose. And they arrive cut to 255 bytes, the
// ellipsis that says so among them, since a relay can send far more.
func TestRunShowsARelaysRefusalAsPlainText(t *testing.T) {
	t.Run("an escape sequence and a newline", func(t *testing.T) {
		run := runAgainst(t, func(*server.CreateSessionRequest) (bool, []byte) {
			return false, []byte("the relay says no\x1b]52;c;ZWNobyBoaQ==\x07\nand more")
		})
		require.Error(t, run.err)
		require.Nil(t, run.created, "the session was reported")
		text := run.err.Error()
		for _, c := range []struct{ name, char string }{{"an ESC", "\x1b"}, {"a BEL", "\x07"}, {"a newline", "\n"}} {
			require.NotContains(t, text, c.char, "the error carries %s from the relay", c.name)
		}
		for _, visible := range []string{"could not initialize session: the relay says no", "]52;c;ZWNobyBoaQ==", "and more"} {
			require.Contains(t, text, visible, "the error lost the relay's visible text")
		}
	})

	t.Run("more than 255 bytes", func(t *testing.T) {
		const bound = 255
		body := strings.Repeat("the relay won't take this session. ", 10)
		require.Greater(t, len(body), bound)
		run := runAgainst(t, func(*server.CreateSessionRequest) (bool, []byte) {
			return false, []byte(body)
		})
		require.Error(t, run.err)
		require.Nil(t, run.created, "the session was reported")
		_, shown, ok := strings.Cut(run.err.Error(), "could not initialize session: ")
		require.True(t, ok, "the error doesn't give the relay's refusal: %v", run.err)
		require.Len(t, shown, bound, "the relay's part of the error isn't cut to %d bytes", bound)
		require.Equal(t, body[:bound-len("…")]+"…", shown)
	})
}
