package host

import (
	"strings"
	"testing"

	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// unsafeAnswerValues are SSH users or session IDs a relay could answer with
// that upterm won't put in a command, each holding a character the check
// refuses. Each is marked "evil", so that a repetition shows in any escaping.
var unsafeAnswerValues = []struct{ name, value string }{
	{"a newline", "evil\nid"},
	{"a semicolon", "evil;id"},
	{"a command substitution", "evil$(id)"},
	{"a backquote", "evil`id`"},
	{"a space", "evil id"},
	{"a double quote", `evil"id`},
	{"a single quote", "evil'id"},
	{"a leading dash", "-oProxyCommand=evil"},
	{"a percent sign", "evil%id"},
	{"a non-ASCII letter", "evilé"},
	{"a tilde a shell expands", "x=~:evil"},
}

// commandSafe, on every platform: it takes the session IDs relays make and
// the users they give, and the rest of the punctuation it allows, and refuses
// every value the Run tests refuse, in either place, an empty session ID, and
// a first character that isn't a letter or a digit.
func TestCommandSafe(t *testing.T) {
	random := utils.GenerateSessionID()
	key, err := NewHostKey()
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	derived := registration.ID(key.PublicKey(), secret)
	embedded := routing.NewEncodeDecoder(routing.ModeEmbedded)
	onePad := embedded.Encode(random, "127.0.0.1:2222")
	twoPads := embedded.Encode(random, "127.0.0.1:222")
	require.True(t, strings.HasSuffix(onePad, "=") && !strings.HasSuffix(onePad, "=="), onePad)
	require.True(t, strings.HasSuffix(twoPads, "=="), twoPads)

	for _, tc := range []struct {
		name string
		resp *server.CreateSessionResponse
	}{
		{"a random session ID, as the user too", &server.CreateSessionResponse{SessionID: random, SshUser: random}},
		{"a session ID derived from the host's key, as the user too", &server.CreateSessionResponse{SessionID: derived, SshUser: derived}},
		{"an embedded relay's ID:base64url(node) padded with '='", &server.CreateSessionResponse{SessionID: random, SshUser: onePad}},
		{"an embedded relay's ID:base64url(node) padded with '=='", &server.CreateSessionResponse{SessionID: random, SshUser: twoPads}},
		{"an empty SSH user with a valid ID", &server.CreateSessionResponse{SessionID: random}},
		{"the rest of the allowed punctuation", &server.CreateSessionResponse{SessionID: "a1.b_c+d-e", SshUser: "a1.b_c+d-e"}},
	} {
		t.Run("takes "+tc.name, func(t *testing.T) {
			require.True(t, commandSafe(tc.resp))
		})
	}

	refused := append([]struct{ name, value string }{
		{"a leading dot", ".evil"},
		{"a leading underscore", "_evil"},
		{"a leading plus sign", "+evil"},
	}, unsafeAnswerValues...)
	for _, bad := range refused {
		t.Run("refuses "+bad.name+" in the SSH user", func(t *testing.T) {
			require.False(t, commandSafe(&server.CreateSessionResponse{SessionID: random, SshUser: bad.value}))
		})
		t.Run("refuses "+bad.name+" in the session ID", func(t *testing.T) {
			require.False(t, commandSafe(&server.CreateSessionResponse{SessionID: bad.value, SshUser: random}))
		})
	}
	t.Run("refuses an empty session ID", func(t *testing.T) {
		require.False(t, commandSafe(&server.CreateSessionResponse{SshUser: random}))
	})
}
