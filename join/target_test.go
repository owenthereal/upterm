package join

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTarget(t *testing.T) {
	ok := []struct {
		in    string
		want  Target
		relay string
	}{
		{"ssh://abc@uptermd.upterm.dev", Target{"ssh", "abc", "uptermd.upterm.dev:22"}, "uptermd.upterm.dev"},
		{"ssh://abc@relay.test:2222", Target{"ssh", "abc", "relay.test:2222"}, "relay.test:2222"},
		{"wss://abc@uptermd.upterm.dev", Target{"wss", "abc", "uptermd.upterm.dev:443"}, "uptermd.upterm.dev"},
		{"ws://abc@relay.test", Target{"ws", "abc", "relay.test:80"}, "relay.test"},
		{"wss://abc:bm9kZTE=@relay.test", Target{"wss", "abc:bm9kZTE=", "relay.test:443"}, "relay.test"},
		{"abc@relay.test", Target{"ssh", "abc", "relay.test:22"}, "relay.test"},
		{"abc:bm9kZTE=@relay.test:2222", Target{"ssh", "abc:bm9kZTE=", "relay.test:2222"}, "relay.test:2222"},
		{"SSH://abc@relay.test", Target{"ssh", "abc", "relay.test:22"}, "relay.test"},
		{"ssh://abc@relay.test/", Target{"ssh", "abc", "relay.test:22"}, "relay.test"},
		{"ssh://abc@[::1]:2222", Target{"ssh", "abc", "[::1]:2222"}, "[::1]:2222"},
		{"wss://abc@[2001:db8::1]", Target{"wss", "abc", "[2001:db8::1]:443"}, "[2001:db8::1]"},
		{"abc@[::1]", Target{"ssh", "abc", "[::1]:22"}, "[::1]"},
	}
	for _, tc := range ok {
		got, err := ParseTarget(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got, tc.in)
		require.Equal(t, tc.relay, got.Relay(), tc.in)
		require.Equal(t, "abc", got.SessionID(), tc.in)
	}

	for _, bad := range []string{
		"", "relay.test", "@relay.test", "abc@", "https://abc@relay.test", "ftp://abc@relay.test",
		"ssh://relay.test", "ssh://abc@relay.test/path", "ssh://abc@relay.test?x=1",
		"ssh://abc@relay.test#frag", "ssh:abc@relay.test", "abc@::1",
	} {
		_, err := ParseTarget(bad)
		require.ErrorIs(t, err, ErrNotATarget, bad)
	}
}

// A bare target's user is everything before the last "@", and the scheme
// check applies only to what precedes the first ":". Each of these is a shape
// url.Parse reports as opaque or mis-splits, so the parser can't lean on it.
func TestParseTargetBareForm(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Target
	}{
		{"abc@def@relay.test", Target{"ssh", "abc@def", "relay.test:22"}},
		{"abc:node@relay.test", Target{"ssh", "abc:node", "relay.test:22"}},
		{"sshabc:node@relay.test", Target{"ssh", "sshabc:node", "relay.test:22"}},
		{"ws2:node@relay.test:2222", Target{"ssh", "ws2:node", "relay.test:2222"}},
	} {
		got, err := ParseTarget(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}

	// Refused: an opaque URL, which has a known scheme, whatever its case,
	// and no "//" after it; a port that is empty, not a number or out of
	// range; and an empty host.
	for _, bad := range []string{
		"ssh:abc@relay.test", "SSH:abc@relay.test", "ws:abc@relay.test", "wss:abc@relay.test",
		"abc@relay.test:", "abc@relay.test:port", "abc@relay.test:0", "abc@relay.test:65536",
		"abc@:22", "ssh://abc@:22", "ssh://abc@relay.test:",
	} {
		_, err := ParseTarget(bad)
		require.ErrorIs(t, err, ErrNotATarget, bad)
	}
}

// A target with no session ID, or with something after the host that isn't a
// port, names nothing to join, however much of it is well-formed.
func TestParseTargetRejectsStrays(t *testing.T) {
	for _, bad := range []string{
		":node@relay.test", "ssh://:node@relay.test", "abc@relay.test/path", "abc@re lay.test",
		"ssh://abc@relay.test//", "ssh://abc@relay.test?", "ssh://abc@relay.test#",
		"ssh://abc@[::1", "ssh://abc@[::1]x", "ssh://abc@[relay.test]", "ssh://abc@[1.2.3.4]",
		"ssh://abc@::1", "ssh://",
	} {
		_, err := ParseTarget(bad)
		require.ErrorIs(t, err, ErrNotATarget, bad)
	}
}

// URL is what the dial reads the session ID and the node from: the session ID
// is the userinfo's username and the node is its password.
func TestTargetURL(t *testing.T) {
	for _, tc := range []struct {
		in       string
		want     string
		username string
		password string
		hasPass  bool
	}{
		{"ssh://abc@relay.test", "ssh://abc@relay.test:22", "abc", "", false},
		{"wss://abc:bm9kZTE=@relay.test", "wss://abc:bm9kZTE=@relay.test:443", "abc", "bm9kZTE=", true},
		{"abc:bm9kZTE=@relay.test:2222", "ssh://abc:bm9kZTE=@relay.test:2222", "abc", "bm9kZTE=", true},
		{"ws://abc@[::1]:8080", "ws://abc@[::1]:8080", "abc", "", false},
		{"wss://abc:node@[2001:db8::1]", "wss://abc:node@[2001:db8::1]:443", "abc", "node", true},
	} {
		target, err := ParseTarget(tc.in)
		require.NoError(t, err, tc.in)

		u := target.URL()
		require.Equal(t, tc.want, u.String(), tc.in)
		require.Equal(t, tc.username, u.User.Username(), tc.in)
		password, hasPass := u.User.Password()
		require.Equal(t, tc.password, password, tc.in)
		require.Equal(t, tc.hasPass, hasPass, tc.in)

		// Parsing the URL back gives the same target.
		back, err := ParseTarget(u.String())
		require.NoError(t, err, tc.in)
		require.Equal(t, target, back, tc.in)
	}

	// A hand-built URL round-trips the way the dial reads it.
	u, err := url.Parse(Target{"ssh", "abc:node", "relay.test:22"}.URL().String())
	require.NoError(t, err)
	require.Equal(t, "abc", u.User.Username())
}

// Whitespace and control characters belong to no target. Each of these is a
// valid target with one added, and most of them were read as a session ID or a
// host that happens to contain it: the user of "ab c@relay.test" is "ab c".
func TestParseTargetRefusesWhitespaceAndControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"ab c@relay.test", "abc\t@relay.test", "abc\n@relay.test", "abc\x00@relay.test",
		" abc@relay.test", "\tabc@relay.test", "abc@relay.test ", "abc@relay.test\n", "abc@relay.test\r\n",
		"abc@relay.test\u00a0", "abc@relay.test\u2003", "abc@re\x7flay.test",
		"ssh://abc@relay.test\n", "ssh://ab c@relay.test", "wss://abc:no de@relay.test",
	} {
		_, err := ParseTarget(bad)
		require.ErrorIs(t, err, ErrNotATarget, "%q", bad)

		var targetErr *TargetError
		require.ErrorAs(t, err, &targetErr, "%q", bad)
		require.Empty(t, targetErr.Suggestion, "%q is no command upterm prints", bad)
	}
}

// A guest who pastes an ssh command upterm printed is told which target it
// reaches. The commands below are those the session's info prints, in the
// quoting it uses for a shell, and the one `upterm proxy --help` and the
// relay's welcome text give, along with what ssh reads the same and a guest
// may have instead: the port first, the default port spelled out, extra
// spaces, whitespace around the line. ParseTarget reads each one as a refusal
// that carries the target.
func TestParseTargetSuggestsTheTargetOfAPrintedSSHCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"ssh", `ssh sid@example.com`, "sid@example.com"},
		{"ssh with a port", `ssh sid@example.com -p 2222`, "sid@example.com:2222"},
		{"ssh with the port first", `ssh -p 2222 sid@example.com`, "sid@example.com:2222"},
		{"ssh with a node", `ssh sid:MTI3LjAuMC4xOjIyMjI=@example.com -p 2222`, "sid:MTI3LjAuMC4xOjIyMjI=@example.com:2222"},
		{"ssh with the default port", `ssh sid@example.com -p 22`, "sid@example.com:22"},
		{"ssh to an IPv6 address", `ssh sid@::1`, "sid@[::1]"},
		{"ssh to an IPv6 address and a port", `ssh sid@::1 -p 2222`, "sid@[::1]:2222"},
		{"ssh with extra spaces", `ssh  sid@example.com   -p  2222 `, "sid@example.com:2222"},
		// A triple-click takes the line's newline with it.
		{"ssh with a trailing newline", "ssh sid@example.com\n", "sid@example.com"},
		{"ssh with a trailing CRLF", "ssh sid@example.com -p 2222\r\n", "sid@example.com:2222"},
		{"ssh between tabs", "\tssh sid@example.com\t", "sid@example.com"},

		{"wss", `ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com'\''' sid@example.com:443`, "wss://sid@example.com"},
		{"ws with a port", `ssh -o ProxyCommand='upterm proxy '\''ws://sid@example.com:8080'\''' sid@example.com:8080`, "ws://sid@example.com:8080"},
		{"wss with a node", `ssh -o ProxyCommand='upterm proxy '\''wss://sid:MTI3LjAuMC4xOjIyMjI=@example.com'\''' sid:MTI3LjAuMC4xOjIyMjI=@example.com:443`, "wss://sid:MTI3LjAuMC4xOjIyMjI=@example.com"},
		{"wss to an IPv6 address", `ssh -o ProxyCommand='upterm proxy '\''wss://sid@[::1]:8443'\''' sid@::1:8443`, "wss://sid@[::1]:8443"},
		{"wss with a trailing slash", `ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com/'\''' sid@example.com:443`, "wss://sid@example.com/"},
		// upterm doubles each % for ssh, which reads %% as one before it runs
		// the command in a shell.
		{"wss with a %", `ssh -o ProxyCommand='upterm proxy '\''wss://s%%2541@example.com'\''' s%41@example.com:443`, "wss://s%2541@example.com"},
		// The form `upterm proxy --help` and the relay's welcome text give.
		{"wss as typed by hand", `ssh -o ProxyCommand='upterm proxy wss://sid@example.com' sid@example.com:443`, "wss://sid@example.com"},
		{"wss with a trailing newline", "ssh -o ProxyCommand='upterm proxy wss://sid@example.com' sid@example.com:443\n", "wss://sid@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTarget(tc.in)
			require.ErrorIs(t, err, ErrNotATarget)

			var targetErr *TargetError
			require.ErrorAs(t, err, &targetErr)
			require.Equal(t, tc.in, targetErr.Input)
			require.Equal(t, tc.want, targetErr.Suggestion)

			_, err = ParseTarget(targetErr.Suggestion)
			require.NoError(t, err, "a suggestion is a target")
		})
	}
}

// Only the commands upterm prints are read. Anything else, though it may name
// the same relay, is no basis for a suggestion, least of all its last field:
// the ws form's is the ssh address "sid@example.com:443", which is not where
// the session is.
func TestParseTargetSuggestsNothingForOtherText(t *testing.T) {
	for _, in := range []string{
		// ssh with options or arguments upterm doesn't print.
		`ssh sid@example.com -L 80:x:80`, `ssh -J jump.test sid@example.com`, `ssh -p 2222 sid@example.com ls`,
		`ssh sid@example.com -p 2222 -v`, `ssh -p 2222 -p 2223 sid@example.com`, `ssh -oPort=2222 sid@example.com`,
		`ssh sid@example.com -p`, `ssh sid@example.com -p abc`, `ssh sid@example.com -p 0`, `ssh sid@example.com -p 65536`,
		`ssh sid@example.com:2222`, `ssh sid@example.com:`, `ssh example.com`, `ssh @example.com`, `ssh sid@`,
		`ssh ssh://sid@example.com`, `ssh wss://sid@example.com`, `ssh sid@example.com/path`, `ssh 'sid @example.com'`,
		`ssh`, `ssh `, "ssh sid@example.com \t-p 2222",
		// Not ssh.
		`sftp sid@example.com`, `scp sid@example.com:file .`, `mosh sid@example.com`, `sid@example.com -p 2222`,
		`sid@example.com ssh`, `upterm join sid@example.com`, `hello world`, `ssh://sid@example.com ssh`,
		// ProxyCommand that isn't `upterm proxy URL`, or whose URL isn't a ws target.
		`ssh -o ProxyCommand='nc proxy.test 80' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy wss://sid@example.com extra' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm tunnel wss://sid@example.com' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy ssh://sid@example.com' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy sid@example.com' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy https://sid@example.com' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com/ws'\''' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com/?a=1'\''' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy '\''wss://example.com'\''' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy wss://sid@example.com' sid@example.com:443 -L 80:x:80`,
		`ssh -o ProxyCommand='upterm proxy wss://sid@example.com'`,
		`ssh -o StrictHostKeyChecking=no sid@example.com:443`,
		`ssh -o ProxyCommand=upterm sid@example.com:443`,
		// A % ssh would expand, and text a shell would expand or run.
		`ssh -o ProxyCommand='upterm proxy wss://sid@%h' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy wss://s%41@example.com' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy wss://sid@example.com%%%' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy $(id)' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy wss://sid@example.com; id' sid@example.com:443`,
		`ssh -o ProxyCommand=upterm\ proxy\ wss://sid@example.com\;id sid@example.com:443`,
		`ssh $HOME@example.com`, `ssh sid@$(id)`, `ssh sid@example.com; id`, "ssh sid@`id`", `ssh sid@*`, `ssh ~sid@example.com`,
		`ssh "sid@example.com"`, `ssh sid@example.com\`, `ssh 'sid@example.com`,
		// Whitespace within the command other than the space upterm separates
		// words with.
		"ssh\tsid@example.com", "ssh sid@example.com\n-p 2222", "ssh\u00a0sid@example.com",
		"ssh -o ProxyCommand='upterm proxy wss://sid@example.com' sid@example.com\t:443",
	} {
		_, err := ParseTarget(in)
		require.ErrorIs(t, err, ErrNotATarget, "%q", in)

		var targetErr *TargetError
		require.ErrorAs(t, err, &targetErr, "%q", in)
		require.Empty(t, targetErr.Suggestion, "%q", in)
	}
}

// The text of an error keeps its shape: the command renders what the guest
// reads, and logs show this.
func TestTargetErrorText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"relay.test", `not a join target "relay.test": no USER@ before the host`},
		{"ssh sid@example.com", `not a join target "ssh sid@example.com": whitespace or a control character`},
		{"abc@relay.test\n", `not a join target "abc@relay.test\n": whitespace or a control character`},
	} {
		_, err := ParseTarget(tc.in)
		require.EqualError(t, err, tc.want)
	}
}
