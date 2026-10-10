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

	// An opaque URL has a known scheme and no "//" after it, whatever its case.
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
