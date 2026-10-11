package join

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrNotATarget is what ParseTarget's errors wrap: the text names no session to
// join.
var ErrNotATarget = errors.New("not a join target")

// TargetError is ParseTarget's error for text that names no session to join.
type TargetError struct {
	Input  string // the text, as given
	Reason string // what is wrong with it
	// Suggestion is the target Input's command reaches, when Input, less any
	// whitespace around it, is one of the ssh commands upterm prints for
	// guests; "" for anything else. It parses as a target.
	Suggestion string
}

func (e *TargetError) Error() string {
	return fmt.Sprintf("%v %q: %s", ErrNotATarget, e.Input, e.Reason)
}

// Is reports a match with ErrNotATarget.
func (e *TargetError) Is(target error) bool { return target == ErrNotATarget }

// defaultPorts maps each scheme a target may carry to its default port. A
// scheme absent here is not a join scheme.
var defaultPorts = map[string]string{
	"ssh": "22",
	"ws":  "80",
	"wss": "443",
}

// Target is a session to join and the relay to reach it through.
type Target struct {
	Scheme string // "ssh", "ws" or "wss"
	User   string // the connect string's user, colon form included
	Host   string // host:port, the port defaulted
}

// ParseTarget reads scheme://USER@HOST[:PORT][/] or the bare USER@HOST[:PORT],
// which means ssh. USER is the session ID, or SESSION:NODE when the relay is
// one of several and the connect string names the node that holds the session.
// An IPv6 literal must be bracketed, as it is in a URL. The error is a
// *TargetError, which wraps ErrNotATarget.
func ParseTarget(s string) (Target, error) {
	// Nothing a target is made of is whitespace or a control character, so
	// text that has one is not a target, whatever the parts around it look
	// like: "ssh abc@relay.test" would otherwise be the session "ssh abc".
	// Nor a byte that isn't UTF-8: one such as 0x9b is a control sequence to
	// some terminals, and the session ID is printed on the guest's.
	if !utf8.ValidString(s) {
		return Target{}, notATarget(s, "text that isn't UTF-8")
	}
	if strings.ContainsFunc(s, isSpaceOrControl) {
		err := notATarget(s, "whitespace or a control character")
		err.Suggestion = suggestTarget(s)
		return Target{}, err
	}

	if strings.Contains(s, "://") {
		return parseURLTarget(s)
	}

	// url.Parse reads "ssh:abc@relay.test" as an opaque URL and
	// "abc:node@relay.test" as one whose scheme is "abc", so it can't tell a
	// bare target from a URL. A known scheme with no "//" after it is a URL
	// that lost its slashes, and anything else is the bare form.
	if scheme, _, ok := strings.Cut(s, ":"); ok {
		if _, known := defaultPorts[strings.ToLower(scheme)]; known {
			return Target{}, notATarget(s, "a URL needs // after its scheme")
		}
	}

	// The user may hold a colon but never an "@", so the host starts after the
	// last one.
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return Target{}, notATarget(s, "no USER@ before the host")
	}
	return newTarget("ssh", s[:i], s[i+1:], s)
}

func parseURLTarget(s string) (Target, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, notATarget(s, err.Error())
	}
	// url.Parse lower-cases the scheme, which is what makes it case-insensitive.
	if _, ok := defaultPorts[u.Scheme]; !ok {
		return Target{}, notATarget(s, fmt.Sprintf("scheme %q is not ssh, ws or wss", u.Scheme))
	}
	if u.Opaque != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(s, "?#") {
		return Target{}, notATarget(s, "a target has no path, query or fragment")
	}
	if u.User == nil {
		return Target{}, notATarget(s, "no USER@ before the host")
	}

	user := u.User.Username()
	if node, ok := u.User.Password(); ok {
		user += ":" + node
	}
	// url.Parse has decoded the escapes in the userinfo, and in the host those
	// of bytes past ASCII and of an IPv6 zone, so the parts can hold what the
	// text, checked above, doesn't: "ssh://abc%0Adef@relay.test" is the user
	// "abc\ndef". What an escape spells belongs to no target either, and
	// neither does a byte that isn't UTF-8 ("%9b").
	if !utf8.ValidString(user) || !utf8.ValidString(u.Host) {
		return Target{}, notATarget(s, "an escape that isn't UTF-8")
	}
	if strings.ContainsFunc(user, isSpaceOrControl) || strings.ContainsFunc(u.Host, isSpaceOrControl) {
		return Target{}, notATarget(s, "an escaped whitespace or control character")
	}
	return newTarget(u.Scheme, user, u.Host, s)
}

// newTarget checks the parts both forms yield and puts the target together.
// in is the text they came from, for the error.
func newTarget(scheme, user, hostPort, in string) (Target, error) {
	if sessionID, _, _ := strings.Cut(user, ":"); sessionID == "" {
		return Target{}, notATarget(in, "no session ID before the @")
	}
	host, err := normalizeHost(hostPort, defaultPorts[scheme])
	if err != nil {
		return Target{}, notATarget(in, err.Error())
	}
	return Target{Scheme: scheme, User: user, Host: host}, nil
}

// normalizeHost returns hostPort as net.JoinHostPort would write it, with
// defaultPort filled in when hostPort has none.
func normalizeHost(hostPort, defaultPort string) (string, error) {
	host, port := hostPort, ""
	switch {
	case strings.HasPrefix(hostPort, "["):
		// A bracketed IPv6 literal, with or without a port after it.
		end := strings.Index(hostPort, "]")
		if end < 0 {
			return "", errors.New("an IPv6 address needs a closing ]")
		}
		host = hostPort[1:end]
		if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
			return "", fmt.Errorf("%q is not an IPv6 address", host)
		}
		if rest := hostPort[end+1:]; rest != "" {
			if rest[0] != ':' {
				return "", errors.New("unexpected text after the ]")
			}
			port = rest[1:]
		} else {
			port = defaultPort
		}
	case strings.Count(hostPort, ":") > 1:
		return "", errors.New("an IPv6 address must be in brackets")
	case strings.Contains(hostPort, ":"):
		var err error
		if host, port, err = net.SplitHostPort(hostPort); err != nil {
			return "", err
		}
	default:
		port = defaultPort
	}

	if host == "" {
		return "", errors.New("no host")
	}
	if strings.ContainsFunc(host, func(r rune) bool {
		return r <= ' ' || r == 0x7f || strings.ContainsRune(`/?#@\[]`, r)
	}) {
		return "", fmt.Errorf("%q is not a host", host)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", fmt.Errorf("%q is not a port", port)
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10)), nil
}

func notATarget(in, why string) *TargetError {
	return &TargetError{Input: in, Reason: why}
}

func isSpaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// suggestTarget reads s, less any whitespace around it, as one of the ssh
// commands upterm prints for guests and returns the target it reaches, or ""
// for any other text. It takes only those shapes, and not a likeness of them,
// so that a suggestion is never a guess:
//
//	ssh ID@HOST
//	ssh ID@HOST -p PORT       (or ssh -p PORT ID@HOST)
//	ssh -o ProxyCommand=... ID@HOST:PORT
//
// The last reaches the relay by `upterm proxy URL`, and that URL, not the last
// field, is the target: read as a target, the last field would be an ssh one,
// and the session is not reached by ssh.
func suggestTarget(s string) string {
	// Whitespace around the command is no part of it: the newline a
	// triple-click takes with a terminal's line, say. Within it, a word ends
	// at a space and at no other whitespace, as in the commands upterm prints.
	s = strings.TrimSpace(s)
	if strings.ContainsFunc(s, func(r rune) bool { return r != ' ' && isSpaceOrControl(r) }) {
		return ""
	}
	words, ok := shellWords(s)
	if !ok || len(words) < 2 || words[0] != "ssh" {
		return ""
	}

	switch args := words[1:]; {
	case len(args) == 1:
		return sshTarget(args[0], "")
	case len(args) == 3 && args[1] == "-p":
		return sshTarget(args[0], args[2])
	case len(args) == 3 && args[0] == "-p":
		return sshTarget(args[2], args[1])
	case len(args) == 3 && args[0] == "-o" && strings.HasPrefix(args[1], "ProxyCommand="):
		// args[2] is the ssh address the proxied connection is for, which the
		// proxy's URL already says.
		return proxyTarget(strings.TrimPrefix(args[1], "ProxyCommand="))
	}
	return ""
}

// sshTarget is the target of `ssh USER@HOST [-p PORT]`, or "" if there is none.
func sshTarget(userHost, port string) string {
	i := strings.LastIndex(userHost, "@")
	// ssh would also take an ssh:// URL here, which upterm doesn't print.
	if i < 0 || strings.Contains(userHost, "://") {
		return ""
	}
	user, host := userHost[:i], userHost[i+1:]
	// upterm prints an IPv6 address as ssh takes it, bare, and a target needs
	// its brackets.
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	target := user + "@" + host
	if port != "" {
		target += ":" + port
	}
	return targetOf(target, "ssh")
}

// proxyTarget is the target of a ProxyCommand that runs `upterm proxy URL`, or
// "" if it runs anything else. upterm doubles each % in the URL, because ssh
// reads %% as one before it hands the command to a shell, and quotes the URL
// for that shell. The command arrives here as ssh has it after the guest's own
// shell is done with it, so those two layers are undone in ssh's order.
func proxyTarget(command string) string {
	if strings.Contains(strings.ReplaceAll(command, "%%", ""), "%") {
		// A token ssh would expand to something else.
		return ""
	}
	words, ok := shellWords(strings.ReplaceAll(command, "%%", "%"))
	if !ok || len(words) != 3 || words[0] != "upterm" || words[1] != "proxy" {
		return ""
	}
	return targetOf(words[2], "ws", "wss")
}

// targetOf returns s if it parses as a target with one of schemes, and "" if
// it doesn't.
func targetOf(s string, schemes ...string) string {
	// ParseTarget would look for a command in text with a space in it.
	if strings.ContainsFunc(s, isSpaceOrControl) {
		return ""
	}
	t, err := ParseTarget(s)
	if err != nil || !slices.Contains(schemes, t.Scheme) {
		return ""
	}
	return s
}

// shellWords splits s into words as a POSIX shell would, for the quoting
// upterm writes: single quotes, and a backslash outside them, which is how a
// single quote inside them is written. It reports false for text a shell would
// expand or read as more than words, rather than reading it its own way.
func shellWords(s string) ([]string, bool) {
	var (
		words  []string
		word   strings.Builder
		inWord bool // an empty word, as in '', is still a word
		quoted bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quoted:
			if c == '\'' {
				quoted = false
			} else {
				word.WriteByte(c)
			}
		case c == '\'':
			quoted, inWord = true, true
		case c == '\\':
			if i+1 == len(s) {
				return nil, false
			}
			i++
			word.WriteByte(s[i])
			inWord = true
		case c == ' ':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case strings.IndexByte("\"$`;&|<>()*?[]{}~!#", c) >= 0:
			return nil, false
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		return nil, false
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, true
}

// SessionID is the part of User before its first colon.
func (t Target) SessionID() string {
	id, _, _ := strings.Cut(t.User, ":")
	return id
}

// Relay is Host as a person writes it: with the port dropped when it is the
// scheme's default, and an IPv6 literal still in its brackets.
func (t Target) Relay() string {
	host, port, err := net.SplitHostPort(t.Host)
	if err != nil || port != defaultPorts[t.Scheme] {
		return t.Host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// URL is the target as the relay dialers read it: the session ID is the
// userinfo's username and the node, if there is one, its password.
func (t Target) URL() *url.URL {
	u := &url.URL{Scheme: t.Scheme, Host: t.Host}
	if id, node, ok := strings.Cut(t.User, ":"); ok {
		u.User = url.UserPassword(id, node)
	} else {
		u.User = url.User(t.User)
	}
	return u
}
