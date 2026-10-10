package join

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotATarget is what ParseTarget's errors wrap: the text names no session to
// join.
var ErrNotATarget = errors.New("not a join target")

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
// An IPv6 literal must be bracketed, as it is in a URL. The error wraps
// ErrNotATarget.
func ParseTarget(s string) (Target, error) {
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

func notATarget(in, why string) error {
	return fmt.Errorf("%w %q: %s", ErrNotATarget, in, why)
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
