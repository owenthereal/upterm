package command

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// proxyError builds a --proxy rejection.
//
// Every one of them carries where the value might have come from. Because the
// value itself is withheld, a bad one supplied through UPTERM_PROXY or the
// config file would otherwise report neither its content nor its origin —
// where every other flag gets both from bindSetError, which never fires for
// --proxy because pflag's Set cannot fail on a string.
func proxyError(reason string) error {
	return errors.New("invalid --proxy: " + reason +
		". The value is withheld because it may carry credentials; it can come " +
		"from --proxy, UPTERM_PROXY, or the proxy key in the config file")
}

// proxyFromEnvironment is how the environment is consulted. It is a variable
// because the real one answers from a sync.Once populated at its first call in
// the process, which a test cannot then influence with t.Setenv.
//
// Production keeps the caching deliberately: gorilla's DefaultDialer.Proxy is
// this same function, so sharing the cache is what guarantees this agrees with
// the dial it is predicting. A CLI's environment does not change mid-run.
var proxyFromEnvironment = http.ProxyFromEnvironment

// connectionIsProxied reports whether the SSH transport will pass through an
// HTTP proxy. That is what makes the peer address x/crypto hands the host-key
// prompt the proxy's rather than the server's.
//
// --proxy always does. ws:// and wss:// additionally fall back to the proxy
// environment, so the question has to be asked the way gorilla asks it: on the
// http/https form of the URL, which is what decides between HTTP_PROXY and
// HTTPS_PROXY, and through the same function, which is what applies NO_PROXY.
// ssh:// never consults the environment, the same as OpenSSH.
func connectionIsProxied(server string, proxyURL *url.URL) bool {
	if proxyURL != nil {
		return true
	}
	u, err := url.Parse(server)
	if err != nil {
		return false
	}
	probe := *u
	switch u.Scheme {
	case "ws":
		probe.Scheme = "http"
	case "wss":
		probe.Scheme = "https"
	default:
		return false
	}
	envProxy, err := proxyFromEnvironment(&http.Request{URL: &probe})
	return err == nil && envProxy != nil
}

// parseProxyURL parses the --proxy flag. It returns nil when the flag is
// empty, leaving the proxy to the environment for ws and wss servers.
//
// Errors never quote the value: it may carry credentials, and
// url.URL.Redacted does not hide them in every form (e.g. "user:pass@host").
// That rules out reporting url.Parse's error as well. Unwrapping the
// *url.Error drops the quoted whole input, but the error underneath quotes the
// offending *fragment*, and for a password containing "/", "?", "#" or a stray
// "%" that fragment is the password:
//
//	http://user:pa/ss@proxy.example.com:3128   ->  invalid port ":pa" after host
//	http://user:50%off@proxy.example.com:3128  ->  invalid URL escape "%of"
//
// Cobra prints flag errors to stderr, where log masking has only the whole
// secret to match on and a fragment slips through.
func parseProxyURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	// Checked before parsing, because url.Parse tolerates "host:port" as
	// scheme:opaque only when the host is a valid scheme token. That splits one
	// mistake in two: "proxy.example.com:3128" reaches the scheme check below,
	// while "10.0.0.1:3128" and "[::1]:3128" — the most common way a proxy is
	// written down — fail to parse at all and earn a vaguer answer. A missing
	// scheme is a missing scheme either way.
	if !strings.Contains(s, "://") {
		return nil, proxyError("only http:// proxies are supported, e.g. http://proxy.example.com:3128")
	}
	u, err := url.Parse(s)
	if err != nil {
		// A bad percent escape is the one reason worth naming: the fix is not
		// obvious from "not a valid URL", and a password is the usual cause.
		// The stdlib error itself stays out either way.
		var escErr url.EscapeError
		if errors.As(err, &escErr) {
			return nil, proxyError("invalid percent-encoding; write a literal % as %25, e.g. http://user:p%25ss@proxy.example.com:3128")
		}
		return nil, proxyError("not a valid URL, e.g. http://proxy.example.com:3128")
	}
	// upterm's CONNECT dialer talks to the proxy in the clear: it never wraps
	// that connection in TLS, so an https:// proxy would fail at dial time.
	// Supporting one is a separate change, not an inherited limitation.
	if u.Scheme != "http" {
		return nil, proxyError("only http:// proxies are supported, e.g. http://proxy.example.com:3128")
	}
	if u.Hostname() == "" {
		return nil, proxyError("missing host, e.g. http://proxy.example.com:3128")
	}
	// Default the port once, here, so every dial path agrees on what
	// "http://proxy.example.com" means, and mirroring what --server already
	// does for portless ws:// and wss:// URLs. "http://proxy.example.com:" also
	// parses, with an empty port, and previously reached the dialer intact to
	// be resolved as port 0.
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "80")
	}
	return u, nil
}
