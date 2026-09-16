package command

import (
	"errors"
	"net/url"
)

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
	u, err := url.Parse(s)
	if err != nil {
		// A bad percent escape is the one reason worth naming: the fix is not
		// obvious from "not a valid URL", and a password is the usual cause.
		// The stdlib error itself stays out either way.
		var escErr url.EscapeError
		if errors.As(err, &escErr) {
			return nil, errors.New("invalid --proxy: invalid percent-encoding; write a literal % as %25, e.g. http://user:p%25ss@proxy.example.com:3128")
		}
		return nil, errors.New("invalid --proxy: not a valid URL, e.g. http://proxy.example.com:3128")
	}
	// websocket.Dialer only speaks CONNECT over plain HTTP, so accepting
	// https:// here would fail at dial time instead.
	if u.Scheme != "http" {
		return nil, errors.New("invalid --proxy: only http:// proxies are supported, e.g. http://proxy.example.com:3128")
	}
	if u.Hostname() == "" {
		return nil, errors.New("invalid --proxy: missing host, e.g. http://proxy.example.com:3128")
	}
	return u, nil
}
