package command

import (
	"fmt"
	"net/url"
)

// parseProxyURL parses the --proxy flag. It returns nil when the flag is
// empty, leaving the proxy to the environment for ws and wss servers.
func parseProxyURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid --proxy %q: %w", s, err)
	}
	// websocket.Dialer only speaks CONNECT over plain HTTP, so accepting
	// https:// here would fail at dial time instead.
	if u.Scheme != "http" {
		return nil, fmt.Errorf("invalid --proxy %q: only http:// proxies are supported", s)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid --proxy %q: missing host", s)
	}
	return u, nil
}
