package command

import (
	"errors"
	"fmt"
	"net/url"
)

// parseProxyURL parses the --proxy flag. It returns nil when the flag is
// empty, leaving the proxy to the environment for ws and wss servers.
// Errors never quote the value: it may carry credentials, and
// url.URL.Redacted does not hide them in every form (e.g. "user:pass@host").
func parseProxyURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		// *url.Error quotes the raw input; keep only the underlying reason.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("invalid --proxy: %w", err)
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
