package host

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// fetchTimeout bounds each key-fetching request.
	fetchTimeout = 5 * time.Second
	// maxRedirects bounds a single fetch's redirect chain.
	maxRedirects = 5
	// maxKeysBody bounds how much of a response we will parse as keys.
	maxKeysBody = 1 << 20
)

// fetchTransport enforces two invariants on every request, including every
// redirect hop:
//
//  1. The scheme must be https. Rejecting only the initial URL is not enough:
//     Go's http.Client follows redirects across a scheme downgrade, and the
//     first hop's TLS is what stops an on-path attacker from forging the
//     response. Once a hop lands on http://, keys can be injected freely.
//
//  2. Authorization may only reach the exact intended origin. go-gh attaches
//     its token using isSameDomain, which also matches *subdomains*, so a
//     redirect from ghe.corp.com to other.ghe.corp.com would otherwise receive
//     the credential.
//
// go-gh installs ClientOptions.Transport as the innermost round tripper and
// wraps its own header round tripper outermost, so this sees the credential
// go-gh just attached. Requests outside the origin are still performed —
// anonymously.
type fetchTransport struct {
	origin string // host[:port] allowed to receive credentials; "" means none
	base   http.RoundTripper
	logger *slog.Logger
}

func (t *fetchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return nil, fmt.Errorf("refusing to fetch keys over %s://: keys fetched over plaintext can be forged by anyone on the network path. Use https, or save the keys to a file and pass --authorized-keys", req.URL.Scheme)
	}

	if req.Header.Get("Authorization") != "" && !strings.EqualFold(req.URL.Host, t.origin) {
		// RoundTrippers must not mutate the request they are given.
		req = req.Clone(req.Context())
		req.Header.Del("Authorization")
		t.logger.Debug("stripped credential outside the intended origin",
			"origin", t.origin, "host", req.URL.Host)
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// redirectPolicy caps the redirect chain and logs cross-origin hops. The hop
// cap cannot live in the transport, which has no view of the chain.
func redirectPolicy(logger *slog.Logger) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// via holds the requests already made, starting with the initial one,
		// so on the Nth redirect len(via) == N. ">" allows exactly
		// maxRedirects hops; ">=" would allow only maxRedirects-1.
		if len(via) > maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if prev := via[len(via)-1]; !strings.EqualFold(req.URL.Host, prev.URL.Host) {
			logger.Debug("following cross-origin redirect",
				"from", prev.URL.Host, "to", req.URL.Host)
		}
		return nil
	}
}

// newFetchClient builds the client used for anonymous .keys fetches. origin is
// the only host permitted to receive an Authorization header; pass "" when no
// credential is in play.
func newFetchClient(origin string, base http.RoundTripper, logger *slog.Logger) *http.Client {
	return &http.Client{
		Timeout:       fetchTimeout,
		Transport:     &fetchTransport{origin: origin, base: base, logger: logger},
		CheckRedirect: redirectPolicy(logger),
	}
}
