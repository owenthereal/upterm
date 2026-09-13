package host

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
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

// Fetcher resolves user references to authorized keys.
type Fetcher struct {
	Logger *slog.Logger
	// Transport, when set, is the base round tripper for every request. Tests
	// use it to trust httptest certificates; production leaves it nil.
	Transport http.RoundTripper
}

// AuthorizedKeysFromUserRefs resolves refs using a default Fetcher.
func AuthorizedKeysFromUserRefs(ctx context.Context, refs []UserRef, logger *slog.Logger) ([]*AuthorizedKey, error) {
	return (&Fetcher{Logger: logger}).AuthorizedKeys(ctx, refs)
}

// AuthorizedKeys fetches every reference, reporting all failures together.
// Any failure fails the whole call: continuing with a partial set can, in the
// limit, degrade "only alice may join" into "anyone may join".
func (f *Fetcher) AuthorizedKeys(ctx context.Context, refs []UserRef) ([]*AuthorizedKey, error) {
	var (
		result []*AuthorizedKey
		errs   error
		seen   = make(map[string]bool)
	)

	for _, ref := range refs {
		key := dedupKey(ref)
		if seen[key] {
			continue
		}
		seen[key] = true

		ak, err := f.fetch(ctx, ref)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("%s: %w", ref.KeysURL(), err))
			continue
		}
		result = append(result, ak)
	}

	if errs != nil {
		return nil, errs
	}
	return result, nil
}

func (f *Fetcher) fetch(ctx context.Context, ref UserRef) (*AuthorizedKey, error) {
	if ref.Provider == "github" {
		return f.githubUserKeys(ctx, ref)
	}
	return f.genericUserKeys(ctx, ref)
}

// genericUserKeys reads the {base}/{user}.keys endpoint every supported forge
// serves, anonymously.
func (f *Fetcher) genericUserKeys(ctx context.Context, ref UserRef) (*AuthorizedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.KeysURL(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := newFetchClient("", f.Transport, f.Logger).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkStatus(resp, ref); err != nil {
		return nil, err
	}

	body, err := readKeysBody(resp.Body, ref)
	if err != nil {
		return nil, err
	}

	return parseAuthorizedKeys(body, ref.Display())
}

// readKeysBody reads at most maxKeysBody bytes, rejecting anything larger
// rather than truncating. A silently truncated body can still parse into a
// shorter-but-valid key set, quietly dropping people who should be authorized.
func readKeysBody(r io.Reader, ref UserRef) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxKeysBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxKeysBody {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", ref.ResolveHost(), maxKeysBody)
	}
	return body, nil
}

// dedupKey identifies a fetch. Raw URLs take their own branch: they have no
// provider, user or credential mode, so the tuple below would collapse
// distinct endpoints such as /team-a/alice.keys and /team-b/alice.keys.
// Credential mode is part of the key because github:alice under GH_HOST and
// github:alice@thathost resolve to the same host under different policies.
func dedupKey(ref UserRef) string {
	if ref.URL != "" {
		return "url\x00" + ref.KeysURL()
	}
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d",
		ref.Provider, ref.ResolveHost(), ref.User, ref.Mode)
}

func checkStatus(resp *http.Response, ref UserRef) error {
	host := ref.ResolveHost()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("user not found on %s", host)
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		if ref.Provider == "github" {
			return fmt.Errorf("%s requires authentication; run: gh auth login --hostname %s", host, host)
		}
		return fmt.Errorf("%s requires authentication (HTTP %d)", host, resp.StatusCode)
	default:
		return fmt.Errorf("unexpected response from %s: HTTP %d", host, resp.StatusCode)
	}
}

// githubUserKeys is implemented in Task 5.
func (f *Fetcher) githubUserKeys(ctx context.Context, ref UserRef) (*AuthorizedKey, error) {
	return f.genericUserKeys(ctx, ref)
}
