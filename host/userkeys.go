package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/cli/go-gh/v2/pkg/config"
	"github.com/hashicorp/go-multierror"
)

const (
	// fetchTimeout bounds each key-fetching request.
	fetchTimeout = 5 * time.Second
	// maxRedirects bounds a single fetch's redirect chain.
	maxRedirects = 5
	// maxKeysBody bounds how much of a response we will parse as keys. On the
	// paginated GitHub path it bounds the sum of every page, so a hostile
	// Link: rel="next" chain cannot make us read unboundedly.
	maxKeysBody = 1 << 20
	// maxKeyPages bounds how many Link: rel="next" hops one GitHub key listing
	// may take. At per_page=100 that is 1000 keys, far past any real account.
	maxKeyPages = 10
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
	// Fetcher is exported, so a third-party caller can construct &Fetcher{}
	// directly. fetchTransport.RoundTrip and redirectPolicy call logger.Debug
	// with no nil guard (unlike base, which is nil-checked), so every
	// downstream construction needs a real logger. The default is a local
	// rather than an assignment to f.Logger: a Fetcher shared between
	// goroutines would otherwise be written to while another fetch reads it.
	logger := f.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

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

		ak, err := f.fetch(ctx, logger, ref)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("%s: %w", ref.Raw, err))
			continue
		}
		result = append(result, ak)
	}

	if errs != nil {
		return nil, errs
	}
	return result, nil
}

func (f *Fetcher) fetch(ctx context.Context, logger *slog.Logger, ref UserRef) (*AuthorizedKey, error) {
	if ref.Provider == "github" {
		return f.githubUserKeys(ctx, logger, ref)
	}
	return f.genericUserKeys(ctx, logger, ref)
}

// genericUserKeys reads the {base}/{user}.keys endpoint every supported forge
// serves, anonymously.
func (f *Fetcher) genericUserKeys(ctx context.Context, logger *slog.Logger, ref UserRef) (*AuthorizedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.KeysURL(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := newFetchClient("", f.Transport, logger).Do(req)
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

// credentialTimeout bounds credential resolution, which may shell out to `gh`
// and touch a system keyring that can block on a locked keychain. It is a
// variable so tests can shrink it.
var credentialTimeout = 5 * time.Second

// hostScopedTokenFunc is a variable so tests can pin credential resolution.
var hostScopedTokenFunc = hostScopedToken

// hostScopedToken returns a token stored specifically for hostname, ignoring
// GH_ENTERPRISE_TOKEN and GITHUB_ENTERPRISE_TOKEN. Those variables are not
// host-scoped: go-gh returns them for *any* non-github.com host, so honoring
// them would send one enterprise instance's token to another.
func hostScopedToken(ctx context.Context, hostname string) (string, error) {
	normalized := auth.NormalizeHostname(hostname)

	if cfg, err := config.Read(nil); err == nil {
		if token, err := cfg.Get([]string{"hosts", normalized, "oauth_token"}); err == nil && token != "" {
			return token, nil
		}
	}

	return keyringToken(ctx, normalized)
}

// keyringToken shells out to `gh auth token`, bounded and cancellable.
//
// A missing `gh` or a non-zero exit means "no credential stored" — an ordinary
// answer. A context error means the lookup could not be completed, which must
// not be reported as absence: silently fetching anonymously would treat "could
// not check" as "confirmed none".
func keyringToken(ctx context.Context, hostname string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("credential lookup for %s did not complete: %w", hostname, err)
	}

	// Match go-gh's executable selection: GH_PATH wins over PATH. Searching
	// PATH only would invoke a different binary than `gh` itself would, or fall
	// back to anonymous despite working keyring credentials.
	ghExe := os.Getenv("GH_PATH")
	if ghExe == "" {
		var err error
		ghExe, err = exec.LookPath("gh")
		if err != nil {
			return "", nil
		}
	}

	// A keyring lookup can block indefinitely on a locked keychain, which would
	// otherwise outlast the HTTP client's timeout and ignore cancellation.
	ctx, cancel := context.WithTimeout(ctx, credentialTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, ghExe, "auth", "token", "--secure-storage", "--hostname", hostname)
	// Killing the process is not sufficient. If a descendant inherited the
	// output pipes, Output blocks until they close, which a surviving
	// grandchild can defer indefinitely. WaitDelay bounds that wait and makes
	// Output return exec.ErrWaitDelay instead of hanging.
	cmd.WaitDelay = credentialTimeout

	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("credential lookup for %s did not complete: %w", hostname, ctxErr)
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			return "", fmt.Errorf("credential lookup for %s did not complete: %w", hostname, err)
		}
		// An ordinary non-zero exit means no credential is stored.
		return "", nil
	}
	return strings.TrimSpace(string(out)), nil
}

// resolveToken picks the credential for ref.
//
// The default branch deliberately does not call auth.TokenForHost: its final
// step shells out to `gh` with no context we can cancel, so a hung subprocess
// would outlive the caller. auth.TokenFromEnvOrConfig covers the same
// environment-then-config precedence without spawning anything, and the
// keyring step is then performed by our own cancellable implementation.
func resolveToken(ctx context.Context, ref UserRef, hostname string) (string, error) {
	switch ref.Mode {
	case CredentialHostScoped:
		return hostScopedTokenFunc(ctx, hostname)
	case CredentialDefault:
		if token, _ := auth.TokenFromEnvOrConfig(hostname); token != "" {
			return token, nil
		}
		return keyringToken(ctx, hostname)
	default:
		return "", nil
	}
}

// githubUserKeys reads a user's keys from the GitHub REST API, which works on
// instances whose web UI requires a login. Without a credential it falls back
// to the anonymous .keys endpoint.
//
// It uses api.NewHTTPClient rather than api.RESTClient because the redirect
// cap must live in CheckRedirect, which ClientOptions does not expose and
// RESTClient keeps unexported. That means building the API URL here, which is
// also what makes non-default ports work.
func (f *Fetcher) githubUserKeys(ctx context.Context, logger *slog.Logger, ref UserRef) (*AuthorizedKey, error) {
	apiURL, clientHost, origin, err := githubClientConfig(ref)
	if err != nil {
		return nil, err
	}

	// Resolve credentials under the full authority, port included. The origin
	// fetchTransport lets a token reach is port-qualified, so it treats
	// ghe.corp.com:8443 as intended and does not strip there. Looking the
	// credential up under a port-less key would therefore hand a token stored
	// for the GHES on ghe.corp.com to whatever answers on :8443.
	authority := ref.ResolveHost()

	token, err := resolveToken(ctx, ref, authority)
	if err != nil {
		return nil, err
	}
	if token == "" {
		if ref.Mode == CredentialHostScoped {
			logger.Warn("no credential stored for host; fetching keys anonymously",
				"host", authority, "fix", "gh auth login --hostname "+authority)
		}
		return f.genericUserKeys(ctx, logger, ref)
	}

	// clientHost is the *normalized* hostname with no port. go-gh matches it
	// against the port-less req.URL.Hostname(), so passing host:port — or an
	// unnormalized alias like foo.github.com, whose requests go to
	// api.github.com — silently drops the token.
	client, err := api.NewHTTPClient(api.ClientOptions{
		Host:      clientHost,
		AuthToken: token,
		Timeout:   fetchTimeout,
		Transport: &fetchTransport{origin: origin, base: f.Transport, logger: logger},
		// go-gh otherwise respects GH_DEBUG and installs httpretty with
		// RequestHeader/ResponseBody: true, which dumps the instance URL, the
		// request headers and the whole key payload to a hardcoded os.Stderr —
		// onto the terminal, or into a CI build log, on any machine where that
		// variable happens to be exported. httpretty's default sanitizer
		// redacts the Authorization *value* (so the token itself survives
		// today), but that is an indirect dependency's default rather than
		// something this package should depend on, and GH_DEBUG is the gh CLI's
		// switch, not upterm's.
		LogIgnoreEnv: true,
	})
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = redirectPolicy(logger)

	// Every page goes through this one client, so each request is policed by
	// the same fetchTransport (https-only, credential confined to origin) and
	// the same redirect cap as the first. A next URL is server-supplied, so
	// building a second client for it would be how a cross-origin next hop
	// escapes those rules.
	var (
		lines []string
		total int
	)
	for pageURL, page := apiURL, 1; pageURL != ""; page++ {
		if page > maxKeyPages {
			return nil, fmt.Errorf("key listing from %s spans more than %d pages", ref.ResolveHost(), maxKeyPages)
		}

		body, next, err := readKeyPage(ctx, client, ref, pageURL)
		if err != nil {
			return nil, err
		}

		// readKeyPage bounds each page; this bounds the chain as a whole.
		total += len(body)
		if total > maxKeysBody {
			return nil, fmt.Errorf("key listing from %s exceeds %d bytes", ref.ResolveHost(), maxKeysBody)
		}

		var keys []struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(body, &keys); err != nil {
			return nil, fmt.Errorf("error decoding keys from %s: %w", ref.ResolveHost(), err)
		}
		for _, k := range keys {
			lines = append(lines, k.Key)
		}

		pageURL = next
	}

	return parseAuthorizedKeys([]byte(strings.Join(lines, "\n")), ref.Display())
}

// readKeyPage fetches one page of a GitHub key listing and reports the next
// page's URL, if the response advertised one.
func readKeyPage(ctx context.Context, client *http.Client, ref UserRef, pageURL string) ([]byte, string, error) {
	// A fresh request per page, built with the context, so cancellation and the
	// client's per-request timeout still apply to page 2 and beyond.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkStatus(resp, ref); err != nil {
		return nil, "", err
	}

	body, err := readKeysBody(resp.Body, ref)
	if err != nil {
		return nil, "", err
	}

	return body, nextPageURL(resp.Header.Get("Link")), nil
}

// nextPageURL extracts the rel="next" target from a Link header.
//
// Absent or malformed means "no more pages" rather than an error: a listing
// that otherwise succeeded should not fail over a header we could not read.
// What keeps that safe is that truncation can only deny access, and that a
// next URL we *do* follow is still subject to every rule the first request
// was — it is requested through the same policed client.
func nextPageURL(link string) string {
	for _, segment := range strings.Split(link, ",") {
		if !strings.Contains(segment, `rel="next"`) {
			continue
		}
		start := strings.Index(segment, "<")
		end := strings.Index(segment, ">")
		if start < 0 || end < start {
			continue
		}
		return strings.TrimSpace(segment[start+1 : end])
	}
	return ""
}
