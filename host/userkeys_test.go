package host

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordingRT captures the requests that reach the network boundary and
// returns a canned body, so a fetch can be exercised against a hostname that
// does not resolve (api.github.com) without touching the network.
type recordingRT struct {
	reqs []*http.Request
	body string
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.reqs = append(r.reqs, req.Clone(req.Context()))

	header := make(http.Header)
	header.Set("Content-Type", "application/json; charset=utf-8")

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     header,
		Request:    req,
	}, nil
}

func Test_fetchTransport(t *testing.T) {
	cases := []struct {
		name          string
		origin        string
		url           string
		setAuth       bool
		wantErrSubstr string
		wantAuth      bool
		wantRequests  int
	}{
		{
			name:         "credential reaches the intended origin",
			origin:       "api.github.com",
			url:          "https://api.github.com/users/alice/keys",
			setAuth:      true,
			wantAuth:     true,
			wantRequests: 1,
		},
		{
			name:         "credential reaches the intended origin on a non-default port",
			origin:       "ghe.corp.com:8443",
			url:          "https://ghe.corp.com:8443/api/v3/users/alice/keys",
			setAuth:      true,
			wantAuth:     true,
			wantRequests: 1,
		},
		{
			name:         "credential is stripped on a sibling subdomain",
			origin:       "ghe.corp.com",
			url:          "https://other.ghe.corp.com/api/v3/users/alice/keys",
			setAuth:      true,
			wantAuth:     false,
			wantRequests: 1,
		},
		{
			name:         "credential is stripped on an unrelated origin",
			origin:       "ghe.corp.com",
			url:          "https://evil.example.com/users/alice/keys",
			setAuth:      true,
			wantAuth:     false,
			wantRequests: 1,
		},
		{
			name:         "credential is stripped when only the port differs",
			origin:       "ghe.corp.com:8443",
			url:          "https://ghe.corp.com:9443/api/v3/users/alice/keys",
			setAuth:      true,
			wantAuth:     false,
			wantRequests: 1,
		},
		{
			name:          "plaintext is refused before contacting the destination",
			origin:        "git.corp.com",
			url:           "http://git.corp.com/alice.keys",
			wantErrSubstr: "refusing to fetch keys over http://",
			wantRequests:  0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recordingRT{}
			tr := &fetchTransport{origin: c.origin, base: rec, logger: testLogger()}

			req, err := http.NewRequest(http.MethodGet, c.url, nil)
			require.NoError(t, err)
			if c.setAuth {
				req.Header.Set("Authorization", "token secret")
			}

			resp, err := tr.RoundTrip(req)
			if c.wantErrSubstr != "" {
				assert.ErrorContains(t, err, c.wantErrSubstr)
			} else {
				require.NoError(t, err)
				_ = resp.Body.Close()
			}

			require.Len(t, rec.reqs, c.wantRequests)
			if c.wantRequests == 0 {
				return
			}
			if c.wantAuth {
				assert.Equal(t, "token secret", rec.reqs[0].Header.Get("Authorization"))
			} else {
				assert.Empty(t, rec.reqs[0].Header.Get("Authorization"))
			}
		})
	}
}

// tlsPool builds a root pool trusting every supplied test server.
func tlsPool(t *testing.T, servers ...*httptest.Server) http.RoundTripper {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}

func Test_fetchClient_refusesRedirectToPlaintext(t *testing.T) {
	var plaintextHits int
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plaintextHits++
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer plaintext.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plaintext.URL+"/alice.keys", http.StatusFound)
	}))
	defer secure.Close()

	client := newFetchClient("", tlsPool(t, secure), testLogger())
	_, err := client.Get(secure.URL + "/alice.keys")

	assert.ErrorContains(t, err, "refusing to fetch keys over http://")
	assert.Zero(t, plaintextHits, "rejection must precede contacting the plaintext destination")
}

func Test_fetchClient_capsRedirects(t *testing.T) {
	// hops counts how many redirects the handler has been asked to serve; it
	// stops redirecting after `limit` so we can test both sides of the cap.
	newChain := func(limit int) *httptest.Server {
		var server *httptest.Server
		var hops int
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hops < limit {
				hops++
				http.Redirect(w, r, server.URL+"/hop", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(testPublicKey))
		}))
		return server
	}

	t.Run("exactly five redirects succeed", func(t *testing.T) {
		server := newChain(5)
		defer server.Close()

		resp, err := newFetchClient("", tlsPool(t, server), testLogger()).Get(server.URL + "/alice.keys")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("a sixth redirect is refused", func(t *testing.T) {
		server := newChain(6)
		defer server.Close()

		_, err := newFetchClient("", tlsPool(t, server), testLogger()).Get(server.URL + "/alice.keys")
		assert.ErrorContains(t, err, "stopped after 5 redirects")
	})
}

func Test_fetchClient_followsCrossOriginRedirectAnonymously(t *testing.T) {
	var gotAuth string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/alice.keys", http.StatusFound)
	}))
	defer origin.Close()

	client := newFetchClient(strings.TrimPrefix(origin.URL, "https://"), tlsPool(t, origin, target), testLogger())

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/alice.keys", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "token secret")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, gotAuth, "cross-origin redirects must be followed anonymously")
}

func rawRef(t *testing.T, server *httptest.Server, path string) UserRef {
	t.Helper()
	ref, err := ParseUserRef(server.URL + path)
	require.NoError(t, err)
	return ref
}

func Test_Fetcher_genericPath(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantErrSubstr string
		wantKeys      int
	}{
		{name: "keys returned", status: 200, body: testPublicKey + "\n", wantKeys: 1},
		{name: "zero-length body is refused", status: 200, body: "", wantErrSubstr: "no public keys found"},
		{name: "whitespace body is refused", status: 200, body: "\n\n", wantErrSubstr: "ssh: no key found"},
		{name: "html body is refused", status: 200, body: "<html>Sign in</html>", wantErrSubstr: "ssh: no key found"},
		{name: "not found", status: 404, wantErrSubstr: "user not found on"},
		{name: "unauthorized", status: 401, wantErrSubstr: "requires authentication"},
		{name: "forbidden", status: 403, wantErrSubstr: "requires authentication"},
		{name: "server error", status: 500, wantErrSubstr: "HTTP 500"},
		{
			name:          "oversized body is rejected rather than truncated",
			status:        200,
			body:          strings.Repeat("x", maxKeysBody+1),
			wantErrSubstr: "exceeds",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer server.Close()

			f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
			aks, err := f.AuthorizedKeys(t.Context(), []UserRef{rawRef(t, server, "/alice")})

			if c.wantErrSubstr != "" {
				assert.ErrorContains(t, err, c.wantErrSubstr)
				assert.Nil(t, aks)
				return
			}
			require.NoError(t, err)
			require.Len(t, aks, 1)
			assert.Len(t, aks[0].PublicKeys, c.wantKeys)
		})
	}
}

func Test_Fetcher_commentIsTheResolvedIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer server.Close()

	ref := rawRef(t, server, "/alice")
	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}

	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)
	require.Len(t, aks, 1)
	assert.Equal(t, ref.Display(), aks[0].Comment)
}

func Test_Fetcher_reportsEveryFailureAtOnce(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	_, err := f.AuthorizedKeys(t.Context(), []UserRef{
		rawRef(t, server, "/alice"),
		rawRef(t, server, "/bob"),
	})

	require.Error(t, err)
	// Verify both failures are reported together. The error message contains
	// ref.Raw (the original token as the user wrote it) so they can grep their
	// config or command line. For raw URLs, this is the pre-.keys input.
	assert.Contains(t, err.Error(), "/alice")
	assert.Contains(t, err.Error(), "/bob")
}

func Test_Fetcher_dedup(t *testing.T) {
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer server.Close()

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	_, err := f.AuthorizedKeys(t.Context(), []UserRef{
		rawRef(t, server, "/team-a/alice"),
		rawRef(t, server, "/team-b/alice"),
		rawRef(t, server, "/team-a/alice"),
	})
	require.NoError(t, err)

	// Distinct raw URLs are distinct endpoints even when the trailing name
	// matches; only the exact repeat is deduplicated.
	assert.ElementsMatch(t, []string{"/team-a/alice.keys", "/team-b/alice.keys"}, paths)
}

func Test_Fetcher_dedupsIdenticalProviderRefs(t *testing.T) {
	// The raw-URL case above exercises dedupKey's URL branch only. A
	// provider reference takes the other branch, built from provider, resolved
	// host, user and credential mode.
	var hits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer server.Close()

	ref, err := ParseUserRef("gitea:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref, ref})
	require.NoError(t, err)

	require.Len(t, aks, 1)
	assert.Equal(t, 1, hits, "the same reference twice must be fetched once")
}

func Test_Fetcher_honorsContextCancellation(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(t.Context())
	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}

	done := make(chan error, 1)
	go func() {
		_, err := f.AuthorizedKeys(ctx, []UserRef{rawRef(t, server, "/alice")})
		done <- err
	}()

	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not honor context cancellation")
	}
}

func Test_dedupKey_separatesCredentialModes(t *testing.T) {
	pinGitHubHost(t, "ghe.corp.com")

	implicit, err := ParseUserRef("github:alice")
	require.NoError(t, err)
	explicit, err := ParseUserRef("github:alice@ghe.corp.com")
	require.NoError(t, err)

	// Same host, different credential policy: keying on the resolved reference
	// alone would let input order decide which policy applies.
	require.Equal(t, implicit.ResolveHost(), explicit.ResolveHost())
	assert.NotEqual(t, dedupKey(implicit), dedupKey(explicit))
}

func Test_githubUserKeys_usesTheAPIWithAHostScopedToken(t *testing.T) {
	var (
		gotPath string
		gotAuth string
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer server.Close()

	// GH_ENTERPRISE_TOKEN must never be used for an explicit @host reference.
	t.Setenv("GH_ENTERPRISE_TOKEN", "wrong-instance-token")

	host := strings.TrimPrefix(server.URL, "https://")
	pinHostScopedToken(t, "host-scoped-token")

	ref, err := ParseUserRef("github:alice@" + host)
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	require.Len(t, aks, 1)
	assert.Len(t, aks[0].PublicKeys, 1)
	assert.Equal(t, "/api/v3/users/alice/keys", gotPath)
	assert.Equal(t, "token host-scoped-token", gotAuth,
		"the host-scoped credential must be used, never GH_ENTERPRISE_TOKEN")
}

// pinHostScopedToken replaces credential resolution for the duration of a test.
func pinHostScopedToken(t *testing.T, token string) {
	t.Helper()
	restore := hostScopedTokenFunc
	hostScopedTokenFunc = func(context.Context, string) (string, error) { return token, nil }
	t.Cleanup(func() { hostScopedTokenFunc = restore })
}

func Test_githubUserKeys_propagatesCredentialLookupFailure(t *testing.T) {
	// A lookup that could not complete must fail the fetch, not silently
	// degrade to anonymous — that would report "could not check" as
	// "confirmed no credential".
	var serverHits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits++
	}))
	defer server.Close()

	restore := hostScopedTokenFunc
	hostScopedTokenFunc = func(ctx context.Context, hostname string) (string, error) {
		<-ctx.Done()
		return "", fmt.Errorf("credential lookup for %s did not complete: %w", hostname, ctx.Err())
	}
	t.Cleanup(func() { hostScopedTokenFunc = restore })

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}

	done := make(chan error, 1)
	go func() {
		_, err := f.AuthorizedKeys(ctx, []UserRef{ref})
		done <- err
	}()

	cancel()

	select {
	case err := <-done:
		assert.ErrorContains(t, err, "did not complete")
		assert.Zero(t, serverHits, "no request may go out after a failed credential lookup")
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked credential lookup did not honor cancellation")
	}
}

func shortCredentialTimeout(t *testing.T) {
	t.Helper()
	restore := credentialTimeout
	// 1s, not a tighter value: keyringToken applies credentialTimeout as a
	// deadline from the moment it is called, so it must cover the stub's own
	// process startup as well as the post-cancel WaitDelay. Writing a fresh
	// executable and running it measures ~270ms on macOS, which is why 200ms
	// killed the stub before it could touch its marker file and the test's
	// Eventually never fired.
	credentialTimeout = 1 * time.Second
	t.Cleanup(func() { credentialTimeout = restore })
}

func Test_keyringToken_honorsGHPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "fake-gh")
	require.NoError(t, os.WriteFile(stub, []byte("#!/bin/sh\necho keyring-token\n"), 0o755))

	// PATH deliberately excludes dir and contains no gh: go-gh checks GH_PATH
	// first, so searching PATH only would miss this binary entirely.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GH_PATH", stub)

	got, err := keyringToken(t.Context(), "ghe.corp.com")
	require.NoError(t, err)
	assert.Equal(t, "keyring-token", got)
}

func Test_keyringToken_boundsALookupWhoseDescendantHoldsThePipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub is POSIX-only")
	}

	// Resolve sleep to an absolute path *before* PATH is narrowed; the stub
	// runs with a PATH that cannot find it otherwise.
	sleepExe, err := exec.LookPath("sleep")
	require.NoError(t, err)

	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	stub := filepath.Join(dir, "fake-gh")

	// The backgrounded sleep inherits stdout, so killing the wrapper still
	// leaves a descendant holding the pipe. Without WaitDelay, Output blocks
	// until that grandchild exits.
	script := fmt.Sprintf("#!/bin/sh\n%s 60 &\ntouch %s\nexec %s 60\n", sleepExe, marker, sleepExe)
	require.NoError(t, os.WriteFile(stub, []byte(script), 0o755))

	t.Setenv("GH_PATH", stub)
	shortCredentialTimeout(t)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := keyringToken(ctx, "ghe.corp.com")
		done <- err
	}()

	// Cancel only once the stub has actually started, so the initial ctx.Err()
	// check cannot short-circuit the subprocess path being tested.
	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	cancel()

	select {
	case err := <-done:
		assert.ErrorContains(t, err, "did not complete")
	case <-time.After(5 * time.Second):
		t.Fatal("keyringToken outlived its context and WaitDelay")
	}
}

func Test_githubUserKeys_authenticatedRequestReachesTheAPIOrigin(t *testing.T) {
	// This must use github.com, not a GHES host. On GHES the website and the
	// API share an origin, so scoping the credential to the website host would
	// still pass. Only github.com separates them: the reference names
	// github.com while the request goes to api.github.com.
	pinGitHubHost(t, "github.com")
	t.Setenv("GH_TOKEN", "ambient-token")

	rec := &recordingRT{body: `[{"key":"` + testPublicKey + `"}]`}

	ref, err := ParseUserRef("github:alice")
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: rec}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)
	require.Len(t, aks, 1)

	require.Len(t, rec.reqs, 1)
	assert.Equal(t, "api.github.com", rec.reqs[0].URL.Host,
		"the request must target the API origin")
	assert.Equal(t, "token ambient-token", rec.reqs[0].Header.Get("Authorization"),
		"scoping the credential to the website host would strip it here")
}

func Test_githubUserKeys_stripsCredentialOnCrossOriginRedirect(t *testing.T) {
	var gotAuth string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer origin.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(origin.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, origin, target)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	assert.Empty(t, gotAuth, "the GitHub path must also follow cross-origin redirects anonymously")
}

// Test_githubUserKeys_capsRedirects pins client.CheckRedirect on the GitHub
// path. It is installed by a different route than the generic client's —
// api.NewHTTPClient returns a client with no redirect policy and ClientOptions
// cannot express one — so the other GitHub redirect tests all survive its
// removal: they assert properties that fetchTransport enforces per request,
// which is blind to the length of a chain. Without the line, Go's default
// 10-hop cap applies instead of ours.
func Test_githubUserKeys_capsRedirects(t *testing.T) {
	var hops int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hops < 6 {
			hops++
			http.Redirect(w, r, server.URL+"/hop", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer server.Close()

	// A credential must be in play, or the fetch falls back to the anonymous
	// .keys endpoint and never builds the go-gh client under test.
	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})

	assert.ErrorContains(t, err, "stopped after 5 redirects")
}

// Test_githubUserKeys_ignoresGHDebug pins LogIgnoreEnv: true.
//
// Without it, go-gh honors GH_DEBUG and installs httpretty, which dumps every
// request and response — the enterprise URL, the request headers and the whole
// key payload — to a hardcoded os.Stderr. go-gh reads os.Stderr inside
// api.NewHTTPClient (opts.Log = os.Stderr) rather than capturing it at init, so
// swapping the package-level variable before the fetch does capture it.
//
// The assertion that discriminates is the silence, not the absence of the
// token: httpretty's default sanitizer redacts an Authorization value to
// "token ████…", so a token-only assertion passes with the line removed. That
// redaction is an indirect dependency's default, one SkipSanitize away from
// changing, which is why the token is also asserted on directly below.
func Test_githubUserKeys_ignoresGHDebug(t *testing.T) {
	const token = "ghp_pinningLogIgnoreEnv0123456789"

	t.Setenv("GH_DEBUG", "api")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer server.Close()

	// A file, not an os.Pipe: httpretty's output can exceed a pipe's buffer,
	// and nothing would be draining it while the fetch is in flight.
	capture, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	defer func() { _ = capture.Close() }()

	realStderr := os.Stderr
	os.Stderr = capture
	t.Cleanup(func() { os.Stderr = realStderr })

	pinHostScopedToken(t, token)

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})

	// Restored before asserting, so a failure can still be reported.
	os.Stderr = realStderr

	require.NoError(t, err)
	require.Len(t, aks, 1)

	logged, err := os.ReadFile(capture.Name())
	require.NoError(t, err)
	assert.Empty(t, string(logged),
		"a key fetch must write nothing to stderr, whatever GH_DEBUG says")
	assert.NotContains(t, string(logged), token,
		"the credential must never reach stderr")
}

// generateTestPublicKey returns a second valid public key, so a test can tell
// the keys from one page apart from another's.
func generateTestPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func marshalKeys(keys []ssh.PublicKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
	}
	return out
}

func Test_githubUserKeys_followsLinkPagination(t *testing.T) {
	// per_page=100 alone only raises the ceiling. An account past that ceiling
	// would authorize a truncated set on the authenticated path while the
	// anonymous .keys fallback returns everyone — "can my colleague join?"
	// answered by whether a token happened to resolve.
	secondPageKey := generateTestPublicKey(t)

	var gotQueries []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQueries = append(gotQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Query().Get("page") == "" {
			next := server.URL + "/api/v3/users/alice/keys?per_page=100&page=2"
			w.Header().Set("Link", `<`+next+`>; rel="next", <`+next+`>; rel="last"`)
			_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"key":"` + secondPageKey + `"}]`))
	}))
	defer server.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	require.Len(t, aks, 1)
	assert.ElementsMatch(t, []string{testPublicKey, secondPageKey}, marshalKeys(aks[0].PublicKeys))
	assert.Equal(t, []string{"per_page=100", "per_page=100&page=2"}, gotQueries,
		"the next page must be requested exactly as advertised, and the chain must stop without one")
}

func Test_githubUserKeys_boundsThePageChain(t *testing.T) {
	// A server that always advertises another page would otherwise loop for as
	// long as it keeps answering.
	var hits int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/users/alice/keys?per_page=100&page=%d>; rel="next"`, server.URL, hits+1))
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer server.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})

	assert.ErrorContains(t, err, fmt.Sprintf("spans more than %d pages", maxKeyPages))
	assert.Equal(t, maxKeyPages, hits, "the cap must stop the chain rather than the server")
}

func Test_githubUserKeys_crossOriginNextPageIsAnonymous(t *testing.T) {
	// The next URL is whatever the server says, so it is subject to the same
	// rules as the first request: it is fetched through the same policed
	// client. Here the two servers share a hostname and differ only in port —
	// the case go-gh's isSameDomain waves through, so the credential is
	// attached and then stripped by fetchTransport's origin check.
	elsewhereKey := generateTestPublicKey(t)

	var (
		elsewhereHits int
		gotAuth       string
	)
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereHits++
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key":"` + elsewhereKey + `"}]`))
	}))
	defer elsewhere.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<`+elsewhere.URL+`/api/v3/users/alice/keys?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer origin.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(origin.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, origin, elsewhere)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	require.Len(t, aks, 1)
	require.Equal(t, 1, elsewhereHits, "the advertised page must actually be requested")
	assert.Empty(t, gotAuth, "a server-supplied next URL outside the origin must be fetched anonymously")
	assert.ElementsMatch(t, []string{testPublicKey, elsewhereKey}, marshalKeys(aks[0].PublicKeys))
}

func Test_githubUserKeys_refusesAPlaintextNextPage(t *testing.T) {
	var plaintextHits int
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plaintextHits++
	}))
	defer plaintext.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<`+plaintext.URL+`/keys?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer secure.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(secure.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, secure)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})

	assert.ErrorContains(t, err, "refusing to fetch keys over http://")
	assert.Zero(t, plaintextHits, "rejection must precede contacting the plaintext destination")
}

func Test_nextPageURL(t *testing.T) {
	cases := []struct {
		name string
		link string
		want string
	}{
		{name: "absent header", link: "", want: ""},
		{
			name: "next among several relations",
			link: `<https://api.github.com/user/keys?page=2>; rel="next", <https://api.github.com/user/keys?page=9>; rel="last"`,
			want: "https://api.github.com/user/keys?page=2",
		},
		{
			name: "prev only",
			link: `<https://api.github.com/user/keys?page=1>; rel="prev"`,
			want: "",
		},
		{
			name: "next last in the list",
			link: `<https://api.github.com/user/keys?page=1>; rel="first", <https://api.github.com/user/keys?page=3>; rel="next"`,
			want: "https://api.github.com/user/keys?page=3",
		},
		// Malformed means "no more pages": a listing that otherwise succeeded
		// should not fail over an unreadable header, and stopping early can
		// only deny access, never grant it.
		{name: "missing angle brackets", link: `https://api.github.com/x; rel="next"`, want: ""},
		{name: "unterminated url", link: `<https://api.github.com/x; rel="next"`, want: ""},
		{name: "relation without a url", link: `rel="next"`, want: ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, nextPageURL(c.link))
		})
	}
}

func Test_Fetcher_zeroValueLoggerDoesNotPanic(t *testing.T) {
	// Fetcher is exported, so a third-party caller can construct &Fetcher{}
	// with no Logger set. Exercise both call sites that log through it
	// (fetchTransport.RoundTrip's credential strip and redirectPolicy's
	// cross-origin hop) to confirm AuthorizedKeys defaults the logger rather
	// than panicking on the first nil *slog.Logger.Debug call.
	var gotAuth string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer target.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer origin.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(origin.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Transport: tlsPool(t, origin, target)}

	var aks []*AuthorizedKey
	require.NotPanics(t, func() {
		aks, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})
	})
	require.NoError(t, err)
	require.Len(t, aks, 1)
	assert.Empty(t, gotAuth, "the credential must still be stripped across the redirect")
}

func Test_githubUserKeys_refusesRedirectToPlaintext(t *testing.T) {
	var plaintextHits int
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plaintextHits++
	}))
	defer plaintext.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plaintext.URL+"/keys", http.StatusFound)
	}))
	defer secure.Close()

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(secure.URL, "https://"))
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, secure)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})

	assert.ErrorContains(t, err, "refusing to fetch keys over http://")
	assert.Zero(t, plaintextHits)
}

func Test_githubUserKeys_honorsContextCancellation(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	pinHostScopedToken(t, "tok")

	ref, err := ParseUserRef("github:alice@" + strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}

	done := make(chan error, 1)
	go func() {
		_, err := f.AuthorizedKeys(ctx, []UserRef{ref})
		done <- err
	}()

	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("GitHub fetch did not honor context cancellation")
	}
}

func Test_githubUserKeys_doesNotSendAPortlessCredentialToAnotherPort(t *testing.T) {
	// A credential stored for ghe.corp.com is stored for the GHES on 443.
	// ghe.corp.com:8443 is a different origin — possibly an unrelated service
	// on the same box — so that token must not be sent there.
	//
	// The lookup key is what decides it: fetchTransport compares against the
	// port-qualified origin and therefore considers :8443 intended, so a
	// port-less lookup hands the token straight over rather than stripping it.
	// Both directions matter: the second subtest stops a future "fix" that
	// simply never authenticates against a port-qualified host.
	cases := []struct {
		name     string
		storedAt string
		wantAuth string
	}{
		{
			name:     "stored for the port-less host is not sent to another port",
			storedAt: "ghe.corp.com",
			wantAuth: "",
		},
		{
			name:     "stored for the exact authority is sent",
			storedAt: "ghe.corp.com:8443",
			wantAuth: "token scoped-token",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			restore := hostScopedTokenFunc
			hostScopedTokenFunc = func(_ context.Context, hostname string) (string, error) {
				if hostname == c.storedAt {
					return "scoped-token", nil
				}
				return "", nil
			}
			t.Cleanup(func() { hostScopedTokenFunc = restore })

			ref, err := ParseUserRef("github:alice@ghe.corp.com:8443")
			require.NoError(t, err)

			rec := &recordingRT{body: `[{"key":"` + testPublicKey + `"}]`}
			f := &Fetcher{Logger: testLogger(), Transport: rec}
			_, _ = f.AuthorizedKeys(t.Context(), []UserRef{ref})

			require.Len(t, rec.reqs, 1)
			assert.Equal(t, c.wantAuth, rec.reqs[0].Header.Get("Authorization"))
		})
	}
}

func Test_githubUserKeys_authenticatesAgainstABracketedIPv6Host(t *testing.T) {
	// A GHES reachable only by IPv6 literal. go-gh attaches the token by
	// comparing ClientOptions.Host against req.URL.Hostname(), which strips the
	// brackets, so a bracketed clientHost matches nothing and the request goes
	// out anonymously — a private instance then answers 401 and the reference
	// looks broken rather than misconfigured.
	for _, ref := range []string{"github:alice@[2001:db8::1]", "github:alice@[2001:db8::1]:8443"} {
		t.Run(ref, func(t *testing.T) {
			pinHostScopedToken(t, "v6-token")

			parsed, err := ParseUserRef(ref)
			require.NoError(t, err)

			rec := &recordingRT{body: `[{"key":"` + testPublicKey + `"}]`}
			f := &Fetcher{Logger: testLogger(), Transport: rec}
			_, err = f.AuthorizedKeys(t.Context(), []UserRef{parsed})
			require.NoError(t, err)

			require.Len(t, rec.reqs, 1)
			assert.Equal(t, "token v6-token", rec.reqs[0].Header.Get("Authorization"),
				"the token must reach an IPv6 GHES, bracketed authority or not")
		})
	}
}

func Test_hostScopedToken_readsHostScopedStorageOnly(t *testing.T) {
	// GH_ENTERPRISE_TOKEN applies to every enterprise host, so honoring it
	// would send one instance's token to another.
	t.Setenv("GH_ENTERPRISE_TOKEN", "wrong-instance-token")
	t.Setenv("GH_PATH", "/nonexistent/gh")
	t.Setenv("PATH", t.TempDir())

	restore := config.Read
	config.Read = func(*config.Config) (*config.Config, error) {
		return config.ReadFromString("hosts:\n  ghe.corp.com:\n    oauth_token: right-token\n"), nil
	}
	t.Cleanup(func() { config.Read = restore })

	got, err := hostScopedToken(t.Context(), "ghe.corp.com")
	require.NoError(t, err)
	assert.Equal(t, "right-token", got)

	got, err = hostScopedToken(t.Context(), "other.corp.com")
	require.NoError(t, err)
	assert.Empty(t, got,
		"a host with no stored credential must not inherit the ambient enterprise token")
}

func Test_githubUserKeys_fallsBackToAnonymousWithoutACredential(t *testing.T) {
	var gotPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(testPublicKey))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	pinHostScopedToken(t, "")

	ref, err := ParseUserRef("github:alice@" + host)
	require.NoError(t, err)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	aks, err := f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	require.Len(t, aks, 1)
	assert.Equal(t, "/alice.keys", gotPath, "no credential means the anonymous .keys endpoint")
}

func Test_githubUserKeys_defaultModeUsesAmbientCredentials(t *testing.T) {
	// A reference with no explicit @host keeps go-gh's full resolution, which
	// is what preserves the previously undocumented GH_HOST behavior.
	var gotAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[{"key":"` + testPublicKey + `"}]`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	pinGitHubHost(t, host)
	t.Setenv("GH_ENTERPRISE_TOKEN", "ambient-token")

	ref, err := ParseUserRef("github:alice")
	require.NoError(t, err)
	require.Equal(t, CredentialDefault, ref.Mode)

	f := &Fetcher{Logger: testLogger(), Transport: tlsPool(t, server)}
	_, err = f.AuthorizedKeys(t.Context(), []UserRef{ref})
	require.NoError(t, err)

	assert.Equal(t, "token ambient-token", gotAuth)
}
