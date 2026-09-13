package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Contains(t, err.Error(), "/alice.keys")
	assert.Contains(t, err.Error(), "/bob.keys")
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
