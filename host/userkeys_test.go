package host

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
