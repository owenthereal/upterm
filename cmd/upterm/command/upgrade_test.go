package command

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ggh "github.com/google/go-github/v48/github"
	"github.com/stretchr/testify/require"
	"github.com/tj/go-update"
)

// withGitHub points the GitHub client at base for the rest of the test.
func withGitHub(t *testing.T, base string) {
	t.Helper()

	u, err := url.Parse(base + "/")
	require.NoError(t, err)

	orig := githubClient
	t.Cleanup(func() { githubClient = orig })
	githubClient = func() *ggh.Client {
		c := ggh.NewClient(nil)
		c.BaseURL = u
		return c
	}
}

func TestGetReleaseOfflineIsAnErrorNotAPanic(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // connection refused from here on
	withGitHub(t, srv.URL)
	_, err := (&store{ctx: context.Background(), Owner: "o", Repo: "r"}).GetRelease("0.37.0")
	require.ErrorContains(t, err, "can't reach GitHub to look up v0.37.0")
}

func TestGetReleaseNotFoundStaysNotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	withGitHub(t, srv.URL)
	_, err := (&store{ctx: context.Background(), Owner: "o", Repo: "r"}).GetRelease("9.9.9")
	require.ErrorIs(t, err, update.ErrNotFound)
}

func TestDownloadReportsAnHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	path, err := downloadAsset(context.Background(), srv.Client(), srv.URL+"/upterm_linux_amd64.tar.gz", nil)
	require.ErrorContains(t, err, "500")
	require.Empty(t, path)
}
