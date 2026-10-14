package command

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggh "github.com/google/go-github/v48/github"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
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
	require.EqualError(t, err, "downloading upterm_linux_amd64.tar.gz: 500 Internal Server Error")
	require.Empty(t, path)
}

// upgrade's lookups fail before anything is downloaded or installed, and the
// message it returns is the one the user reads.
func TestUpgradeReportsWhyItStopped(t *testing.T) {
	// A release with no archive for this system: uptermd's and the
	// checksums, not upterm's.
	const noArchive = `{"tag_name": "v0.38.0", "assets": [
		{"name": "checksums.txt", "browser_download_url": "%[1]s/download/checksums.txt"},
		{"name": "uptermd_linux_amd64.tar.gz", "browser_download_url": "%[1]s/download/uptermd_linux_amd64.tar.gz"}]}`

	offline := httptest.NewServer(http.NotFoundHandler())
	offline.Close() // connection refused from here on

	var github *httptest.Server
	github = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/owenthereal/upterm/releases/tags/v0.38.0",
			r.URL.Path == "/repos/owenthereal/upterm/releases/latest":
			_, _ = fmt.Fprintf(w, noArchive, github.URL)
		case strings.HasPrefix(r.URL.Path, "/download/"):
			t.Errorf("upgrade downloaded %s", r.URL.Path)
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)

	noArchiveWant := fmt.Sprintf("release v0.38.0 has no upterm archive for this system (%s)", currentPlatform().assetName())

	const rateLimited = `{"message":"API rate limit exceeded for 1.2.3.4."}`

	for _, tc := range []struct {
		name   string
		base   string
		args   []string
		want   string
		prefix bool   // want is the start of the message, not all of it
		not    string // the message doesn't contain this
	}{
		{"offline, pinned", offline.URL, []string{"0.37.0"}, "can't reach GitHub to look up v0.37.0: ", true, ""},
		{"offline, latest", offline.URL, nil, "can't reach GitHub to look up the latest release: ", true, ""},
		// GitHub answered with an error status: it was reached.
		{"rate limited, pinned", githubAnswering(t, http.StatusForbidden, rateLimited), []string{"0.37.0"}, "GitHub returned an error for v0.37.0: ", true, "can't reach"},
		{"server error, latest", githubAnswering(t, http.StatusInternalServerError, `{"message":"Server Error"}`), nil, "GitHub returned an error for the latest release: ", true, "can't reach"},
		{"no latest release", githubAnswering(t, http.StatusNotFound, `{"message":"Not Found"}`), nil, "GitHub returned an error for the latest release: ", true, "can't reach"},
		// An answer that can't be read is not an error status.
		{"unreadable answer, pinned", githubAnswering(t, http.StatusOK, "not json"), []string{"0.37.0"}, "can't reach GitHub to look up v0.37.0: ", true, ""},
		{"unreadable answer, latest", githubAnswering(t, http.StatusOK, "not json"), nil, "can't reach GitHub to look up the latest release: ", true, ""},
		{"unknown version", github.URL, []string{"9.9.9"}, "release v9.9.9 not found", false, ""},
		{"unknown version typed with a v", github.URL, []string{"v9.9.9"}, "release v9.9.9 not found", false, ""},
		{"pinned release without our archive", github.URL, []string{"0.38.0"}, noArchiveWant, false, ""},
		{"latest release without our archive", github.URL, nil, noArchiveWant, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGitHub(t, tc.base)
			quietStdout(t)
			// Install would replace whatever upterm is on PATH; it must
			// not be reached, and could not find one if it were.
			t.Setenv("PATH", t.TempDir())

			logger, err := logging.New(logging.File(filepath.Join(t.TempDir(), "upterm.log")))
			require.NoError(t, err)
			t.Cleanup(func() { _ = logger.Close() })

			cmd := upgradeCmd()
			cmd.SetContext(uptermctx.WithLogger(context.Background(), logger))

			err = cmd.RunE(cmd, tc.args)
			require.Error(t, err)
			if tc.prefix {
				require.True(t, strings.HasPrefix(err.Error(), tc.want), "got %q, want it to start with %q", err, tc.want)
			} else {
				require.EqualError(t, err, tc.want)
			}
			if tc.not != "" {
				require.NotContains(t, err.Error(), tc.not)
			}
		})
	}
}

// githubAnswering is the base URL of a GitHub that answers every request
// with status and body.
func githubAnswering(t *testing.T, status int, body string) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

// quietStdout sends os.Stdout to the null device for the test: upgrade hides
// and shows the cursor with escape sequences written there.
func quietStdout(t *testing.T) {
	t.Helper()

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = null
	t.Cleanup(func() {
		os.Stdout = orig
		_ = null.Close()
	})
}
