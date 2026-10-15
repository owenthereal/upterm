package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
			withRunningBinary(t, aStandaloneBinary(t))

			err := runUpgrade(t, tc.args)
			require.Error(t, err)
			if tc.prefix {
				require.True(t, strings.HasPrefix(err.Error(), tc.want), "got %q, want it to start with %q", err, tc.want)
			} else {
				require.EqualError(t, err, tc.want)
			}
			if tc.not != "" {
				require.NotContains(t, err.Error(), tc.not)
			}
			// go-github ends a plain error response with the empty list of
			// its detailed errors.
			require.False(t, strings.HasSuffix(err.Error(), " []"), "got %q", err)
		})
	}
}

// Whose binary it is, and whether it can be replaced, is settled before
// anything is looked up or downloaded.
func TestUpgradeRefusesTheRunningBinaryBeforeLookingAnythingUp(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upgrade asked GitHub for %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(github.Close)

	// stops runs upgrade, for the latest release and for a pinned one, with
	// binary as the running upterm, and expects want from both.
	stops := func(t *testing.T, binary func() (string, error), want string) {
		t.Helper()

		withGitHub(t, github.URL)
		withRunningBinaryFunc(t, binary)

		require.EqualError(t, runUpgrade(t, nil), want)
		require.EqualError(t, runUpgrade(t, []string{"0.37.0"}), want)
	}

	t.Run("installed by Homebrew", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "Cellar", "upterm", "0.38.0", "bin", "upterm")
		require.NoError(t, os.MkdirAll(filepath.Dir(bin), 0o755))
		require.NoError(t, os.WriteFile(bin, nil, 0o755))

		// A confirmed owner is refused before anything is probed for writing.
		withWritableDir(t, func(string) error {
			t.Error("upgrade checked that it could write before it checked who owns the binary")
			return nil
		})

		stops(t, func() (string, error) { return bin, nil },
			"this upterm was installed by Homebrew; upgrade it with brew upgrade upterm")
	})

	// A binary a Linux package database lists, or that a database which can't
	// be asked might list, is refused: through the probes the command really
	// runs and the tools those run.
	for _, tc := range []struct {
		name, tool, flag string
		status           int
		stdout, stderr   string
		// want is the line, for the binary at bin.
		want func(bin string) string
	}{
		{"dpkg owns it", "dpkg-query", "-S", 0, "", "",
			func(string) string {
				return "this upterm was installed by the upterm package (dpkg); upgrade it with apt"
			}},
		{"rpm owns it", "rpm", "-qf", 0, "", "",
			func(string) string {
				return "this upterm was installed by the upterm package (rpm); upgrade it with dnf or yum"
			}},
		{"dpkg can't be asked", "dpkg-query", "-S", 2, "", "dpkg-query: error: the database is locked",
			func(bin string) string {
				return "can't check whether a package owns " + bin + ": dpkg-query failed: exit status 2: dpkg-query: error: the database is locked; if a package manager installed it, upgrade it there"
			}},
		// Unable to open its database, rpm says the file is not owned as well.
		{"rpm can't be asked", "rpm", "-qf", 1, rpmNotOwned, rpmCantOpen,
			func(bin string) string {
				return "can't check whether a package owns " + bin + ": rpm failed: exit status 1: error: cannot open Packages database in /var/lib/rpm; if a package manager installed it, upgrade it there"
			}},
		{"rpm fails without a word", "rpm", "-qf", 1, "", "",
			func(bin string) string {
				return "can't check whether a package owns " + bin + ": rpm failed: exit status 1; if a package manager installed it, upgrade it there"
			}},
	} {
		// refused runs upgrade on a binary the tool answers for as above: it
		// is refused, GitHub isn't asked, nothing is probed for writing, and
		// the binary and its directory are as they were.
		refused := func(t *testing.T) {
			bin := aStandaloneBinary(t)
			require.NoError(t, os.WriteFile(bin, []byte("old"), 0o755))
			fakeToolSaying(t, tc.tool, tc.status, tc.stdout, tc.stderr, tc.flag, bin)
			withWritableDir(t, func(string) error {
				t.Error("upgrade checked that it could write before it checked who owns the binary")
				return nil
			})

			stops(t, func() (string, error) { return bin, nil }, tc.want(bin))

			got, err := os.ReadFile(bin)
			require.NoError(t, err)
			require.Equal(t, "old", string(got))
			require.Equal(t, []string{"upterm"}, fileNames(t, filepath.Dir(bin)))
		}

		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS != "linux" {
				t.Skip("the system's probes ask only on Linux")
			}

			// The probes the command has when it runs, in place of the
			// stand-ins the tests have; the tool they run is the fake.
			orig := systemProbes
			t.Cleanup(func() { systemProbes = orig })
			systemProbes = realSystemProbes

			refused(t)
		})

		t.Run(tc.name+", on any system", func(t *testing.T) {
			orig := systemProbes
			t.Cleanup(func() { systemProbes = orig })
			systemProbes = packageProbes("linux")

			refused(t)
		})
	}

	t.Run("in a directory it can't write", func(t *testing.T) {
		bin := filepath.Join(readOnlyDir(t), "upterm")

		stops(t, func() (string, error) { return bin, nil }, unwritableLine(bin, fs.ErrPermission))
	})

	t.Run("on a read-only file system", func(t *testing.T) {
		bin := aStandaloneBinary(t)
		withWritableDir(t, func(path string) error {
			return &fs.PathError{Op: "open", Path: filepath.Join(filepath.Dir(path), ".upterm-writable-1"), Err: syscall.EROFS}
		})

		stops(t, func() (string, error) { return bin, nil }, "can't replace "+bin+": read-only file system")
	})

	t.Run("not found", func(t *testing.T) {
		stops(t, func() (string, error) { return "", errors.New("no such file") },
			"can't find the running upterm: no such file")
	})
}

// aStandaloneBinary is a file nothing owns, in a directory the test can
// write: what a binary put there by hand looks like.
func aStandaloneBinary(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "upterm")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))

	return bin
}

// withRunningBinary makes upgrade take path for the binary it replaces, so
// no test can reach the test binary.
func withRunningBinary(t *testing.T, path string) {
	t.Helper()

	withRunningBinaryFunc(t, func() (string, error) { return path, nil })
}

// withRunningBinaryFunc is withRunningBinary for a binary that can't be found.
func withRunningBinaryFunc(t *testing.T, f func() (string, error)) {
	t.Helper()

	orig := runningBinary
	t.Cleanup(func() { runningBinary = orig })
	runningBinary = f
}

// withWritableDir replaces the check that upgrade can write beside the
// binary, so a test can fail it for a reason the machine can't produce.
func withWritableDir(t *testing.T, f func(path string) error) {
	t.Helper()

	orig := writableDir
	t.Cleanup(func() { writableDir = orig })
	writableDir = f
}

// runUpgrade runs the command with args and returns its error.
func runUpgrade(t *testing.T, args []string) error {
	t.Helper()

	quietStdout(t)

	return runUpgradeLoud(t, args)
}

// runUpgradeLoud is runUpgrade with stdout left as it is, for a test that
// reads what upgrade prints.
func runUpgradeLoud(t *testing.T, args []string) error {
	t.Helper()

	cmd := upgradeCmd()
	cmd.SetContext(context.Background())

	return cmd.RunE(cmd, args)
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
