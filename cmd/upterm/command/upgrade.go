package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	ggh "github.com/google/go-github/v48/github"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
)

func upgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the CLI",
		Example: `  # Upgrade to the latest version:
  upterm upgrade

  # Upgrade to a specific version:
  upterm upgrade 0.2.0`,
		Args: cobra.MaximumNArgs(1),
		// A broken config file doesn't stop it.
		Annotations: map[string]string{annotationConfig: "none"},
		RunE:        upgradeRunE,
	}

	return cmd
}

func upgradeRunE(c *cobra.Command, args []string) error {
	// The binary to replace, and whether upterm may replace it, are settled
	// before anything is looked up or downloaded.
	target, err := runningBinary()
	if err != nil {
		return fmt.Errorf("can't find the running upterm: %w", err)
	}
	if o, ok := confirmedOwner(target, systemProbes); ok {
		return errors.New(o.refusal())
	}
	if err := writableDir(target); err != nil {
		return errors.New(unwritableLine(target, err))
	}

	removeStaleOld(target, runtime.GOOS)

	showCursor := hideCursorIfTerminal(os.Stdout)
	defer showCursor()

	m := &update.Manager{
		Store: &store{
			ctx:     c.Context(),
			Owner:   "owenthereal",
			Repo:    "upterm",
			Version: version.String(),
		},
	}

	var r *update.Release
	if len(args) > 0 {
		v := trimVPrefix(args[0])
		rr, err := m.GetRelease(v)
		if errors.Is(err, update.ErrNotFound) {
			return fmt.Errorf("release v%s not found", v)
		}
		if err != nil {
			return err
		}

		r = rr
	} else {
		// fetch the new releases
		releases, err := m.LatestReleases()
		if err != nil {
			return err
		}

		// no updates
		if len(releases) == 0 {
			return fmt.Errorf("no updates")
		}

		// latest release
		r = releases[0]
	}

	cur, next := version.String(), trimVPrefix(r.Version)
	if compareVersions(cur, next) == 0 {
		fmt.Println(outcomeLine(cur, next))
		return nil
	}

	// find the tarball for this system
	name := currentPlatform().assetName()
	a := findAsset(r.Assets, name)
	if a == nil {
		return fmt.Errorf("release %s has no upterm archive for this system (%s)", r.Version, name)
	}

	// download tarball to a tmp dir
	tarball, err := downloadAsset(c.Context(), http.DefaultClient, a.URL, downloadProxy(os.Stdout))
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tarball) }()

	// replace the running binary itself, not wherever PATH finds an upterm
	if err := installBinary(tarball, target, runtime.GOOS); err != nil {
		return fmt.Errorf("installing %s: %w", target, err)
	}

	fmt.Println(outcomeLine(cur, next))
	return nil
}

// downloadProxy draws the download's progress bar on f when f is a terminal.
// The bar is made of escape sequences and keeps writing to the stdout it
// started on, so for a pipe or a file there is none.
func downloadProxy(f *os.File) update.Proxy {
	if !isTerminal(f) {
		return nil
	}

	return progress.Reader
}

func trimVPrefix(s string) string {
	return strings.TrimPrefix(s, "v")
}

// githubClient is the GitHub API client; tests point BaseURL at httptest.
var githubClient = func() *ggh.Client { return ggh.NewClient(nil) }

// store looks releases up on GitHub. go-update's Store methods take no
// context, so the command's rides along in ctx.
type store struct {
	ctx     context.Context
	Owner   string
	Repo    string
	Version string
}

// githubText is err's text without the " []" go-github ends an error
// response's with when it has no detailed errors, which is a plain 4xx or 5xx.
func githubText(err error) string {
	return strings.TrimSuffix(err.Error(), " []")
}

func (s *store) GetRelease(version string) (*update.Release, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	r, res, err := githubClient().Repositories.GetReleaseByTag(ctx, s.Owner, s.Repo, "v"+version)
	if err != nil {
		// res is nil when the request never got an answer.
		switch {
		case res != nil && res.StatusCode == http.StatusNotFound:
			return nil, update.ErrNotFound
		case res != nil && res.StatusCode >= http.StatusBadRequest:
			return nil, fmt.Errorf("GitHub returned an error for v%s: %s", version, githubText(err))
		}

		return nil, fmt.Errorf("can't reach GitHub to look up v%s: %w", version, err)
	}

	return githubRelease(r), nil
}

func (s *store) LatestReleases() ([]*update.Release, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	r, res, err := githubClient().Repositories.GetLatestRelease(ctx, s.Owner, s.Repo)
	if err != nil {
		if res != nil && res.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("GitHub returned an error for the latest release: %s", githubText(err))
		}

		return nil, fmt.Errorf("can't reach GitHub to look up the latest release: %w", err)
	}

	return []*update.Release{
		githubRelease(r),
	}, nil
}

// downloadAsset fetches url into a temp file in os.TempDir and returns its
// path. A non-2xx status is an error naming it (update.Asset.DownloadProxy
// returns ("", nil) on a 4xx/5xx), and the temp file is removed on any error.
// A nil proxy means no proxying.
func downloadAsset(ctx context.Context, hc *http.Client, url string, proxy update.Proxy) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}

	name := path.Base(req.URL.Path)

	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", name, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		_ = res.Body.Close()
		return "", fmt.Errorf("downloading %s: %s", name, res.Status)
	}

	f, err := os.CreateTemp(os.TempDir(), "update-")
	if err != nil {
		_ = res.Body.Close()
		return "", fmt.Errorf("downloading %s: %w", name, err)
	}

	// ContentLength is -1 when unknown.
	size := max(int(res.ContentLength), 0)

	body := res.Body
	if proxy != nil {
		body = proxy(size, body)
	}

	_, err = io.Copy(f, body)
	if cerr := body.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("downloading %s: %w", name, err)
	}

	return f.Name(), nil
}

func githubRelease(r *ggh.RepositoryRelease) *update.Release {
	out := &update.Release{
		Version:     r.GetTagName(),
		Notes:       r.GetBody(),
		PublishedAt: r.GetPublishedAt().Time,
		URL:         r.GetURL(),
	}

	for _, a := range r.Assets {
		out.Assets = append(out.Assets, &update.Asset{
			Name:      a.GetName(),
			Size:      a.GetSize(),
			URL:       a.GetBrowserDownloadURL(),
			Downloads: a.GetDownloadCount(),
		})
	}

	return out
}
