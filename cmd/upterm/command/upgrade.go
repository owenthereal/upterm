package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	o, owned, err := confirmedOwner(target, systemProbes)
	if err != nil {
		return errors.New(unknownOwnerLine(target, err))
	}
	if owned {
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
	cmp := compareVersions(cur, next)
	if cmp == 0 {
		fmt.Println(outcomeLine(cur, next))
		return nil
	}

	// Asked for the latest, a build past it has nothing to upgrade to. Only a
	// version asked for by name is installed when it is older.
	if len(args) == 0 && cmp > 0 {
		fmt.Printf("upterm %s is newer than the latest release (%s)\n", cur, next)
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

// upgradeAdvice is how the version warning tells the operator to upgrade this
// upterm, from the checks upgrade makes before replacing it: upgrade itself
// when it could replace this binary, the owning package manager's command
// when one is confirmed, and otherwise the way it was installed. A check that
// can't answer is not an answer, so it gets the last of those too: the
// warning names only what upterm confirmed.
func upgradeAdvice() string {
	target, err := runningBinary()
	if err != nil {
		return theWayItWasInstalled
	}
	o, owned, err := confirmedOwner(target, systemProbes)
	switch {
	case err != nil:
		return theWayItWasInstalled
	case owned:
		return "upgrade with " + o.Upgrade
	}
	if err := writableDir(target); err != nil {
		return theWayItWasInstalled
	}
	return "upgrade with upterm upgrade"
}

// theWayItWasInstalled is the upgrade advice that claims nothing about how
// upterm was installed.
const theWayItWasInstalled = "upgrade it the way it was installed"

// upgradeAdviceTimeout bounds upgradeAdviceWithin's lookup. A var so a test
// can shorten it.
var upgradeAdviceTimeout = time.Second

// upgradeAdviceWithin is upgradeAdvice, given upgradeAdviceTimeout to answer.
// The daemon asks for it before the banner, and the package databases behind
// it take as long as they take: a lookup that hasn't answered by then gets the
// advice that claims nothing, and is left to finish on its own, since nothing
// it does needs undoing.
func upgradeAdviceWithin(logger *slog.Logger) string {
	// Buffered, so a lookup that answers late can still send and exit.
	answer := make(chan string, 1)
	go func() { answer <- upgradeAdvice() }()
	timer := time.NewTimer(upgradeAdviceTimeout)
	defer timer.Stop()
	select {
	case advice := <-answer:
		return advice
	case <-timer.C:
		logger.Debug("the upgrade advice lookup timed out; advising to upgrade the way upterm was installed", "timeout", upgradeAdviceTimeout)
		return theWayItWasInstalled
	}
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
