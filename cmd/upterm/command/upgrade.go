package command

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ggh "github.com/google/go-github/v55/github"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	"github.com/tj/go/term"
)

func upgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the CLI",
		Example: `  # Upgrade to the latest version
  upterm upgrade

  # Upgrade to a specific version
  $ upterm upgrade 0.2.0`,
		RunE: upgradeRunE,
	}

	return cmd
}

func upgradeRunE(c *cobra.Command, args []string) error {
	term.HideCursor()
	defer term.ShowCursor()

	m := &update.Manager{
		Command: "upterm",
		Store: &store{
			Owner:   "owenthereal",
			Repo:    "upterm",
			Version: Version,
		},
	}

	var r release
	if len(args) > 0 {
		rr, err := m.GetRelease(trimVPrefix(args[0]))
		if err != nil {
			return fmt.Errorf("error fetching release: %s", err)
		}

		r = release{rr}
	} else {
		// fetch the new releases
		releases, err := m.LatestReleases()
		if err != nil {
			log.Fatalf("error fetching releases: %s", err)
		}

		// no updates
		if len(releases) == 0 {
			return fmt.Errorf("no updates")
		}

		// latest release
		r = release{releases[0]}
	}

	if fmt.Sprintf("v%s", Version) == r.Version {
		fmt.Println("Upterm is up-to-date")
		return nil
	}

	// find the tarball for this system
	a := r.FindTarballWithVersion(runtime.GOOS, runtime.GOARCH)
	if a == nil {
		return fmt.Errorf("no binary for your system")
	}

	// download tarball to a tmp dir
	tarball, err := a.DownloadProxy(progress.Reader)
	if err != nil {
		return fmt.Errorf("error downloading: %s", err)
	}

	// install it
	if err := m.Install(tarball); err != nil {
		return fmt.Errorf("error installing: %s", err)
	}

	fmt.Printf("Upgraded upterm %s to %s\n", Version, trimVPrefix(r.Version))
	return nil
}

func trimVPrefix(s string) string {
	return strings.TrimPrefix(s, "v")
}

type release struct {
	*update.Release
}

func (r *release) FindTarballWithVersion(os, arch string) *update.Asset {
	s := fmt.Sprintf("%s_%s", os, arch)
	for _, a := range r.Assets {
		ext := filepath.Ext(a.Name)
		if strings.Contains(a.Name, s) && ext == ".gz" {
			return a
		}
	}

	return nil
}

type store struct {
	Owner   string
	Repo    string
	Version string
}

func (s *store) GetRelease(version string) (*update.Release, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gh := ggh.NewClient(nil)

	r, res, err := gh.Repositories.GetReleaseByTag(ctx, s.Owner, s.Repo, "v"+version)

	if res.StatusCode == 404 {
		return nil, update.ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	return githubRelease(r), nil
}

func (s *store) LatestReleases() ([]*update.Release, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gh := ggh.NewClient(nil)

	r, _, err := gh.Repositories.GetLatestRelease(ctx, s.Owner, s.Repo)
	if err != nil {
		return nil, err
	}

	return []*update.Release{
		githubRelease(r),
	}, nil
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
