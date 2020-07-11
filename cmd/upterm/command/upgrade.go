package command

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	"github.com/tj/go-update/stores/github"
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
		Store: &github.Store{
			Owner:   "jingweno",
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

	// find the tarball for this system
	a := r.FindTarballWithVersion(runtime.GOOS, runtime.GOARCH, r.Version)
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

func (r *release) FindTarballWithVersion(os, arch, ver string) *update.Asset {
	s := fmt.Sprintf("%s-%s-%s", os, arch, ver)
	for _, a := range r.Assets {
		ext := filepath.Ext(a.Name)
		if strings.Contains(a.Name, s) && ext == ".gz" {
			return a
		}
	}

	return nil
}
