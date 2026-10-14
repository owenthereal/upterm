package command

import (
	"encoding/json"
	"os"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tj/go-update"
)

// loadAssets reads a release's asset names, in the order the API lists them.
func loadAssets(t *testing.T, path string) []*update.Asset {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var names []string
	require.NoError(t, json.Unmarshal(b, &names))

	assets := make([]*update.Asset, 0, len(names))
	for _, n := range names {
		assets = append(assets, &update.Asset{Name: n})
	}

	return assets
}

func TestEveryBuiltPlatformFindsItsOwnArchive(t *testing.T) {
	assets := loadAssets(t, "testdata/release-v0.38.0-assets.json")
	for _, tc := range []struct {
		p    platform
		want string
	}{
		{platform{"linux", "amd64", ""}, "upterm_linux_amd64.tar.gz"},
		{platform{"linux", "arm64", ""}, "upterm_linux_arm64.tar.gz"},
		{platform{"linux", "arm", "6"}, "upterm_linux_armv6.tar.gz"},
		{platform{"linux", "386", ""}, "upterm_linux_386.tar.gz"},
		{platform{"linux", "ppc64le", ""}, "upterm_linux_ppc64le.tar.gz"},
		{platform{"linux", "s390x", ""}, "upterm_linux_s390x.tar.gz"},
		{platform{"darwin", "amd64", ""}, "upterm_darwin_amd64.tar.gz"},
		{platform{"darwin", "arm64", ""}, "upterm_darwin_arm64.tar.gz"},
		{platform{"windows", "386", ""}, "upterm_windows_386.tar.gz"},
		{platform{"windows", "amd64", ""}, "upterm_windows_amd64.tar.gz"},
		{platform{"windows", "arm64", ""}, "upterm_windows_arm64.tar.gz"},
	} {
		a := findAsset(assets, tc.p.assetName())
		require.NotNil(t, a, tc.want)
		require.Equal(t, tc.want, a.Name)
	}
}

func TestNoPartialMatch(t *testing.T) {
	assets := loadAssets(t, "testdata/release-v0.38.0-assets.json")
	require.Nil(t, findAsset(assets, platform{"linux", "amd64", "v3"}.assetName()))
	require.Nil(t, findAsset(assets, platform{"linux", "arm", "7"}.assetName()))
}

func TestPlatformLevelDropsTheFloatSuffix(t *testing.T) {
	require.Equal(t, "6", armLevel("6,softfloat"))
	require.Equal(t, "", amd64Level("v1"))
	require.Equal(t, "v3", amd64Level("v3"))
}

func TestPlatformFromReadsTheBuildSettings(t *testing.T) {
	setting := func(k, v string) []debug.BuildSetting {
		return []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}, {Key: k, Value: v}}
	}

	for _, tc := range []struct {
		name     string
		goos     string
		goarch   string
		settings []debug.BuildSetting
		want     string
	}{
		{"arm GOARM=6", "linux", "arm", setting("GOARM", "6"), "upterm_linux_armv6.tar.gz"},
		{"arm GOARM=7 with a float suffix", "linux", "arm", setting("GOARM", "7,softfloat"), "upterm_linux_armv7.tar.gz"},
		{"arm without settings", "linux", "arm", nil, "upterm_linux_arm.tar.gz"},
		{"amd64 GOAMD64=v1", "linux", "amd64", setting("GOAMD64", "v1"), "upterm_linux_amd64.tar.gz"},
		{"amd64 GOAMD64=v3", "linux", "amd64", setting("GOAMD64", "v3"), "upterm_linux_amd64v3.tar.gz"},
		{"arm64 GOARM64=v8.0", "linux", "arm64", setting("GOARM64", "v8.0"), "upterm_linux_arm64.tar.gz"},
		{"another arch's setting is ignored", "linux", "amd64", setting("GOARM", "6"), "upterm_linux_amd64.tar.gz"},
	} {
		require.Equal(t, tc.want, platformFrom(tc.goos, tc.goarch, tc.settings).assetName(), tc.name)
	}
}

// archiveNameTemplate is the name_template of .goreleaser.yml's upterm
// archive, which assetName reproduces by hand.
const archiveNameTemplate = `{{ .Binary }}_{{ .Os }}_{{ .Arch }}{{ with .Arm }}v{{ . }}{{ end }}{{ with .Mips }}_{{ . }}{{ end }}{{ if not (eq .Amd64 "v1") }}{{ .Amd64 }}{{ end }}`

// Every shipped upterm looks for its upgrade by assetName, so a release
// config that names archives differently strands them all.
func TestAssetNameFollowsTheGoreleaserArchive(t *testing.T) {
	b, err := os.ReadFile("../../../.goreleaser.yml")
	require.NoError(t, err)

	archive := goreleaserArchive(string(b), "upterm")
	require.NotEmpty(t, archive, "no archive with id upterm in .goreleaser.yml")

	var templates []string
	for _, line := range archive {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "name_template:"); ok {
			templates = append(templates, strings.Trim(strings.TrimSpace(v), `'"`))
		}
		// formats:, format: and format_overrides: all leave tar.gz.
		require.False(t, strings.HasPrefix(line, "format"),
			".goreleaser.yml's upterm archive sets %q: assetName (upgrade_asset.go) assumes goreleaser's default tar.gz and must change with it", line)
	}

	require.Equal(t, []string{archiveNameTemplate}, templates,
		".goreleaser.yml's upterm archive name_template changed: assetName (upgrade_asset.go) must change with it, or every installed upterm stops finding its upgrade")
}

// goreleaserArchive is the lines of the archives: entry whose id is id, from
// its "- id:" line to the next entry, or nil.
func goreleaserArchive(yml, id string) []string {
	var (
		lines     []string
		inSection bool
		inEntry   bool
	)

	for _, line := range strings.Split(yml, "\n") {
		line = strings.TrimRight(line, "\r")

		switch {
		case line == "archives:":
			inSection = true
		case !inSection:
		case line != "" && line[0] != ' ' && line[0] != '#':
			return lines // the next top-level key
		case strings.HasPrefix(line, "  - id:"):
			inEntry = strings.TrimSpace(strings.TrimPrefix(line, "  - id:")) == id
			if inEntry {
				lines = append(lines, line)
			}
		case inEntry:
			lines = append(lines, line)
		}
	}

	return lines
}
