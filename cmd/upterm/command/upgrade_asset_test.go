package command

import (
	"encoding/json"
	"os"
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
