package command

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpgradeTargetResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "tools", "upterm")
	require.NoError(t, os.MkdirAll(filepath.Dir(real), 0o755))
	require.NoError(t, os.WriteFile(real, []byte("x"), 0o755))
	link := filepath.Join(dir, "bin", "upterm")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	if err := os.Symlink(real, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("this account can't create symlinks: %v", err)
		}
		require.NoError(t, err)
	}

	got, err := resolveTarget(link)
	require.NoError(t, err)
	// The temp dir itself may sit under a symlink (macOS's /var).
	want, err := filepath.EvalSymlinks(real)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestManagedInstallsAreRefusedWithTheirCommand(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/opt/homebrew/Caskroom/upterm/0.38.0/upterm", "brew upgrade upterm"},
		{"/home/linuxbrew/.linuxbrew/Cellar/upterm/0.38.0/bin/upterm", "brew upgrade upterm"},
	} {
		o, ok := confirmedOwner(tc.path, probes{})
		require.True(t, ok, tc.path)
		require.Equal(t, tc.want, o.Upgrade)
	}

	o, ok := confirmedOwner("/usr/bin/upterm", probes{dpkgOwns: func(string) bool { return true }})
	require.True(t, ok)
	require.Equal(t, "dpkg", o.Name)

	o, ok = confirmedOwner("/usr/bin/upterm", probes{
		dpkgOwns: func(string) bool { return false },
		rpmOwns:  func(string) bool { return true },
	})
	require.True(t, ok)
	require.Equal(t, "rpm", o.Name)
}

func TestHomebrewOwnsOnlyUptermsOwnDirectories(t *testing.T) {
	for _, path := range []string{
		"/opt/homebrew/bin/upterm",
		"/opt/homebrew/Cellar/uptermd/0.38.0/bin/uptermd",
		"/opt/homebrew/Cellar/other/0.1.0/bin/upterm",
		"/home/me/Cellar/upterm",
	} {
		_, ok := confirmedOwner(path, probes{})
		require.False(t, ok, path)
	}
}

func TestScoopUnderACustomRootIsConfirmedByItsMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Tools") // like D:\Tools, a custom Scoop root
	app := filepath.Join(root, "apps", "upterm", "current")
	require.NoError(t, os.MkdirAll(app, 0o755))
	bin := filepath.Join(app, "upterm.exe")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))
	require.False(t, scoopOwns(bin), "no metadata yet")

	for _, names := range [][2]string{{"scoop-manifest.json", "scoop-install.json"}, {"manifest.json", "install.json"}} {
		for _, n := range names {
			require.NoError(t, os.WriteFile(filepath.Join(app, n), []byte("{}"), 0o644))
		}
		o, ok := confirmedOwner(bin, probes{})
		require.True(t, ok, names)
		require.Equal(t, "scoop update upterm", o.Upgrade)
		for _, n := range names {
			require.NoError(t, os.Remove(filepath.Join(app, n)))
		}
	}
}

func TestScoopNeedsItsAppDirectoryAndBothMetadataFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dir   []string // the binary's directory below the temp dir
		files []string // metadata beside the binary
	}{
		{"one file of a pair", []string{"Tools", "apps", "upterm", "current"}, []string{"scoop-install.json"}},
		{"another app's directory", []string{"Tools", "apps", "other", "current"}, []string{"scoop-manifest.json", "scoop-install.json"}},
		{"not under apps", []string{"Tools", "upterm", "current"}, []string{"scoop-manifest.json", "scoop-install.json"}},
		{"too shallow", []string{"upterm"}, []string{"scoop-manifest.json", "scoop-install.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(append([]string{t.TempDir()}, tc.dir...)...)
			require.NoError(t, os.MkdirAll(dir, 0o755))
			bin := filepath.Join(dir, "upterm.exe")
			require.NoError(t, os.WriteFile(bin, nil, 0o755))
			for _, n := range tc.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644))
			}

			require.False(t, scoopOwns(bin))
		})
	}
}

func TestAStandaloneBinaryInUsrBinIsNotClaimedForAnyManager(t *testing.T) {
	_, ok := confirmedOwner("/usr/bin/upterm", probes{dpkgOwns: func(string) bool { return false }, rpmOwns: func(string) bool { return false }})
	require.False(t, ok)
	_, ok = confirmedOwner("/usr/bin/upterm", probes{})
	require.False(t, ok, "tools that are missing own nothing")
}

func TestEachManagersRefusalNamesItsUpgradeCommand(t *testing.T) {
	for _, tc := range []struct {
		owner owner
		want  string
	}{
		{homebrew, "this upterm was installed by Homebrew; upgrade it with brew upgrade upterm"},
		{scoop, "this upterm was installed by scoop; upgrade it with scoop update upterm"},
		{dpkg, "this upterm was installed by the upterm package (dpkg); upgrade it with apt"},
		{rpm, "this upterm was installed by the upterm package (rpm); upgrade it with dnf or yum"},
	} {
		require.Equal(t, tc.want, tc.owner.refusal(), tc.owner.Name)
	}
}

func TestUnwritableLineNamesTheFileAndItsDirectory(t *testing.T) {
	target := filepath.FromSlash("/usr/bin/upterm")
	require.Equal(t,
		"can't replace "+target+": permission denied. If a package manager installed it, upgrade it there; otherwise rerun with permission to write "+filepath.Dir(target),
		unwritableLine(target))
}

func TestWritableDirIsAboutCreatingAFileBesideTheBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "upterm")
	require.True(t, writableDir(bin))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "the probe file is removed")

	require.False(t, writableDir(filepath.Join(dir, "missing", "upterm")))

	locked := readOnlyDir(t)
	require.False(t, writableDir(filepath.Join(locked, "upterm")))
}

// readOnlyDir is a directory its owner can't create files in. It skips the
// test where permissions don't hold: Windows, and root.
func readOnlyDir(t *testing.T) string {
	t.Helper()

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't stop this user")
	}

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	return dir
}
