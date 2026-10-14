package command

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

func TestUnwritableLineForAPermissionErrorNamesTheFileAndItsDirectory(t *testing.T) {
	target := filepath.FromSlash("/usr/bin/upterm")
	err := &fs.PathError{Op: "open", Path: filepath.FromSlash("/usr/bin/.upterm-writable-1"), Err: fs.ErrPermission}

	require.Equal(t,
		"can't replace "+target+": permission denied. If a package manager installed it, upgrade it there; otherwise rerun with permission to write "+filepath.Dir(target),
		unwritableLine(target, err))
}

// Any other cause gives the operating system's reason and no advice: upterm
// can't tell that a package manager is involved, or that more permission
// would help.
func TestUnwritableLineForAnyOtherCauseGivesTheSystemsReasonOnly(t *testing.T) {
	target := filepath.FromSlash("/nix/store/abc-upterm/bin/upterm")
	err := &fs.PathError{Op: "open", Path: filepath.FromSlash("/nix/store/abc-upterm/bin/.upterm-writable-1"), Err: syscall.EROFS}

	require.Equal(t,
		"can't replace "+target+": read-only file system",
		unwritableLine(target, err))
}

func TestWritableDirIsAboutCreatingAFileBesideTheBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "upterm")
	require.NoError(t, writableDir(bin))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "the probe file is removed")

	require.ErrorIs(t, writableDir(filepath.Join(dir, "missing", "upterm")), fs.ErrNotExist)

	locked := readOnlyDir(t)
	require.ErrorIs(t, writableDir(filepath.Join(locked, "upterm")), fs.ErrPermission)
}

// fakeTool makes name the only command on PATH, and the only one the probes
// can find. It exits with status, but only when run with exactly args; any
// other call exits 2.
func fakeTool(t *testing.T, name string, status int, args ...string) {
	t.Helper()

	t.Setenv("PATH", writeFakeTool(t, name, status, args...))
	withToolFallbacks(t, nil)
}

// writeFakeTool writes the script fakeTool describes into a new directory and
// returns the directory.
func writeFakeTool(t *testing.T, name string, status int, args ...string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the fake tools are shell scripts")
	}

	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&script, "[ \"$#\" = %d ] || exit 2\n", len(args))
	for i, a := range args {
		fmt.Fprintf(&script, "[ \"$%d\" = '%s' ] || exit 2\n", i+1, a)
	}
	fmt.Fprintf(&script, "exit %d\n", status)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script.String()), 0o755))

	return dir
}

// withToolFallbacks sets where the probes look for a tool PATH doesn't have,
// for the rest of the test.
func withToolFallbacks(t *testing.T, fallbacks map[string]string) {
	t.Helper()

	orig := toolFallbacks
	t.Cleanup(func() { toolFallbacks = orig })
	toolFallbacks = fallbacks
}

func TestPackageProbesTrustTheToolsExitStatusOnLinux(t *testing.T) {
	const path = "/usr/bin/upterm"
	for _, tc := range []struct {
		tool   string
		args   []string
		probe  func(probes) func(string) bool
		status int
		want   bool
	}{
		{"dpkg-query", []string{"-S", path}, func(p probes) func(string) bool { return p.dpkgOwns }, 0, true},
		{"dpkg-query", []string{"-S", path}, func(p probes) func(string) bool { return p.dpkgOwns }, 1, false},
		{"rpm", []string{"-qf", path}, func(p probes) func(string) bool { return p.rpmOwns }, 0, true},
		{"rpm", []string{"-qf", path}, func(p probes) func(string) bool { return p.rpmOwns }, 1, false},
	} {
		t.Run(fmt.Sprintf("%s exits %d", tc.tool, tc.status), func(t *testing.T) {
			fakeTool(t, tc.tool, tc.status, tc.args...)

			require.Equal(t, tc.want, tc.probe(packageProbes("linux"))(path))
		})
	}
}

func TestPackageProbesSayNoWhenTheToolIsMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("probes ask nothing here")
	}

	t.Setenv("PATH", t.TempDir())
	withToolFallbacks(t, nil)

	p := packageProbes("linux")
	require.False(t, p.dpkgOwns("/usr/bin/upterm"))
	require.False(t, p.rpmOwns("/usr/bin/upterm"))
}

// root's PATH may lack /usr/bin, and a package-owned binary must not be
// overwritten for that: a tool PATH doesn't have is tried where the system
// keeps it, and one PATH does have is the one asked.
func TestPackageProbesFallBackToWhereTheSystemKeepsTheTools(t *testing.T) {
	const path = "/usr/bin/upterm"
	for _, tc := range []struct {
		tool  string
		args  []string
		probe func(probes) func(string) bool
	}{
		{"dpkg-query", []string{"-S", path}, func(p probes) func(string) bool { return p.dpkgOwns }},
		{"rpm", []string{"-qf", path}, func(p probes) func(string) bool { return p.rpmOwns }},
	} {
		t.Run(tc.tool+" only in the fallback", func(t *testing.T) {
			for status, want := range map[int]bool{0: true, 1: false} {
				t.Setenv("PATH", t.TempDir())
				withToolFallbacks(t, map[string]string{
					tc.tool: filepath.Join(writeFakeTool(t, tc.tool, status, tc.args...), tc.tool),
				})

				require.Equal(t, want, tc.probe(packageProbes("linux"))(path), "exits %d", status)
			}
		})

		t.Run(tc.tool+" on PATH and in the fallback", func(t *testing.T) {
			t.Setenv("PATH", writeFakeTool(t, tc.tool, 1, tc.args...))
			withToolFallbacks(t, map[string]string{
				tc.tool: filepath.Join(writeFakeTool(t, tc.tool, 0, tc.args...), tc.tool),
			})

			require.False(t, tc.probe(packageProbes("linux"))(path), "the fallback answered over PATH")
		})
	}
}

// The tools' fallback locations are where Linux distributions put them.
func TestToolFallbacksAreTheSystemsOwnDirectory(t *testing.T) {
	require.Equal(t, map[string]string{
		"dpkg-query": "/usr/bin/dpkg-query",
		"rpm":        "/usr/bin/rpm",
	}, toolFallbacks)
}

// Off Linux the probes don't run the tools at all, so a tool that would
// answer yes is never asked.
func TestPackageProbesAskNothingOffLinux(t *testing.T) {
	const path = "/usr/bin/upterm"
	for _, goos := range []string{"darwin", "windows", "freebsd"} {
		t.Run(goos+" dpkg", func(t *testing.T) {
			fakeTool(t, "dpkg-query", 0, "-S", path)

			require.False(t, packageProbes(goos).dpkgOwns(path))
		})
		t.Run(goos+" rpm", func(t *testing.T) {
			fakeTool(t, "rpm", 0, "-qf", path)

			require.False(t, packageProbes(goos).rpmOwns(path))
		})
	}
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
