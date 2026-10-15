package command

import (
	"errors"
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

// ownerOf is confirmedOwner for a case that has no failing probe.
func ownerOf(t *testing.T, path string, p probes) (owner, bool) {
	t.Helper()

	o, ok, err := confirmedOwner(path, p)
	require.NoError(t, err, path)

	return o, ok
}

// answers is a probe that always gives the same answer.
func answers(owned bool, err error) func(string) (bool, error) {
	return func(string) (bool, error) { return owned, err }
}

func TestManagedInstallsAreRefusedWithTheirCommand(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/opt/homebrew/Caskroom/upterm/0.38.0/upterm", "brew upgrade upterm"},
		{"/home/linuxbrew/.linuxbrew/Cellar/upterm/0.38.0/bin/upterm", "brew upgrade upterm"},
	} {
		o, ok := ownerOf(t, tc.path, probes{})
		require.True(t, ok, tc.path)
		require.Equal(t, tc.want, o.Upgrade)
	}

	o, ok := ownerOf(t, "/usr/bin/upterm", probes{dpkgOwns: answers(true, nil)})
	require.True(t, ok)
	require.Equal(t, "dpkg", o.Name)

	o, ok = ownerOf(t, "/usr/bin/upterm", probes{
		dpkgOwns: answers(false, nil),
		rpmOwns:  answers(true, nil),
	})
	require.True(t, ok)
	require.Equal(t, "rpm", o.Name)
}

// A package database that can't be asked is neither a yes nor a no: the
// answer is the error, and nothing else is asked after it.
func TestAPackageDatabaseThatCantBeAskedIsNotAnAnswer(t *testing.T) {
	failed := errors.New("dpkg-query failed: exit status 2")
	rpmAsked := func(string) (bool, error) {
		t.Error("rpm was asked after dpkg couldn't answer")
		return true, nil
	}

	_, ok, err := confirmedOwner("/usr/bin/upterm", probes{dpkgOwns: answers(false, failed), rpmOwns: rpmAsked})
	require.False(t, ok)
	require.ErrorIs(t, err, failed)

	failed = errors.New("rpm failed: exit status 1")
	_, ok, err = confirmedOwner("/usr/bin/upterm", probes{dpkgOwns: answers(false, nil), rpmOwns: answers(false, failed)})
	require.False(t, ok)
	require.ErrorIs(t, err, failed)

	// Homebrew and Scoop are known from the path's own structure, with no
	// database to ask.
	broken := probes{dpkgOwns: answers(false, failed), rpmOwns: answers(false, failed)}
	o, ok, err := confirmedOwner("/opt/homebrew/Cellar/upterm/0.38.0/bin/upterm", broken)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, homebrew, o)
}

func TestUnknownOwnerLineNamesTheFileAndTheToolsFailure(t *testing.T) {
	require.Equal(t,
		"can't check whether a package owns /usr/bin/upterm: dpkg-query failed: exit status 2: dpkg-query: error: the database is locked; if a package manager installed it, upgrade it there",
		unknownOwnerLine("/usr/bin/upterm", errors.New("dpkg-query failed: exit status 2: dpkg-query: error: the database is locked")))
}

func TestHomebrewOwnsOnlyUptermsOwnDirectories(t *testing.T) {
	for _, path := range []string{
		"/opt/homebrew/bin/upterm",
		"/opt/homebrew/Cellar/uptermd/0.38.0/bin/uptermd",
		"/opt/homebrew/Cellar/other/0.1.0/bin/upterm",
		"/home/me/Cellar/upterm",
	} {
		_, ok := ownerOf(t, path, probes{})
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
		o, ok := ownerOf(t, bin, probes{})
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
	_, ok := ownerOf(t, "/usr/bin/upterm", probes{dpkgOwns: answers(false, nil), rpmOwns: answers(false, nil)})
	require.False(t, ok)
	_, ok = ownerOf(t, "/usr/bin/upterm", probes{})
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

	fakeToolSaying(t, name, status, "", "", args...)
}

// fakeToolSaying is fakeTool for a tool that also writes stdout and stderr
// (each a line, when not empty) before it exits.
func fakeToolSaying(t *testing.T, name string, status int, stdout, stderr string, args ...string) {
	t.Helper()

	t.Setenv("PATH", writeFakeTool(t, name, status, stdout, stderr, args...))
	withToolFallbacks(t, nil)
}

// shellQuoted is s as one word of a shell script.
func shellQuoted(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeFakeTool writes the script fakeToolSaying describes into a new
// directory and returns the directory.
func writeFakeTool(t *testing.T, name string, status int, stdout, stderr string, args ...string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the fake tools are shell scripts")
	}

	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&script, "[ \"$#\" = %d ] || exit 2\n", len(args))
	for i, a := range args {
		fmt.Fprintf(&script, "[ \"$%d\" = %s ] || exit 2\n", i+1, shellQuoted(a))
	}
	if stdout != "" {
		fmt.Fprintf(&script, "printf '%%s\\n' %s\n", shellQuoted(stdout))
	}
	if stderr != "" {
		fmt.Fprintf(&script, "printf '%%s\\n' %s >&2\n", shellQuoted(stderr))
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

// rpmNotOwned is what rpm says, on stdout, of a file no package lists. It says
// it when it can't open its database too, then with rpmCantOpen on stderr.
const (
	rpmNotOwned = "file /usr/bin/upterm is not owned by any package"
	rpmCantOpen = "error: cannot open Packages database in /var/lib/rpm"
)

// dpkg-query: 0 is owned, 1 is not owned, anything else is that it couldn't
// say. rpm: 0 is owned; a failure whose stdout says the file is not owned by
// any package, with no error line on stderr, is not owned; any other failure
// is that it couldn't say.
func TestPackageProbesAnswerFromTheToolsOwnWordsOnLinux(t *testing.T) {
	const path = "/usr/bin/upterm"
	dpkgProbe := func(p probes) func(string) (bool, error) { return p.dpkgOwns }
	rpmProbe := func(p probes) func(string) (bool, error) { return p.rpmOwns }

	for _, tc := range []struct {
		name           string
		tool           string
		args           []string
		probe          func(probes) func(string) (bool, error)
		status         int
		stdout, stderr string
		owned          bool
		failure        string // the error's text; empty when the tool could say
	}{
		{"dpkg lists it", "dpkg-query", []string{"-S", path}, dpkgProbe, 0, "upterm: /usr/bin/upterm", "", true, ""},
		{"dpkg lists nothing", "dpkg-query", []string{"-S", path}, dpkgProbe, 1, "", "dpkg-query: no path found matching pattern /usr/bin/upterm", false, ""},
		{"dpkg has a fatal error", "dpkg-query", []string{"-S", path}, dpkgProbe, 2, "", "dpkg-query: error: the database is locked\nsecond line", false,
			"dpkg-query failed: exit status 2: dpkg-query: error: the database is locked"},
		{"dpkg has a fatal error and says nothing", "dpkg-query", []string{"-S", path}, dpkgProbe, 2, "", "", false,
			"dpkg-query failed: exit status 2"},
		{"dpkg fails some other way", "dpkg-query", []string{"-S", path}, dpkgProbe, 3, "", "  \n  padded line  \n", false,
			"dpkg-query failed: exit status 3: padded line"},

		{"rpm lists it", "rpm", []string{"-qf", path}, rpmProbe, 0, "upterm-0.38.0-1.x86_64", "", true, ""},
		{"rpm says on stdout that no package has it", "rpm", []string{"-qf", path}, rpmProbe, 1, rpmNotOwned, "", false, ""},
		{"rpm says it with another status", "rpm", []string{"-qf", path}, rpmProbe, 2, rpmNotOwned, "", false, ""},
		{"rpm says it and warns", "rpm", []string{"-qf", path}, rpmProbe, 1, rpmNotOwned, "warning: something to note", false, ""},
		// What rpm does when it can't open its database: it says the file is
		// not owned as well, but after an error line.
		{"rpm can't open its database", "rpm", []string{"-qf", path}, rpmProbe, 1, rpmNotOwned, rpmCantOpen, false,
			"rpm failed: exit status 1: " + rpmCantOpen},
		{"rpm can't open its database, twice over", "rpm", []string{"-qf", path}, rpmProbe, 1, rpmNotOwned, rpmCantOpen + "\n" + rpmCantOpen, false,
			"rpm failed: exit status 1: " + rpmCantOpen},
		{"rpm errors after a warning", "rpm", []string{"-qf", path}, rpmProbe, 1, rpmNotOwned, "warning: a note\n  " + rpmCantOpen, false,
			"rpm failed: exit status 1: warning: a note"},
		// Only stderr has the words: not what rpm says of a file no package has.
		{"rpm says it on stderr", "rpm", []string{"-qf", path}, rpmProbe, 1, "", rpmNotOwned, false,
			"rpm failed: exit status 1: " + rpmNotOwned},
		{"rpm errors and says nothing else", "rpm", []string{"-qf", path}, rpmProbe, 1, "", rpmCantOpen, false,
			"rpm failed: exit status 1: " + rpmCantOpen},
		{"rpm fails and says nothing", "rpm", []string{"-qf", path}, rpmProbe, 1, "", "", false,
			"rpm failed: exit status 1"},
		{"rpm can't find the file", "rpm", []string{"-qf", path}, rpmProbe, 1, "", "error: file /usr/bin/upterm: No such file or directory", false,
			"rpm failed: exit status 1: error: file /usr/bin/upterm: No such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeToolSaying(t, tc.tool, tc.status, tc.stdout, tc.stderr, tc.args...)

			owned, err := tc.probe(packageProbes("linux"))(path)
			require.Equal(t, tc.owned, owned)
			if tc.failure == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.failure)
			}
		})
	}
}

// A tool that isn't installed doesn't run, and owns nothing: it can't have
// installed upterm.
func TestPackageProbesSayNoWhenTheToolIsMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("probes ask nothing here")
	}

	t.Setenv("PATH", t.TempDir())
	withToolFallbacks(t, nil)

	p := packageProbes("linux")
	owned, err := p.dpkgOwns("/usr/bin/upterm")
	require.NoError(t, err)
	require.False(t, owned)
	owned, err = p.rpmOwns("/usr/bin/upterm")
	require.NoError(t, err)
	require.False(t, owned)

	// Nor does one the fallback names but the system doesn't have.
	withToolFallbacks(t, map[string]string{
		"dpkg-query": filepath.Join(t.TempDir(), "dpkg-query"),
		"rpm":        filepath.Join(t.TempDir(), "rpm"),
	})
	owned, err = p.dpkgOwns("/usr/bin/upterm")
	require.NoError(t, err)
	require.False(t, owned)
	owned, err = p.rpmOwns("/usr/bin/upterm")
	require.NoError(t, err)
	require.False(t, owned)
}

// root's PATH may lack /usr/bin, and a package-owned binary must not be
// overwritten for that: a tool PATH doesn't have is tried where the system
// keeps it, and one PATH does have is the one asked.
func TestPackageProbesFallBackToWhereTheSystemKeepsTheTools(t *testing.T) {
	const path = "/usr/bin/upterm"
	for _, tc := range []struct {
		tool  string
		args  []string
		probe func(probes) func(string) (bool, error)
		// notOwned is how the tool says it lists nothing.
		notOwnedStatus int
		notOwnedStdout string
	}{
		{"dpkg-query", []string{"-S", path}, func(p probes) func(string) (bool, error) { return p.dpkgOwns }, 1, ""},
		{"rpm", []string{"-qf", path}, func(p probes) func(string) (bool, error) { return p.rpmOwns }, 1, rpmNotOwned},
	} {
		t.Run(tc.tool+" only in the fallback", func(t *testing.T) {
			t.Setenv("PATH", t.TempDir())
			withToolFallbacks(t, map[string]string{
				tc.tool: filepath.Join(writeFakeTool(t, tc.tool, 0, "", "", tc.args...), tc.tool),
			})
			owned, err := tc.probe(packageProbes("linux"))(path)
			require.NoError(t, err)
			require.True(t, owned, "the fallback's yes")

			withToolFallbacks(t, map[string]string{
				tc.tool: filepath.Join(writeFakeTool(t, tc.tool, tc.notOwnedStatus, tc.notOwnedStdout, "", tc.args...), tc.tool),
			})
			owned, err = tc.probe(packageProbes("linux"))(path)
			require.NoError(t, err)
			require.False(t, owned, "the fallback's no")
		})

		t.Run(tc.tool+" on PATH and in the fallback", func(t *testing.T) {
			t.Setenv("PATH", writeFakeTool(t, tc.tool, tc.notOwnedStatus, tc.notOwnedStdout, "", tc.args...))
			withToolFallbacks(t, map[string]string{
				tc.tool: filepath.Join(writeFakeTool(t, tc.tool, 0, "", "", tc.args...), tc.tool),
			})

			owned, err := tc.probe(packageProbes("linux"))(path)
			require.NoError(t, err)
			require.False(t, owned, "the fallback answered over PATH")
		})
	}
}

// The tools' fallback locations are where Linux distributions put them.
func TestToolFallbacksAreTheSystemsOwnDirectory(t *testing.T) {
	require.Equal(t, map[string]string{
		"dpkg-query": "/usr/bin/dpkg-query",
		"rpm":        "/usr/bin/rpm",
	}, realToolFallbacks)
}

// The tests never run the machine's own package tools: a test that reaches
// the probes without fakes would get an answer that depends on the machine.
func TestTheSuiteHasNoPackageToolsToAsk(t *testing.T) {
	require.Nil(t, systemProbes.dpkgOwns)
	require.Nil(t, systemProbes.rpmOwns)
	require.Empty(t, toolFallbacks)
	require.NotNil(t, realSystemProbes.dpkgOwns, "TestMain keeps the real ones for the tests of them")
}

// A package tool runs with the words it says in English and the system's
// directories after upterm's own PATH, so one found by the fallback can run its
// helpers when upterm's PATH has none.
func TestPackageToolsRunWithTheSystemDirectoriesOnPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake tools are shell scripts")
	}

	const path = "/usr/bin/upterm"
	for _, tc := range []struct {
		name string
		// path is upterm's PATH, set once the tool is placed.
		path func(toolDir string) string
		// fallback is that the tool is found by the fallback, not PATH.
		fallback bool
		want     func(toolDir string) string
	}{
		{"found on PATH", func(dir string) string { return dir }, false,
			func(dir string) string { return dir + ":/usr/sbin:/usr/bin:/sbin:/bin" }},
		{"found by the fallback, PATH set", func(string) string { return "/some/dir" }, true,
			func(string) string { return "/some/dir:/usr/sbin:/usr/bin:/sbin:/bin" }},
		{"found by the fallback, PATH empty", func(string) string { return "" }, true,
			func(string) string { return "/usr/sbin:/usr/bin:/sbin:/bin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seen := filepath.Join(t.TempDir(), "seen")
			script := "#!/bin/sh\n" +
				"printf '%s\\n%s\\n' \"$PATH\" \"$LC_ALL\" > " + shellQuoted(seen) + "\n" +
				"exit 0\n"
			require.NoError(t, os.WriteFile(filepath.Join(dir, "dpkg-query"), []byte(script), 0o755))

			t.Setenv("PATH", tc.path(dir))
			if tc.fallback {
				withToolFallbacks(t, map[string]string{"dpkg-query": filepath.Join(dir, "dpkg-query")})
			} else {
				withToolFallbacks(t, nil)
			}

			owned, err := packageProbes("linux").dpkgOwns(path)
			require.NoError(t, err)
			require.True(t, owned)

			got, err := os.ReadFile(seen)
			require.NoError(t, err)
			require.Equal(t, tc.want(dir)+"\nC\n", string(got))
		})
	}
}

// Off Linux the probes don't run the tools at all, so a tool that would
// answer yes is never asked.
func TestPackageProbesAskNothingOffLinux(t *testing.T) {
	const path = "/usr/bin/upterm"
	for _, goos := range []string{"darwin", "windows", "freebsd"} {
		t.Run(goos+" dpkg", func(t *testing.T) {
			fakeTool(t, "dpkg-query", 0, "-S", path)

			owned, err := packageProbes(goos).dpkgOwns(path)
			require.NoError(t, err)
			require.False(t, owned)
		})
		t.Run(goos+" rpm", func(t *testing.T) {
			fakeTool(t, "rpm", 0, "-qf", path)

			owned, err := packageProbes(goos).rpmOwns(path)
			require.NoError(t, err)
			require.False(t, owned)
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
