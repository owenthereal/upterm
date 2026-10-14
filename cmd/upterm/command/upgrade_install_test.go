package command

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/owenthereal/upterm/internal/version"
	"github.com/stretchr/testify/require"
)

// tarFile is one entry of a test archive: a regular file unless kind says
// otherwise, in which case link is what it points to.
type tarFile struct {
	name, content string
	kind          byte
	link          string
}

// tarballOf writes a .tar.gz holding files, in order, and returns its path.
func tarballOf(t *testing.T, files ...tarFile) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	f, err := os.Create(path)
	require.NoError(t, err)

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		kind := file.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     file.name,
			Mode:     0o755,
			Size:     int64(len(file.content)),
			Typeflag: kind,
			Linkname: file.link,
		}))
		_, err := tw.Write([]byte(file.content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())

	return path
}

// tarballDeclaring writes a .tar.gz whose one file, name, claims to be size
// bytes and is cut off after its header, and returns its path.
func tarballDeclaring(t *testing.T, name string, size int64) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	f, err := os.Create(path)
	require.NoError(t, err)

	gz := gzip.NewWriter(f)
	require.NoError(t, tar.NewWriter(gz).WriteHeader(&tar.Header{
		Name: name, Mode: 0o755, Size: size, Typeflag: tar.TypeReg,
	}))
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())

	return path
}

// badTrailer is the .tar.gz at path with the CRC-32 in its gzip trailer
// changed, so everything before it is a valid archive and the whole of it is
// not.
func badTrailer(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// The trailer is the CRC-32 and then the length, four bytes each.
	data[len(data)-8] ^= 0xff

	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	require.NoError(t, os.WriteFile(bad, data, 0o644))

	return bad
}

// tarball writes a .tar.gz holding one file, name, and returns its path.
func tarball(t *testing.T, name, content string) string {
	t.Helper()

	return tarballOf(t, tarFile{name: name, content: content})
}

// fileNames is what dir holds.
func fileNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

// installCases are the platforms upgrade installs for and their name for the
// binary in the archive.
var installCases = []struct{ goos, binary string }{
	{"linux", "upterm"},
	{"windows", "upterm.exe"},
}

func TestInstallReplacesTheTarget(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		dir := t.TempDir()
		name := "upterm"
		if goos == "windows" {
			name = "upterm.exe"
		}
		target := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))
		archive := tarball(t, name, "new")
		require.NoError(t, installBinary(archive, target, goos))
		got, _ := os.ReadFile(target)
		require.Equal(t, "new", string(got))
	}
}

func TestInstalledBinaryIsExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no execute bit")
	}

	target := filepath.Join(t.TempDir(), "upterm")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	require.NoError(t, installBinary(tarball(t, "upterm", "new"), target, "linux"))

	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

// The file replaced is the one upgrade was asked to replace, whatever it is
// called: a build named upterm-dev gets the new binary as upterm-dev, and no
// upterm appears beside it.
func TestInstallWritesExactlyTheTarget(t *testing.T) {
	for _, tc := range installCases {
		t.Run(tc.goos, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "upterm-dev"+filepath.Ext(tc.binary))
			require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))

			require.NoError(t, installBinary(tarball(t, tc.binary, "new"), target, tc.goos))

			got, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, "new", string(got))

			want := []string{filepath.Base(target)}
			if tc.goos == "windows" {
				// The replaced binary may be the one running; it is set
				// aside, not deleted.
				want = append(want, filepath.Base(target)+".old")
				old, err := os.ReadFile(target + ".old")
				require.NoError(t, err)
				require.Equal(t, "old", string(old))
			}
			require.ElementsMatch(t, want, fileNames(t, dir))
		})
	}
}

// Only the binary at the archive's root is written; the archive's other
// files, and a same-named file in a subdirectory, are not.
func TestInstallTakesOnlyTheBinaryAtTheRoot(t *testing.T) {
	for _, tc := range installCases {
		t.Run(tc.goos, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, tc.binary)
			require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))

			archive := tarballOf(t,
				tarFile{name: "LICENSE", content: "license"},
				tarFile{name: "README.md", content: "readme"},
				tarFile{name: "etc/man/man1/upterm.1", content: "man"},
				tarFile{name: "sub/" + tc.binary, content: "decoy"},
				tarFile{name: tc.binary, content: "new"},
				tarFile{name: "docs/upterm.md", content: "docs"},
			)
			require.NoError(t, installBinary(archive, target, tc.goos))

			got, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, "new", string(got))

			for _, name := range fileNames(t, dir) {
				require.Contains(t, []string{tc.binary, tc.binary + ".old"}, name)
			}
		})
	}
}

// A binary that can't be installed leaves the old one in place and nothing
// else behind.
func TestAFailedInstallLeavesTheOldBinaryAndNothingElse(t *testing.T) {
	// A stream that gzip and tar accept for a while and then cut off.
	cutOff := func(t *testing.T, name string) string {
		t.Helper()

		noise := make([]byte, 1<<20)
		_, err := rand.Read(noise)
		require.NoError(t, err)

		whole, err := os.ReadFile(tarball(t, name, string(noise)))
		require.NoError(t, err)

		path := filepath.Join(t.TempDir(), "cut.tar.gz")
		require.NoError(t, os.WriteFile(path, whole[:len(whole)/2], 0o644))

		return path
	}

	for _, tc := range installCases {
		other := map[string]string{"upterm": "upterm.exe", "upterm.exe": "upterm"}[tc.binary]

		for _, bad := range []struct {
			name    string
			archive func(t *testing.T) string
			want    string // the error contains this
		}{
			{"no binary in it", func(t *testing.T) string { return tarball(t, "LICENSE", "x") }, "the archive has no " + tc.binary + " at its root"},
			{"the binary only in a directory", func(t *testing.T) string { return tarball(t, "upterm_x/"+tc.binary, "x") }, "the archive has no " + tc.binary + " at its root"},
			{"another system's binary", func(t *testing.T) string { return tarball(t, other, "x") }, "the archive has no " + tc.binary + " at its root"},
			// A name that is not a file is not the binary, however it is named.
			{"a symlink named for the binary", func(t *testing.T) string {
				return tarballOf(t, tarFile{name: tc.binary, kind: tar.TypeSymlink, link: "/bin/sh"})
			}, "the archive has no " + tc.binary + " at its root"},
			{"a hard link named for the binary", func(t *testing.T) string {
				return tarballOf(t, tarFile{name: "LICENSE", content: "x"}, tarFile{name: tc.binary, kind: tar.TypeLink, link: "LICENSE"})
			}, "the archive has no " + tc.binary + " at its root"},
			{"a directory named for the binary", func(t *testing.T) string {
				return tarballOf(t, tarFile{name: tc.binary, kind: tar.TypeDir})
			}, "the archive has no " + tc.binary + " at its root"},
			// The binary comes whole and first; what is wrong is further on, in
			// the checksum that closes the stream.
			{"a wrong checksum after the binary", func(t *testing.T) string {
				return badTrailer(t, tarballOf(t,
					tarFile{name: tc.binary, content: "new"},
					tarFile{name: "LICENSE", content: "license"},
					tarFile{name: "docs/upterm.md", content: "docs"},
				))
			}, "reading the archive: gzip: invalid checksum"},
			{"a binary over the size limit", func(t *testing.T) string {
				return tarballDeclaring(t, tc.binary, maxBinarySize+1)
			}, tc.binary + " in the archive is over 256 MiB"},
			{"not an archive", func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "x.tar.gz")
				require.NoError(t, os.WriteFile(p, []byte("not a tarball"), 0o644))
				return p
			}, "reading the archive"},
			{"cut off", func(t *testing.T) string { return cutOff(t, tc.binary) }, "reading the archive"},
			{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone.tar.gz") }, "gone.tar.gz"},
		} {
			t.Run(tc.goos+"/"+bad.name, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, tc.binary)
				require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))

				err := installBinary(bad.archive(t), target, tc.goos)
				require.ErrorContains(t, err, bad.want)

				got, rerr := os.ReadFile(target)
				require.NoError(t, rerr)
				require.Equal(t, "old", string(got))
				require.Equal(t, []string{tc.binary}, fileNames(t, dir))
			})
		}
	}
}

// Renaming is the only step that touches the old binary, and a rename that
// fails puts everything back.
func TestAFailedRenameLeavesTheOldBinaryAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		goos   string
		binary string
		fails  func(target, from, to string) bool
		// wantInErr is in the error: where the old binary is when it
		// couldn't be put back.
		wantInErr string
		// wantNames is what the directory holds afterwards.
		wantNames []string
	}{
		{"linux, moving the new binary into place", "linux", "upterm",
			func(target, _, to string) bool { return to == target },
			"", []string{"upterm"}},
		{"windows, setting the old binary aside", "windows", "upterm.exe",
			func(_, _, to string) bool { return strings.HasSuffix(to, ".old") },
			"", []string{"upterm.exe"}},
		{"windows, moving the new binary into place", "windows", "upterm.exe",
			func(target, from, _ string) bool { return strings.HasSuffix(from, ".new") },
			"", []string{"upterm.exe"}},
		{"windows, and the old binary can't be put back", "windows", "upterm.exe",
			func(target, _, to string) bool { return to == target },
			"upterm.exe.old", []string{"upterm.exe.old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, tc.binary)
			require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))

			orig := renameFile
			t.Cleanup(func() { renameFile = orig })
			renameFile = func(from, to string) error {
				if tc.fails(target, from, to) {
					return errors.New("rename refused")
				}
				return os.Rename(from, to)
			}

			err := installBinary(tarball(t, tc.binary, "new"), target, tc.goos)
			require.ErrorContains(t, err, "rename refused")
			if tc.wantInErr != "" {
				require.ErrorContains(t, err, filepath.Join(dir, tc.wantInErr))
			}

			require.Equal(t, tc.wantNames, fileNames(t, dir))
			if tc.wantInErr == "" {
				got, rerr := os.ReadFile(target)
				require.NoError(t, rerr)
				require.Equal(t, "old", string(got))
			}
		})
	}
}

func TestOnlyWindowsClearsTheLastUpgradesOldBinary(t *testing.T) {
	for _, tc := range []struct {
		goos string
		kept bool
	}{{"windows", false}, {"linux", true}} {
		t.Run(tc.goos, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "upterm")
			require.NoError(t, os.WriteFile(target, []byte("new"), 0o755))
			require.NoError(t, os.WriteFile(target+".old", []byte("old"), 0o755))

			removeStaleOld(target, tc.goos)

			_, err := os.Stat(target + ".old")
			require.Equal(t, tc.kept, err == nil)
			_, err = os.Stat(target)
			require.NoError(t, err)

			// Nothing to clear is not a problem.
			removeStaleOld(filepath.Join(dir, "other"), tc.goos)
		})
	}
}

func TestOutcomeSaysTheDirection(t *testing.T) {
	require.Equal(t, "Upgraded upterm 0.37.0 to 0.38.0", outcomeLine("0.37.0", "0.38.0"))
	require.Equal(t, "Downgraded upterm 0.38.0 to 0.37.0", outcomeLine("0.38.0", "0.37.0"))
	require.Equal(t, "upterm is already 0.38.0", outcomeLine("0.38.0", "0.38.0"))
}

func TestOutcomeComparesVersionsNotStrings(t *testing.T) {
	for _, tc := range []struct{ cur, next, want string }{
		// 0.9.0 sorts after 0.10.0 as text.
		{"0.9.0", "0.10.0", "Upgraded upterm 0.9.0 to 0.10.0"},
		{"0.10.0", "0.9.0", "Downgraded upterm 0.10.0 to 0.9.0"},
		// A prerelease is before its release.
		{"0.38.0-rc.1", "0.38.0", "Upgraded upterm 0.38.0-rc.1 to 0.38.0"},
		{"0.38.0", "0.38.0-rc.1", "Downgraded upterm 0.38.0 to 0.38.0-rc.1"},
		// A dev build is before every release.
		{"0.0.0+dev", "0.1.0", "Upgraded upterm 0.0.0+dev to 0.1.0"},
		// So is a version that isn't one.
		{"unknown", "0.1.0", "Upgraded upterm unknown to 0.1.0"},
		// A source build of a release is not the release.
		{"0.38.0+dirty", "0.38.0", "Upgraded upterm 0.38.0+dirty to 0.38.0"},
		{"0.38.0+abc", "0.38.0+xyz", "upterm is already 0.38.0+abc"},
	} {
		require.Equal(t, tc.want, outcomeLine(tc.cur, tc.next), "%s -> %s", tc.cur, tc.next)
	}
}

// upgrade's stdout is read by scripts and logs, so a pipe gets no cursor
// escapes.
func TestNoCursorEscapesIntoAPipe(t *testing.T) {
	out := captureStdout(t, func() { hideCursorIfTerminal(os.Stdout)() })
	require.NotContains(t, out, "\033[?25l")
	require.Empty(t, out)
}

// The progress bar draws with escape sequences on whatever stdout it was
// started on, so it is only given a terminal.
func TestNoProgressBarForAPipeOrAFile(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	require.Nil(t, downloadProxy(w))

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = null.Close() })
	require.Nil(t, downloadProxy(null))
}

// withVersion makes the running upterm report v for the rest of the test.
func withVersion(t *testing.T, v string) {
	t.Helper()

	orig := version.Version
	t.Cleanup(func() { version.Version = orig })
	version.Version = v
}

// withTempDir sends os.TempDir, where downloads land, to a new directory and
// returns it.
func withTempDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, dir)
	}

	return dir
}

// archiveName is the name of the binary in this system's release archive.
func archiveName() string {
	if runtime.GOOS == "windows" {
		return "upterm.exe"
	}

	return "upterm"
}

// releaseOf serves a GitHub whose release tag has archive, the file at that
// path, as this system's upterm archive. It returns the GitHub's base URL and
// the count of archive downloads.
func releaseOf(t *testing.T, tag, archive string) (string, *atomic.Int32) {
	t.Helper()

	data, err := os.ReadFile(archive)
	require.NoError(t, err)

	name := currentPlatform().assetName()
	downloads := new(atomic.Int32)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owenthereal/upterm/releases/tags/" + tag, "/repos/owenthereal/upterm/releases/latest":
			_, _ = fmt.Fprintf(w, `{"tag_name": %q, "assets": [{"name": %q, "browser_download_url": "%s/download/%s"}]}`, tag, name, srv.URL, name)
		case "/download/" + name:
			downloads.Add(1)
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return srv.URL, downloads
}

func TestUpgradeReplacesTheRunningBinaryAndSaysWhichWay(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  string
		args []string
		want string
	}{
		{"newer, pinned", "0.37.0", []string{"0.38.0"}, "Upgraded upterm 0.37.0 to 0.38.0\n"},
		{"newer, latest", "0.37.0", nil, "Upgraded upterm 0.37.0 to 0.38.0\n"},
		{"newer, typed with a v", "0.37.0", []string{"v0.38.0"}, "Upgraded upterm 0.37.0 to 0.38.0\n"},
		{"older", "0.39.0", []string{"0.38.0"}, "Downgraded upterm 0.39.0 to 0.38.0\n"},
		{"from a dev build", "0.0.0+dev", nil, "Upgraded upterm 0.0.0+dev to 0.38.0\n"},
		{"from a source build of the same version", "0.38.0+dirty", nil, "Upgraded upterm 0.38.0+dirty to 0.38.0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withVersion(t, tc.cur)
			tmp := withTempDir(t)
			base, downloads := releaseOf(t, "v0.38.0", tarball(t, archiveName(), "new"))
			withGitHub(t, base)

			// The running binary is not called upterm, and another upterm
			// is first on PATH: only the running one is replaced.
			dir := t.TempDir()
			target := filepath.Join(dir, "upterm-dev")
			require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))
			withRunningBinary(t, target)

			onPath := filepath.Join(t.TempDir(), archiveName())
			require.NoError(t, os.WriteFile(onPath, []byte("on PATH"), 0o755))
			t.Setenv("PATH", filepath.Dir(onPath))

			var err error
			out := captureStdout(t, func() { err = runUpgradeLoud(t, tc.args) })
			require.NoError(t, err)
			require.Equal(t, tc.want, out, "no escape sequences into a pipe")

			require.EqualValues(t, 1, downloads.Load())
			got, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, "new", string(got))
			got, err = os.ReadFile(onPath)
			require.NoError(t, err)
			require.Equal(t, "on PATH", string(got))

			want := []string{"upterm-dev"}
			if runtime.GOOS == "windows" {
				want = append(want, "upterm-dev.old")
			}
			require.ElementsMatch(t, want, fileNames(t, dir))

			// The downloaded archive is gone.
			require.Empty(t, fileNames(t, tmp))
		})
	}
}

func TestUpgradeToTheVersionItIsDownloadsNothing(t *testing.T) {
	for name, args := range map[string][]string{"latest": nil, "pinned": {"0.38.0"}} {
		t.Run(name, func(t *testing.T) {
			withVersion(t, "0.38.0")
			tmp := withTempDir(t)
			base, downloads := releaseOf(t, "v0.38.0", tarball(t, archiveName(), "new"))
			withGitHub(t, base)

			target := aStandaloneBinary(t)
			withRunningBinary(t, target)

			var err error
			out := captureStdout(t, func() { err = runUpgradeLoud(t, args) })
			require.NoError(t, err)
			require.Equal(t, "upterm is already 0.38.0\n", out)

			require.Zero(t, downloads.Load())
			require.Empty(t, fileNames(t, tmp))
			got, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Empty(t, got, "the binary is untouched")
		})
	}
}

func TestUpgradeThatCantInstallLeavesTheBinaryAndRemovesTheDownload(t *testing.T) {
	withVersion(t, "0.37.0")
	tmp := withTempDir(t)
	base, downloads := releaseOf(t, "v0.38.0", tarball(t, "LICENSE", "no binary here"))
	withGitHub(t, base)

	dir := t.TempDir()
	target := filepath.Join(dir, "upterm")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o755))
	withRunningBinary(t, target)

	var err error
	out := captureStdout(t, func() { err = runUpgradeLoud(t, []string{"0.38.0"}) })
	require.EqualError(t, err, fmt.Sprintf("installing %s: the archive has no %s at its root", target, archiveName()))
	require.Empty(t, out)

	require.EqualValues(t, 1, downloads.Load())
	got, rerr := os.ReadFile(target)
	require.NoError(t, rerr)
	require.Equal(t, "old", string(got))
	require.Equal(t, []string{"upterm"}, fileNames(t, dir))
	require.Empty(t, fileNames(t, tmp))
}

// An upgrade clears the previous one's set-aside binary on Windows, where it
// couldn't be deleted while it was running, and touches no such file
// elsewhere.
func TestUpgradeClearsTheLastUpgradesOldBinaryOnWindowsOnly(t *testing.T) {
	withVersion(t, "0.38.0")
	withTempDir(t)
	base, _ := releaseOf(t, "v0.38.0", tarball(t, archiveName(), "new"))
	withGitHub(t, base)

	dir := t.TempDir()
	target := filepath.Join(dir, "upterm")
	require.NoError(t, os.WriteFile(target, nil, 0o755))
	require.NoError(t, os.WriteFile(target+".old", []byte("old"), 0o755))
	withRunningBinary(t, target)

	require.NoError(t, runUpgrade(t, nil))

	want := []string{"upterm", "upterm.old"}
	if runtime.GOOS == "windows" {
		want = []string{"upterm"}
	}
	require.ElementsMatch(t, want, fileNames(t, dir))
}
