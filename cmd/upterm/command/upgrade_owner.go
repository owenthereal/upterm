package command

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// owner is a package manager that owns the binary, when upterm confirmed it.
type owner struct {
	Name    string // "Homebrew", "scoop", "dpkg", "rpm"
	Upgrade string // "brew upgrade upterm", "scoop update upterm", "apt", "dnf or yum"
}

var (
	homebrew = owner{Name: "Homebrew", Upgrade: "brew upgrade upterm"}
	scoop    = owner{Name: "scoop", Upgrade: "scoop update upterm"}
	dpkg     = owner{Name: "dpkg", Upgrade: "apt"}
	rpm      = owner{Name: "rpm", Upgrade: "dnf or yum"}
)

// refusal is what upgrade says instead of replacing a binary its manager owns.
func (o owner) refusal() string {
	by := o.Name
	if o == dpkg || o == rpm {
		by = "the upterm package (" + o.Name + ")"
	}

	return "this upterm was installed by " + by + "; upgrade it with " + o.Upgrade
}

// probes run a package database; tests replace them. Each reports whether the
// database lists the file. A tool that isn't installed lists nothing, but one
// that runs and can't say (say, for a database it can't open) is an error: it
// doesn't tell upterm the file is unowned. A nil probe never claims a file.
type probes struct {
	dpkgOwns func(path string) (bool, error)
	rpmOwns  func(path string) (bool, error)
}

// packageProbes ask the package databases of a machine running goos. Only a
// Linux distribution's package puts upterm where dpkg or rpm would own it, so
// on any other system they say no without running anything.
func packageProbes(goos string) probes {
	return probes{
		// dpkg-query -S exits 0 for a listed file, 1 for one no package lists
		// and 2 for a failure such as a database it can't read.
		dpkgOwns: func(path string) (bool, error) {
			return packageOwns(goos, "dpkg-query", []string{"-S", path},
				func(status int, _, _ string) bool { return status == 1 })
		},
		// rpm -qf exits 1 both for a file no package lists and for a database
		// it can't open, and for the second it says the file is not owned as
		// well, after an error line. So the file is unowned only when rpm
		// says so and had no error to report.
		rpmOwns: func(path string) (bool, error) {
			return packageOwns(goos, "rpm", []string{"-qf", path},
				func(_ int, stdout, stderr string) bool {
					return strings.Contains(stdout, "is not owned by any package") && !hasErrorLine(stderr)
				})
		},
	}
}

// hasErrorLine reports whether a tool's stderr has a line that begins "error:".
func hasErrorLine(stderr string) bool {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "error:") {
			return true
		}
	}

	return false
}

// toolFallbacks is where each package tool is when PATH doesn't have it. A
// root's PATH may leave out /usr/bin, and a package-owned binary must not be
// replaced for that. A var so a test can point it elsewhere.
var toolFallbacks = map[string]string{
	"dpkg-query": "/usr/bin/dpkg-query",
	"rpm":        "/usr/bin/rpm",
}

// systemProbes ask this machine's package databases.
var systemProbes = packageProbes(runtime.GOOS)

// packageOwns reports whether the package tool lists a file, on Linux: it does
// when the tool exits 0. A tool that fails lists nothing only if listsNothing,
// given its exit status and what it wrote to stdout and to stderr, says so; any
// other failure is an error
// naming the tool, its exit status and the first line it wrote to stderr. The
// tool is looked up on PATH, then in toolFallbacks; one that isn't found
// doesn't run, so it owns nothing.
func packageOwns(goos, tool string, args []string, listsNothing func(status int, stdout, stderr string) bool) (bool, error) {
	if goos != "linux" {
		return false, nil
	}

	exe, err := exec.LookPath(tool)
	if err != nil {
		var ok bool
		if exe, ok = toolFallbacks[tool]; !ok {
			return false, nil
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(exe, args...)
	cmd.Env = toolEnv()
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	var exit *exec.ExitError
	if errors.As(err, &exit) && listsNothing(exit.ExitCode(), stdout.String(), stderr.String()) {
		return false, nil
	}

	failure := err.Error()
	for _, line := range strings.Split(stderr.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			failure += ": " + line
			break
		}
	}

	return false, fmt.Errorf("%s failed: %s", tool, failure)
}

// systemPath is where a Linux system keeps the programs its package tools run.
const systemPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// toolEnv is the environment a package tool runs in: upterm's own, with the
// words it says in English (they are matched, see packageProbes), and with
// systemPath after upterm's PATH, so a tool found by toolFallbacks can still
// run the helpers it needs when upterm's PATH lacks them.
func toolEnv() []string {
	path := systemPath
	if p := os.Getenv("PATH"); p != "" {
		path = p + ":" + systemPath
	}

	return append(os.Environ(), "LC_ALL=C", "PATH="+path)
}

// unknownOwnerLine is what upgrade says when a package database can't be asked
// whether it lists path, and err says why. It stops rather than replace what a
// package might own.
func unknownOwnerLine(path string, err error) string {
	return fmt.Sprintf("can't check whether a package owns %s: %s; if a package manager installed it, upgrade it there", path, err)
}

// confirmedOwner reports the package manager that owns path, only when its own
// structure or database says so: Homebrew's Cellar or Caskroom, a Scoop app
// directory, or a dpkg or rpm database that lists the file. A path alone
// proves nothing, so a binary in /usr/bin that no database lists is unowned.
// A database that can't be asked is an error, and the ones after it aren't
// asked.
func confirmedOwner(path string, p probes) (owner, bool, error) {
	switch {
	case inHomebrew(path):
		return homebrew, true, nil
	case scoopOwns(path):
		return scoop, true, nil
	}

	for _, db := range []struct {
		owns func(path string) (bool, error)
		by   owner
	}{{p.dpkgOwns, dpkg}, {p.rpmOwns, rpm}} {
		if db.owns == nil {
			continue
		}

		owned, err := db.owns(path)
		if err != nil {
			return owner{}, false, err
		}
		if owned {
			return db.by, true, nil
		}
	}

	return owner{}, false, nil
}

// inHomebrew reports whether path lies in upterm's own Cellar (formula) or
// Caskroom (cask) directory, under any Homebrew prefix.
func inHomebrew(path string) bool {
	p := filepath.ToSlash(path)

	return strings.Contains(p, "/Cellar/upterm/") || strings.Contains(p, "/Caskroom/upterm/")
}

// scoopNames are the per-app metadata Scoop keeps in an installed version's
// directory: current Scoop writes the first pair, older Scoop the second, and
// current Scoop still reads the older one.
var scoopNames = [2][2]string{
	{"scoop-manifest.json", "scoop-install.json"},
	{"manifest.json", "install.json"},
}

// scoopOwns reports whether path is a Scoop-installed upterm under any root
// (default, $SCOOP, $SCOOP_GLOBAL or a custom one): the binary sits in
// <root>\apps\upterm\<version or current>\ and that directory holds Scoop's
// metadata for the app, both files of either generation.
func scoopOwns(path string) bool {
	dir := filepath.Dir(path)
	app := filepath.Dir(dir)
	if filepath.Base(app) != "upterm" || filepath.Base(filepath.Dir(app)) != "apps" {
		return false
	}

	for _, names := range scoopNames {
		if fileExists(filepath.Join(dir, names[0])) && fileExists(filepath.Join(dir, names[1])) {
			return true
		}
	}

	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
