package command

import (
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

// probes run a package database; tests replace them. Each returns false when
// the tool is missing or says the file isn't owned, and a nil probe never
// claims a file.
type probes struct {
	dpkgOwns func(path string) bool // dpkg-query -S PATH exits 0
	rpmOwns  func(path string) bool // rpm -qf PATH exits 0
}

// packageProbes ask the package databases of a machine running goos. Only a
// Linux distribution's package puts upterm where dpkg or rpm would own it, so
// on any other system they say no without running anything.
func packageProbes(goos string) probes {
	return probes{
		dpkgOwns: func(path string) bool { return packageOwns(goos, "dpkg-query", "-S", path) },
		rpmOwns:  func(path string) bool { return packageOwns(goos, "rpm", "-qf", path) },
	}
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

// packageOwns reports whether the package tool exits 0 for args, on Linux. The
// tool is looked up on PATH, then in toolFallbacks; one that isn't found
// doesn't run, so it owns nothing.
func packageOwns(goos, tool string, args ...string) bool {
	if goos != "linux" {
		return false
	}

	exe, err := exec.LookPath(tool)
	if err != nil {
		var ok bool
		if exe, ok = toolFallbacks[tool]; !ok {
			return false
		}
	}

	return exec.Command(exe, args...).Run() == nil
}

// confirmedOwner reports the package manager that owns path, only when its own
// structure or database says so: Homebrew's Cellar or Caskroom, a Scoop app
// directory, or a dpkg or rpm database that lists the file. A path alone
// proves nothing, so a binary in /usr/bin that no database lists is
// unowned.
func confirmedOwner(path string, p probes) (owner, bool) {
	switch {
	case inHomebrew(path):
		return homebrew, true
	case scoopOwns(path):
		return scoop, true
	case p.dpkgOwns != nil && p.dpkgOwns(path):
		return dpkg, true
	case p.rpmOwns != nil && p.rpmOwns(path):
		return rpm, true
	}

	return owner{}, false
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
