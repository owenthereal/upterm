package command

import (
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/tj/go-update"
)

// platform is the triple a release names its archives by: the running
// binary's GOOS and GOARCH, and its architecture level when the release
// template appends one (arm's GOARM; amd64's GOAMD64 when it isn't v1).
type platform struct {
	OS, Arch string
	Level    string // "6" for GOARM=6; "v3" for GOAMD64=v3; "" otherwise
}

// currentPlatform reads runtime.GOOS/GOARCH and the build info's "GOARM" or
// "GOAMD64" setting, dropping a ",softfloat"/",hardfloat" suffix.
func currentPlatform() platform {
	p := platform{OS: runtime.GOOS, Arch: runtime.GOARCH}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return p
	}

	for _, s := range info.Settings {
		switch {
		case p.Arch == "arm" && s.Key == "GOARM":
			p.Level = armLevel(s.Value)
		case p.Arch == "amd64" && s.Key == "GOAMD64":
			p.Level = amd64Level(s.Value)
		}
	}

	return p
}

// armLevel is GOARM without the ",softfloat"/",hardfloat" suffix newer Go
// versions record.
func armLevel(s string) string {
	level, _, _ := strings.Cut(s, ",")
	return level
}

// amd64Level is GOAMD64 unless it is v1, which the release name leaves out.
func amd64Level(s string) string {
	if s == "v1" {
		return ""
	}

	return s
}

// assetName is the archive's whole name, built as .goreleaser.yml:36 builds
// it: upterm_<os>_<arch>[v<arm>|<amd64 level>].tar.gz.
func (p platform) assetName() string {
	name := "upterm_" + p.OS + "_" + p.Arch
	switch p.Arch {
	case "arm":
		if p.Level != "" {
			name += "v" + p.Level
		}
	case "amd64":
		name += p.Level
	}

	return name + ".tar.gz"
}

// findAsset returns the asset whose name is exactly name, or nil. A substring
// match would let uptermd_linux_amd64.tar.gz stand in for upterm's.
func findAsset(assets []*update.Asset, name string) *update.Asset {
	for _, a := range assets {
		if a.Name == name {
			return a
		}
	}

	return nil
}
