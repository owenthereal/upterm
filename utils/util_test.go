package utils

import (
	"testing"
)

func Test_compareVersion(t *testing.T) {
	// check if first version is big than second version
	versions := []struct {
		a, b   string
		result int
	}{
		{"1.05.00.0156", "1.0.221.9289", 1},
		{"1.0.1", "1.0.1", 0},
		{"1", "1.0.1", -1},
		{"1.0.1", "1.0.2", -1},
		{"1.0.3", "1.0.2", 1},
		{"1.0.3", "1.1", -1},
		{"1.1", "1.1.1", -1},
		{"1.1.1", "1.1.2", -1},
		{"1.1.132", "1.2.2", -1},
		{"1.1.2", "1.2", -1},
	}
	for _, version := range versions {
		if CompareVersion(version.a, version.b) != version.result {
			t.Fatal("Can't compare version", version.a, version.b)
		}
	}
}
