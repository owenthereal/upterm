package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionFromBuildInfo(t *testing.T) {
	t.Run("built as upterm", func(t *testing.T) {
		v, ok := versionFromBuildInfo(&debug.BuildInfo{
			Main: debug.Module{Path: moduleName, Version: "v0.25.1"},
		})
		require.True(t, ok)
		require.Equal(t, "0.25.1", v)
	})

	// An embedding program has its own main module on its own version. Taking
	// it would have ServerSSHVersion advertise that as an upterm version.
	t.Run("embedded in another program", func(t *testing.T) {
		v, ok := versionFromBuildInfo(&debug.BuildInfo{
			Main: debug.Module{Path: "example.com/their/daemon", Version: "v2.3.0"},
			Deps: []*debug.Module{
				{Path: "example.com/other/dep", Version: "v1.0.0"},
				{Path: moduleName, Version: "v0.25.1"},
			},
		})
		require.True(t, ok)
		require.Equal(t, "0.25.1", v)
	})

	t.Run("upterm absent", func(t *testing.T) {
		_, ok := versionFromBuildInfo(&debug.BuildInfo{
			Main: debug.Module{Path: "example.com/their/daemon", Version: "v2.3.0"},
		})
		require.False(t, ok, "an embedding program's version is not an upterm version")
	})

	// A source build records no usable version; the dev default has to stand,
	// since Current panics on anything that does not parse.
	t.Run("source build", func(t *testing.T) {
		_, ok := versionFromBuildInfo(&debug.BuildInfo{
			Main: debug.Module{Path: moduleName, Version: "(devel)"},
		})
		require.False(t, ok)
	})
}

func TestParseFromSSHVersion(t *testing.T) {
	tests := []struct {
		name        string
		sshVersion  string
		expectedVer string
		expectError bool
	}{
		{
			name:        "valid uptermd SSH version",
			sshVersion:  "SSH-2.0-uptermd-0.14.3",
			expectedVer: "0.14.3",
			expectError: false,
		},
		{
			name:        "SSH version without numeric version",
			sshVersion:  "SSH-2.0-openssh",
			expectedVer: "",
			expectError: true,
		},
		{
			name:        "malformed version",
			sshVersion:  "SSH-2.0-uptermd-invalid",
			expectedVer: "",
			expectError: true,
		},
		{
			name:        "no version suffix",
			sshVersion:  "SSH-2.0-uptermd",
			expectedVer: "",
			expectError: true,
		},
		{
			name:        "complex semantic version with prerelease",
			sshVersion:  "SSH-2.0-uptermd-1.0.0-beta.1",
			expectedVer: "1.0.0-beta.1",
			expectError: false,
		},
		{
			name:        "complex semantic version with build metadata",
			sshVersion:  "SSH-2.0-uptermd-1.0.0+build.123",
			expectedVer: "1.0.0+build.123",
			expectError: false,
		},
		{
			name:        "complex semantic version with both prerelease and build",
			sshVersion:  "SSH-2.0-uptermd-2.0.0-rc.1+20220101",
			expectedVer: "2.0.0-rc.1+20220101",
			expectError: false,
		},
		{
			name:        "wrong server name - should fail",
			sshVersion:  "SSH-2.0-upterm-server-0.14.3",
			expectedVer: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := ParseFromSSHVersion(tt.sshVersion)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedVer, version.String())
		})
	}
}

func TestCheckCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		sshVersion   string
		expectedComp bool
		expectedHost string
		expectedSvr  string
		expectedMsg  string
	}{
		{
			name:         "same versions",
			sshVersion:   "SSH-2.0-uptermd-" + Version,
			expectedComp: true,
			expectedHost: "v" + Version,
			expectedSvr:  "v" + Version,
			expectedMsg:  "",
		},
		{
			name:         "same major, different minor",
			sshVersion:   "SSH-2.0-uptermd-0.15.0",
			expectedComp: true,
			expectedHost: "v" + Version,
			expectedSvr:  "v0.15.0",
			expectedMsg:  "",
		},
		{
			name:         "different major versions",
			sshVersion:   "SSH-2.0-uptermd-1.0.0",
			expectedComp: false,
			expectedHost: "v" + Version,
			expectedSvr:  "v1.0.0",
			expectedMsg:  "Major version mismatch: host v" + Version + ", server v1.0.0",
		},
		{
			name:         "different server (openssh) - treated as unknown",
			sshVersion:   "SSH-2.0-openssh-8.0",
			expectedComp: false,
			expectedHost: "v" + Version,
			expectedSvr:  "unknown",
			expectedMsg:  "Unable to determine server version - possibly older upterm server or non-upterm server",
		},
		{
			name:         "unparseable server version (no version) - incompatible",
			sshVersion:   "SSH-2.0-openssh",
			expectedComp: false,
			expectedHost: "v" + Version,
			expectedSvr:  "unknown",
			expectedMsg:  "Unable to determine server version - possibly older upterm server or non-upterm server",
		},
		{
			name:         "malformed SSH version - incompatible",
			sshVersion:   "invalid-version-string",
			expectedComp: false,
			expectedHost: "v" + Version,
			expectedSvr:  "unknown",
			expectedMsg:  "Unable to determine server version - possibly older upterm server or non-upterm server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCompatibility(tt.sshVersion)

			assert.Equal(t, tt.expectedComp, result.Compatible)
			assert.Equal(t, tt.expectedHost, result.HostVersion)
			assert.Equal(t, tt.expectedSvr, result.ServerVersion)
			assert.Equal(t, tt.expectedMsg, result.Message)
		})
	}
}

func TestServerSSHVersion(t *testing.T) {
	expected := "SSH-2.0-uptermd-" + Version
	actual := ServerSSHVersion()

	assert.Equal(t, expected, actual)
}

func TestCurrent(t *testing.T) {
	// Test that Current() returns a valid version and doesn't panic
	v := Current()
	assert.NotNil(t, v)
	assert.Equal(t, Version, v.String())
}

func TestCurrentPanic(t *testing.T) {
	// This test would only fail if Version constant is invalid
	// which would be a build-time issue, but we test the panic behavior
	assert.NotPanics(t, func() {
		Current()
	})
}
