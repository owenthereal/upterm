package io

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// The README's rejoin script resets every mode the tracker restores, to the
// tracker's default, so a mode tracked later fails here until the README
// resets it too.
func TestREADMERejoinScriptResetsEveryTrackedMode(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	line := regexp.MustCompile(`(?m)^reset_modes\(\) \{ printf '([^']*)'; \}$`).FindSubmatch(raw)
	require.NotNil(t, line, "the README's reset_modes line")
	set := map[int]bool{}
	for _, m := range regexp.MustCompile(`\\033\[\?(\d+)([hl])`).FindAllSubmatch(line[1], -1) {
		n, _ := strconv.Atoi(string(m[1]))
		set[n] = string(m[2]) == "h"
	}
	for _, n := range restorableModes() {
		on, ok := set[n]
		require.True(t, ok, "mode %d is tracked but not reset", n)
		require.Equal(t, restorable[n], on, "mode %d is reset away from its default", n)
	}
	require.Contains(t, string(line[1]), `\033[<u`, "the kitty keyboard protocol")
	require.Contains(t, string(line[1]), `\033[>4m`, "modifyOtherKeys")
}
