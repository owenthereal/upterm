package io

import (
	"bytes"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The README's rejoin script resets what the tracker's Restore restores: the
// modes at their defaults, the alternate screen, the scroll region and the
// charset, plus the kitty keyboard protocol and modifyOtherKeys. A mode
// tracked later fails here until the README resets it too. The alternate
// screen and scroll region resets sit between a cursor save and restore,
// because on the normal screen they would otherwise move the cursor.
func TestREADMERejoinScriptResetsEveryTrackedMode(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	// Windows checkouts convert line endings, and `$` below won't match before a `\r`.
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	line := regexp.MustCompile(`(?m)^reset_modes\(\) \{ printf '([^']*)'; \}$`).FindSubmatch(raw)
	require.NotNil(t, line, "the README's reset_modes line")
	set := map[int]bool{}
	for _, m := range regexp.MustCompile(`\\033\[\?(\d+)([hl])`).FindAllSubmatch(line[1], -1) {
		n, _ := strconv.Atoi(string(m[1]))
		set[n] = string(m[2]) == "h"
	}
	modes := restorableModes()
	require.NotEmpty(t, modes, "the tracker restores no modes, so there is nothing to check the README against")
	for _, n := range modes {
		on, ok := set[n]
		require.True(t, ok, "mode %d is tracked but not reset", n)
		require.Equal(t, restorable[n], on, "mode %d is reset away from its default", n)
	}
	require.Contains(t, string(line[1]), `\033[<u`, "the kitty keyboard protocol")
	require.Contains(t, string(line[1]), `\033[>4m`, "modifyOtherKeys")

	reset := string(line[1])
	require.Contains(t, reset, `\030`, "CAN, to abort a half-received sequence")
	require.Contains(t, reset, `\033[r`, "the scroll region")
	require.Contains(t, reset, `\033(B`, "US ASCII into G0")
	save := strings.Index(reset, `\0337`)
	altOff := strings.Index(reset, `\033[?1049l`)
	region := strings.Index(reset, `\033[r`)
	restore := strings.Index(reset, `\0338`)
	charset := strings.Index(reset, `\033(B`)
	require.GreaterOrEqual(t, save, 0, "DECSC, which saves the cursor")
	require.GreaterOrEqual(t, restore, 0, "DECRC, which puts the cursor back")
	require.Less(t, save, altOff, "the cursor is saved before the alternate screen is left")
	require.Less(t, altOff, restore, "the cursor is put back after the alternate screen is left")
	require.Less(t, save, region, "the cursor is saved before the scroll region is reset")
	require.Less(t, region, restore, "the cursor is put back after the scroll region is reset")
	require.Less(t, restore, charset, "the charset is set after DECRC, which restores the saved one")
}
