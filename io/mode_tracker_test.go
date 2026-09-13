package io

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ModeTracker_DECPrivateModes(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?2004h\x1b[?25l"))
	require.NoError(t, err)

	// Ascending numeric order, so the snapshot is deterministic.
	require.Equal(t, "\x1b[?25l\x1b[?1049h\x1b[?2004h", string(m.Snapshot()))
}

func Test_ModeTracker_LastWriteWins(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?1049l"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1049l", string(m.Snapshot()))
}

func Test_ModeTracker_MultipleParamsInOneSequence(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1000;1006h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1000h\x1b[?1006h", string(m.Snapshot()))
}

func Test_ModeTracker_ScrollRegionAndCharset(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[5;20r\x1b(0"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[5;20r\x1b(0", string(m.Snapshot()))
}

func Test_ModeTracker_SplitAcrossWrites(t *testing.T) {
	m := NewModeTracker()
	for _, chunk := range []string{"\x1b", "[?10", "49h"} {
		_, err := m.Write([]byte(chunk))
		require.NoError(t, err)
	}
	require.Equal(t, "\x1b[?1049h", string(m.Snapshot()))
}

func Test_ModeTracker_IgnoresNonModeSequences(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("hello \x1b[31mred\x1b[0m world\x1b[6n"))
	require.NoError(t, err)
	require.Empty(t, m.Snapshot())
}

func Test_ModeTracker_IgnoresUnknownModes(t *testing.T) {
	m := NewModeTracker()

	// Ten thousand distinct mode numbers nobody restores.
	var b strings.Builder
	for i := 3000; i < 13000; i++ {
		fmt.Fprintf(&b, "\x1b[?%dh", i)
	}
	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	require.Empty(t, m.Snapshot(), "only modes worth restoring may be retained")
}

func Test_ModeTracker_BoundsUnterminatedSequence(t *testing.T) {
	m := NewModeTracker()

	// A CSI that never terminates must not grow the parser without limit.
	_, err := m.Write([]byte("\x1b[" + strings.Repeat("1;", 100_000)))
	require.NoError(t, err)
	require.LessOrEqual(t, m.bufferedBytes(), maxSequenceBytes)

	// And the parser must have recovered: a real sequence after the garbage
	// still registers.
	_, err = m.Write([]byte("\x1b[?1049h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1049h", string(m.Snapshot()))
}

func Test_ModeTracker_SnapshotIsBounded(t *testing.T) {
	m := NewModeTracker()

	var b strings.Builder
	for _, mode := range restorableModes() {
		fmt.Fprintf(&b, "\x1b[?%dh", mode)
	}
	b.WriteString("\x1b[1;99999r\x1b(0")
	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	// Every restorable mode set at once, plus scroll region and charset, must
	// still be trivially smaller than a guest's sink.
	require.Less(t, len(m.Snapshot()), 1024)
}
