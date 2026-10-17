package replay

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// overshoot is how long past its deadline a replay may still be running when
// it returns: the meter's interval of work, about a millisecond, the work
// outside the meter, bounded by the screen's size, and the scheduling of a
// loaded machine.
const overshoot = 50 * time.Millisecond * timeScale

// The rings the measurements found costliest, at the size cap, where each
// scrolled line or erase touches 131,072 cells: empty lines, as yes prints
// them given an empty string, a background-coloured blank row per 9 bytes,
// one REP of 100,000,000, and ED 2 after ED 2. Each renders, or fails at its
// deadline, by the deadline and one meter interval.
func TestReplayPathological(t *testing.T) {
	const wait = 200 * time.Millisecond
	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{"yes ''", bytes.Repeat([]byte("\n"), uio.DefaultReplayBytes)},
		{"coloured blank rows", bytes.Repeat([]byte("\x1b[41m\x1b[K\n"), uio.DefaultReplayBytes/9)},
		// REP prints, so the line feed after it is what ends a batch.
		{"ESC[100000000b", []byte("x\x1b[100000000b\n")},
		{"ED 2 floods", bytes.Repeat([]byte("\x1b[2J"), uio.DefaultReplayBytes/4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			began := time.Now()
			em, err := New().Start(context.Background(), began.Add(wait),
				captureOf(string(tc.stream), event(1, 0, 512, 256)), termsize.Size{Cols: 512, Rows: 256})
			if err == nil {
				var render []byte
				render, err = em.Render()
				require.LessOrEqual(t, len(render), uio.DefaultReplayBytes)
			}
			elapsed := time.Since(began)
			t.Logf("after %v: %v", elapsed, err)
			require.LessOrEqual(t, elapsed, wait+overshoot)
		})
	}
}

// One 4 KiB piece of ED 2 at the size cap is 1,024 erases of 131,072 cells,
// in a single Write. The meter asks the stop function at least once an
// interval inside it, and the emulation stops at the first ask after the
// deadline, within one interval of it.
func TestReplayStopsInsideAnED2Flood(t *testing.T) {
	flood := bytes.Repeat([]byte("\x1b[2J"), piece/4)
	e := start(t, captureOf("x\r\n", event(1, 0, 512, 256)))
	deadline := time.Now().Add(100 * time.Millisecond)
	var asked []time.Time
	e.stop = func() bool {
		now := time.Now()
		asked = append(asked, now)
		return !now.Before(deadline)
	}

	err := e.Feed([][]byte{flood}, nil)
	returned := time.Now()
	require.ErrorIs(t, err, uio.ErrReplayDeadline)
	require.Greater(t, len(asked), 2, "the meter didn't ask inside the piece")
	require.False(t, asked[len(asked)-1].Before(deadline))
	require.True(t, asked[len(asked)-2].Before(deadline), "it went on after the stop function said stop")
	var longest time.Duration
	for i := 1; i < len(asked); i++ {
		longest = max(longest, asked[i].Sub(asked[i-1]))
	}
	t.Logf("asked %d times, at most %v apart; returned %v after the deadline", len(asked), longest, returned.Sub(deadline))
	require.LessOrEqual(t, returned.Sub(deadline), overshoot)
	requireHandoff(t, e, 3, 1)
}
