package replay

import (
	"cmp"
	"encoding/binary"
	"errors"
	"flag"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// fuzzWait is the deadline each of FuzzReplay's replays gets: short, so that
// an input that would run long meets it, and how far past it the replay runs
// is measured.
const fuzzWait = 50 * time.Millisecond

// fuzzScale stretches a timing bound while fuzzing: the fuzzer runs a worker
// per CPU, so a replay that reaches its deadline shares the machine with the
// other workers' and waits its turn to stop. Without fuzzing, as when the
// seed corpus runs as an ordinary test, it is 1. Work the meter doesn't stop
// still overshoots by far more, and the meter's own stopping is checked by
// counting its asks, with no clock.
func fuzzScale() time.Duration {
	for _, name := range []string{"test.fuzz", "test.fuzzworker"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" && f.Value.String() != "false" {
			return time.Duration(runtime.GOMAXPROCS(0))
		}
	}
	return 1
}

// fuzzCase is the case FuzzReplay's input describes: the stream cut at cut,
// what follows the cut its suffix; an event for each four bytes of events,
// an offset into the prefix, then the columns and the rows, in order of
// offset, the first moved to 0, or 80x24 for none; and Start offered split's
// fraction of the prefix, a Feed the rest.
func fuzzCase(stream []byte, cut uint32, split uint16, events []byte) contCase {
	p := int(cut % uint32(len(stream)+1))
	c := contCase{prefix: stream[:p:p], suffix: stream[p:]}
	for ; len(events) >= 4; events = events[4:] {
		c.sizes = append(c.sizes, uio.SizeEvent{
			Offset: uint64(int(binary.BigEndian.Uint16(events)) % (p + 1)),
			Size:   termsize.Size{Cols: 1 + int(events[2])%160, Rows: 1 + int(events[3])%60},
		})
	}
	if len(c.sizes) == 0 {
		c.sizes = []uio.SizeEvent{{Size: termsize.Size{Cols: 80, Rows: 24}}}
	}
	slices.SortStableFunc(c.sizes, func(a, b uio.SizeEvent) int { return cmp.Compare(a.Offset, b.Offset) })
	c.sizes[0].Offset = 0
	renumber(c.sizes)
	if s := int(split) * p / 0xffff; s > 0 && s < p {
		c.offers = []int{s, p}
	}
	return c
}

// bounded replays c as a join does, at the budget a join has and with
// fuzzWait to its deadline, and says how long it took.
func (c contCase) bounded() (render []byte, elapsed time.Duration, err error) {
	began := time.Now()
	em, err := c.replay(began.Add(fuzzWait))
	if err == nil {
		render, err = em.Render()
	}
	return render, time.Since(began), err
}

// fuzzEvents encodes sizes as fuzzCase decodes them.
func fuzzEvents(sizes []uio.SizeEvent) []byte {
	var b []byte
	for _, ev := range sizes {
		b = binary.BigEndian.AppendUint16(b, uint16(ev.Offset))
		b = append(b, byte(ev.Size.Cols-1), byte(ev.Size.Rows-1))
	}
	return b
}

// FuzzReplay mutates the stream, where it is cut and its size events. No
// panic escapes Start, Feed or Render; the render is at most
// DefaultReplayBytes; the replay returns by its deadline and 10 ms; and the
// property holds: a terminal given the render, the deferred tail and the
// rest of the stream is in the state of the one given the whole stream.
//
// A disagreement between the tracker and the emulator is a fallback here,
// as it is in the host, and not a failure, as it is in the property test:
// the fuzzer reaches bytes the tracker leaves out by design, such as 8-bit
// C1 introducers and a CSI past its 64 bytes, where the emulator acts and the
// tracker doesn't, and the replay detecting that and falling back is right.
func FuzzReplay(f *testing.F) {
	for i := range 8 {
		rnd := rand.New(rand.NewPCG(*propertySeed, 1<<33|uint64(i)))
		stream, sizes := genStream(rnd)
		cut := rnd.IntN(len(stream) + 1)
		f.Add(stream, uint32(cut), uint16(rnd.Uint32()), fuzzEvents(sizes[:eventsUpTo(sizes, cut)]))
	}
	f.Add([]byte("x\x1b[100000000b\nmore"), uint32(17), uint16(0), fuzzEvents([]uio.SizeEvent{event(1, 0, 160, 60)}))
	f.Add([]byte("abc\x1b[1;\nxyz"), uint32(7), uint16(0x8000), []byte{0, 0, 79, 23, 0, 3, 39, 23})
	f.Add([]byte("text\r\ne\u0301 \U0001F468\u200d\U0001F469"), uint32(15), uint16(0), []byte(nil))
	f.Fuzz(func(t *testing.T, stream []byte, cut uint32, split uint16, events []byte) {
		if len(stream) > 64<<10 {
			return
		}
		c := fuzzCase(stream, cut, split, events)

		// The bounds, at the budget a join has. Wall time counts whatever
		// else the machine runs, and the fuzzer runs a worker per CPU, so a
		// replay that runs past its deadline is run again, and fails only if
		// it does every time: work the meter doesn't stop overshoots on every
		// run, and a stall of the process on one.
		limit := fuzzWait + 10*time.Millisecond*timeScale*fuzzScale()
		render, elapsed, err := c.bounded()
		for runs := 1; elapsed > limit && runs < 3; runs++ {
			render, elapsed, err = c.bounded()
		}
		require.LessOrEqual(t, len(render), uio.DefaultReplayBytes)
		require.LessOrEqual(t, elapsed, limit, "the replay ran past its deadline: %v", err)
		require.NotErrorIs(t, err, ErrHandoffInvariant)
		if errors.Is(err, uio.ErrReplayDeadline) {
			return
		}

		// The property, with the history kept whole.
		setBudget(t, 64<<20)
		r := c.run(time.Second)
		if errors.Is(r.bug, ErrTrackerDisagrees) {
			return
		}
		if fail := r.failure(); fail != "" {
			t.Fatalf("%s\n%s", fail, c.repro())
		}
	})
}

// FuzzReplayGenerated is the property, fuzzed through the generator: the
// fuzzer's bytes drive genCase, the stream, its cut, its suffix and io's
// offers, so every case stays in the vocabulary the tracker and the emulator
// both read. There, as in the property test, the two disagreeing, or a
// handoff point that carries a cluster, fails it, where FuzzReplay's raw
// bytes reach what the tracker leaves out by design.
func FuzzReplayGenerated(f *testing.F) {
	for i := range 8 {
		rnd := rand.New(rand.NewPCG(*propertySeed, 1<<35|uint64(i)))
		b := make([]byte, 64)
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, entropy []byte) {
		setBudget(t, 64<<20)
		c := genCase(rand.New(newFuzzSource(entropy)))
		if fail := c.run(time.Minute).failure(); fail != "" {
			t.Fatalf("%s\n%s", fail, c.repro())
		}
	})
}

// fuzzSource is a rand.Source that draws from the fuzzer's bytes while they
// last, eight to a number, and then from a PCG seeded by them, so a mutated
// input changes the stream genStream writes where the mutated bytes are
// drawn, and every input writes one to its end.
type fuzzSource struct {
	b   []byte
	pcg *rand.PCG
}

func newFuzzSource(b []byte) *fuzzSource {
	var seed [16]byte
	for i, c := range b {
		seed[i%len(seed)] ^= c
		seed[(i+7)%len(seed)] += c
	}
	return &fuzzSource{b: b, pcg: rand.NewPCG(binary.LittleEndian.Uint64(seed[:8]), binary.LittleEndian.Uint64(seed[8:]))}
}

func (s *fuzzSource) Uint64() uint64 {
	if len(s.b) == 0 {
		return s.pcg.Uint64()
	}
	var n [8]byte
	k := copy(n[:], s.b)
	s.b = s.b[k:]
	return binary.LittleEndian.Uint64(n[:])
}

// FuzzTrackerSnapshot is the priming property, fuzzed: the fuzzer's bytes
// drive genStream, so its streams stay within the vocabulary both the
// tracker and the emulator read, and pick the ring.
func FuzzTrackerSnapshot(f *testing.F) {
	for i := range 4 {
		rnd := rand.New(rand.NewPCG(*propertySeed, 1<<34|uint64(i)))
		b := make([]byte, 64)
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		f.Add(b, uint16(rnd.Uint32()))
	}
	f.Fuzz(func(t *testing.T, entropy []byte, ring uint16) {
		stream, sizes := genStream(rand.New(newFuzzSource(entropy)))
		requirePrimes(t, stream, sizes, 64+int(ring)%(8<<10), "the stream the input drew")
	})
}
