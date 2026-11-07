package capacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Generate a large unfinished screen row without allocating that row. Keep
// readers alive at its end so the bound applies to resident, usable channels.
type heldFramePrefix struct {
	remaining int
	tail      *strings.Reader
	reached   chan struct{}
	release   chan struct{}
	once      sync.Once
	released  sync.Once
	maxRead   atomic.Int64
}

func (r *heldFramePrefix) Read(p []byte) (int, error) {
	for old := r.maxRead.Load(); int64(len(p)) > old; old = r.maxRead.Load() {
		if r.maxRead.CompareAndSwap(old, int64(len(p))) {
			break
		}
	}
	if r.remaining > 0 {
		n := min(len(p), r.remaining)
		for i := range n {
			p[i] = 'x'
		}
		r.remaining -= n
		return n, nil
	}
	r.once.Do(func() { close(r.reached) })
	<-r.release
	return r.tail.Read(p)
}

func (r *heldFramePrefix) Close() error {
	r.released.Do(func() { close(r.release) })
	return nil
}

func TestTerminalReadersKeepFixedBuffers(t *testing.T) {
	for _, helperInput := range []bool{false, true} {
		t.Run(fmt.Sprintf("helper=%t", helperInput), func(t *testing.T) {
			const channels = 4
			var observations atomic.Int64
			var wg sync.WaitGroup
			errors := make(chan error, channels)
			readers := make([]*heldFramePrefix, channels)
			t.Cleanup(func() {
				for _, r := range readers {
					if r != nil {
						_ = r.Close()
					}
				}
				wg.Wait()
			})
			for i := range readers {
				fresh := string(frame("I", i, 9, time.Unix(123, 456), 128))
				r := &heldFramePrefix{remaining: 600 << 10, tail: strings.NewReader(fresh), reached: make(chan struct{}), release: make(chan struct{})}
				readers[i] = r
				wg.Go(func() {
					if helperInput {
						var out bytes.Buffer
						err := helper(context.Background(), r, &out, 0, false, time.Hour)
						if err == nil && out.String() != "CAP READY\n"+fresh {
							err = fmt.Errorf("helper lost fresh frame: %q", out.String())
						}
						errors <- err
						return
					}
					err := scanFrames(r, func(o observation) error {
						observations.Add(1)
						if o.kind != "I" || o.seq != 9 {
							return fmt.Errorf("wrong fresh frame: %+v", o)
						}
						return nil
					}, func(observation) { observations.Add(1) })
					if err == io.EOF {
						err = nil
					}
					errors <- err
				})
			}
			for _, r := range readers {
				<-r.reached
				require.Zero(t, observations.Load(), "unfinished junk became a frame")
				if r.maxRead.Load() > 4096 {
					t.Errorf("terminal reader grew its read buffer to %d bytes", r.maxRead.Load())
				}
			}
			for _, r := range readers {
				_ = r.Close()
			}
			wg.Wait()
			close(errors)
			for err := range errors {
				require.NoError(t, err)
			}
			if !helperInput {
				require.EqualValues(t, channels, observations.Load())
			}
		})
	}
}

// A Reader may deliver its final bytes and error together or separately.
type terminalEndingReader struct {
	data     string
	end      error
	step     int
	withData bool
}

func (r *terminalEndingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.end
	}
	if r.step > 0 && len(p) > r.step {
		p = p[:r.step]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 && r.withData {
		return n, r.end
	}
	return n, nil
}

func TestTerminalFrameRawBoundaries(t *testing.T) {
	broken := errors.New("terminal read failed")
	for _, kind := range []string{"I", "H", "R", "A", "Q", "F", "B"} {
		for _, ending := range []string{"\n", "\r\n", "\r\r\n", "\r\r\r\n", "", "\r", "\r\r"} {
			for _, delta := range []int{-1, 0, 1} {
				for _, end := range []error{io.EOF, broken} {
					for _, together := range []bool{false, true} {
						name := fmt.Sprintf("%s/ending=%q/delta=%d/%v/together=%t", kind, ending, delta, end, together)
						t.Run(name, func(t *testing.T) {
							canonical := string(frame(kind, 3, 7, time.Unix(123, 456), frameLength(kind)))
							body := strings.TrimSuffix(canonical, "\n") + ending
							data := strings.Repeat("x", (1<<20)+delta-len(body)) + body
							reader := &terminalEndingReader{data: data, end: end, withData: together}
							var delivered, ready int
							err := scanFrames(reader, func(o observation) error { delivered++; return nil }, func(observation) { ready++ })
							terminated := strings.HasSuffix(ending, "\n")
							tooLong := delta > 0 || (delta == 0 && !terminated && !together)
							valid := !tooLong && ending != "\r\r\r\n"
							wantDelivered, wantReady := 0, 0
							if valid && kind == "A" {
								wantReady = 1
							}
							if valid && kind != "A" && kind != "R" {
								wantDelivered = 1
							}
							require.Equal(t, wantDelivered, delivered)
							require.Equal(t, wantReady, ready)
							if tooLong {
								require.ErrorContains(t, err, "token too long")
							} else {
								require.ErrorIs(t, err, end)
							}
						})
					}
				}
			}
		}
	}
}

func TestTerminalFrameSplitTagsAndFinalCanonicalPayload(t *testing.T) {
	for _, kind := range []string{"I", "H", "R", "A", "Q", "F", "B"} {
		for _, step := range []int{1, 2, 3, 127, 1024} {
			canonical := strings.TrimSuffix(string(frame(kind, 3, 7, time.Unix(123, 456), frameLength(kind))), "\n")
			for _, suffix := range []string{canonical, canonical + "x", canonical[:len(canonical)-1], canonical + "CAP bad", canonical[:len(canonical)-1] + "y"} {
				data := "CAP stale replay " + suffix + "\r\n"
				delivered, ready := 0, 0
				err := scanFrames(&terminalEndingReader{data: data, end: io.EOF, step: step}, func(observation) error { delivered++; return nil }, func(observation) { ready++ })
				require.ErrorIs(t, err, io.EOF)
				wantDelivered, wantReady := 0, 0
				if suffix == canonical && kind == "A" {
					wantReady = 1
				}
				if suffix == canonical && kind != "A" && kind != "R" {
					wantDelivered = 1
				}
				require.Equal(t, wantDelivered, delivered, "kind=%s step=%d", kind, step)
				require.Equal(t, wantReady, ready, "kind=%s step=%d", kind, step)
			}
		}
	}
}

func TestHelperFrameRawBoundaries(t *testing.T) {
	broken := errors.New("helper read failed")
	for _, kind := range []string{"I", "H", "R", "A", "Q", "F", "B"} {
		for _, ending := range []string{"\n", "\r\n", "\r\r\n", "", "\r", "\r\r"} {
			for _, delta := range []int{-1, 0, 1} {
				for _, end := range []error{io.EOF, broken} {
					for _, together := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%q/%d/%v/%t", kind, ending, delta, end, together), func(t *testing.T) {
							stamp := time.Unix(123, 456)
							body := strings.TrimSuffix(string(frame(kind, 3, 7, stamp, frameLength(kind))), "\n") + ending
							data := strings.Repeat("x", (1<<20)+delta-len(body)) + body
							var out bytes.Buffer
							err := helper(context.Background(), &terminalEndingReader{data: data, end: end, withData: together}, &out, 0, false, time.Hour)
							tooLong := delta > 0 || (delta == 0 && !strings.HasSuffix(ending, "\n") && !together)
							valid := !tooLong && ending != "\r\r\n" && ending != "\r\r"
							want := "CAP READY\n"
							if valid {
								switch kind {
								case "I":
									want += string(frame("I", 3, 7, stamp, 128))
								case "R":
									want += string(frame("A", 3, 7, stamp, 128))
								case "Q", "F":
									want += string(frame("B", 3, 0, stamp, 128))
								}
							}
							require.Equal(t, want, out.String())
							if tooLong {
								require.ErrorContains(t, err, "token too long")
							} else if end == io.EOF {
								require.NoError(t, err)
							} else {
								require.ErrorIs(t, err, end)
							}
						})
					}
				}
			}
		}
	}
}
