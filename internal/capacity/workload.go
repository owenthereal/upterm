package capacity

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// A frame's entire fixed length is application payload: its header is 44
// bytes (including the following space), its final byte is LF, the rest 'x'.
func frame(kind string, id, seq int, at time.Time, size int) []byte {
	header := fmt.Sprintf("CAP %s %08d %08d %019d ", kind, id, seq, at.UnixNano())
	return []byte(header + strings.Repeat("x", size-len(header)-1) + "\n")
}

type observation struct {
	kind    string
	id, seq int
	sent    time.Time
}

func parseFrame(line string) (observation, bool) {
	// Reconstruction can end mid-row, placing old screen text before the
	// first fresh frame on this scan line. Only the final complete tag can be
	// that live frame; timestamp-bound challenges/barriers reject stale replay.
	i := strings.LastIndex(line, "CAP ")
	if i < 0 {
		return observation{}, false
	}
	fields := strings.Fields(line[i:])
	if len(fields) != 6 || (fields[1] != "I" && fields[1] != "H" && fields[1] != "R" && fields[1] != "A" && fields[1] != "Q" && fields[1] != "F" && fields[1] != "B") {
		return observation{}, false
	}
	id, e1 := strconv.Atoi(fields[2])
	seq, e2 := strconv.Atoi(fields[3])
	ns, e3 := strconv.ParseInt(fields[4], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return observation{}, false
	}
	return observation{fields[1], id, seq, time.Unix(0, ns)}, true
}

// Helper is the runner's harmless hosted command. It echoes fixed 128-byte
// input frames and, in active mode, emits exactly 1 KiB every ten seconds.
// It never starts a shell or interprets received text as a command.
func Helper(ctx context.Context, in io.Reader, out io.Writer, hostID int, active bool) error {
	return helper(ctx, in, out, hostID, active, 10*time.Second)
}
func helper(ctx context.Context, in io.Reader, out io.Writer, hostID int, active bool, outputInterval time.Duration) error {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(f.Fd()), state)
	}
	if _, err := io.WriteString(out, "CAP READY\n"); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	received := make(chan []byte)
	failed := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			i := strings.LastIndex(line, "CAP ")
			if i < 0 || len(line)-i != 127 {
				continue
			}
			o, ok := parseFrame(line[i:])
			if !ok || (o.kind != "I" && o.kind != "R" && o.kind != "Q" && o.kind != "F") {
				continue
			}
			b := []byte(line[i:] + "\n")
			select {
			case received <- b:
			case <-ctx.Done():
				return
			}
		}
		err := scanner.Err()
		if err == nil {
			err = io.EOF
		}
		failed <- err
	}()
	defer func() {
		cancel()
		if closer, ok := in.(io.Closer); ok {
			_ = closer.Close()
		}
		<-done
	}()
	started := time.Now()
	tick := time.NewTicker(outputInterval)
	defer tick.Stop()
	seq := 0
	quiesced := false
	emitDue := func(now time.Time) error {
		if active && !quiesced {
			due := int(now.Sub(started) / outputInterval)
			for seq < due {
				if _, err := out.Write(frame("H", hostID, seq, now, 1024)); err != nil {
					return err
				}
				seq++
			}
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case b := <-received:
			if o, ok := parseFrame(string(b)); ok && (o.kind == "Q" || o.kind == "F") {
				if err := emitDue(time.Now()); err != nil {
					return err
				}
				if o.kind == "F" {
					quiesced = true
				}
				if _, err := out.Write(frame("B", o.id, seq, o.sent, 128)); err != nil {
					return err
				}
				continue
			}
			if len(b) > 4 && b[4] == 'R' {
				b[4] = 'A'
			}
			if _, err := out.Write(b); err != nil {
				return err
			}
		case now := <-tick.C:
			if err := emitDue(now); err != nil {
				return err
			}
		}
	}
}

type sequenceTracker map[string]int

func (s sequenceTracker) observe(o observation) error {
	key := o.kind + ":" + strconv.Itoa(o.id)
	if last, ok := s[key]; ok && o.seq != last+1 {
		return fmt.Errorf("sequence gap/reordering %s: previous=%d current=%d", key, last, o.seq)
	}
	s[key] = o.seq
	return nil
}
func scanFrames(in io.Reader, consume func(observation) error, helperReady func(observation)) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {

		if o, ok := parseFrame(scanner.Text()); ok {
			if o.kind == "R" {
				continue
			}
			if o.kind == "A" {
				helperReady(o)
				continue
			}
			if err := consume(o); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}
func (r *runState) observe(tracker sequenceTracker, epochs map[string]int, o observation) error {
	if o.kind == "I" {
		r.clientsMu.RLock()
		if o.id < 0 || o.id/4 >= len(r.guests) {
			r.clientsMu.RUnlock()
			return errors.New("unknown input source")
		}
		peer := r.guests[o.id/4]
		r.clientsMu.RUnlock()
		peer.mu.Lock()
		generation, expected := peer.generation, peer.expected
		peer.mu.Unlock()
		key := "I:" + strconv.Itoa(o.id)
		if old, ok := epochs[key]; expected || !ok || old != generation {
			delete(tracker, key)
		}
		epochs[key] = generation
		if expected {
			return nil
		}
	}
	return tracker.observe(o)
}
