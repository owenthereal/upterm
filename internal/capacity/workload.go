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
	i := strings.Index(line, "CAP ")
	if i < 0 {
		return observation{}, false
	}
	fields := strings.Fields(line[i:])
	if len(fields) != 6 || (fields[1] != "I" && fields[1] != "H" && fields[1] != "R" && fields[1] != "A") {
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
		for {
			b := make([]byte, 128)
			_, err := io.ReadFull(in, b)
			if err != nil {
				failed <- err
				return
			}
			select {
			case received <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		if closer, ok := in.(io.Closer); ok {
			_ = closer.Close()
		}
		<-done
	}()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	seq := 0
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
			if len(b) > 4 && b[4] == 'R' {
				b[4] = 'A'
			}
			if _, err := out.Write(b); err != nil {
				return err
			}
		case now := <-tick.C:
			if active {
				if _, err := out.Write(frame("H", hostID, seq, now, 1024)); err != nil {
					return err
				}
				seq++
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
