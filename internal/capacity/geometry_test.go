package capacity

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Record the actual child terminal before the first guest can resize it.
func runGeometryHelper(report string, in *os.File, out io.Writer) error {
	writeSize := func(suffix string) error {
		cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return err
		}
		return os.WriteFile(report+suffix, fmt.Appendf(nil, "%dx%d", cols, rows), 0600)
	}
	if err := writeSize("-startup"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "geometry" {
			if err := writeSize("-after"); err != nil {
				return err
			}
			continue
		}
		if observation, ok := parseFrame(line); ok {
			kind := observation.kind
			if kind == "Q" {
				kind = "B"
			}
			if _, err := out.Write(frame(kind, observation.id, observation.seq, observation.sent, 128)); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

type geometryOutput struct {
	mu      sync.Mutex
	data    bytes.Buffer
	changed chan struct{}
}

func (o *geometryOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.data.Write(p)
	select {
	case o.changed <- struct{}{}:
	default:
	}
	return n, err
}

func geometryHasMarker(data, marker []byte) bool {
	rows := bytes.Split(data, []byte{'\n'})
	for _, row := range rows[:len(rows)-1] {
		row = bytes.TrimSuffix(row, []byte{'\r'})
		if start := bytes.LastIndex(row, []byte("CAP ")); start >= 0 && bytes.Equal(row[start:], marker) {
			return true
		}
	}
	return false
}

func TestGeometryOutputMarker(t *testing.T) {
	// Captured from Windows CI run 42174271728, job 127748995046.
	const prefix = "\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[H"
	const marker = "CAP I 00000314 00000007 1793946543794605400 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	for _, tc := range []struct {
		name   string
		output string
		want   bool
	}{
		{"captured Windows prefix", prefix + marker + "\r\n", true},
		{"plain LF", marker + "\n", true},
		{"plain CRLF", marker + "\r\n", true},
		{"corrupt padding", prefix + marker[:len(marker)-1] + "y\r\n", false},
		{"corrupt header", prefix + "CAP B" + marker[5:] + "\r\n", false},
		{"wrong timestamp", prefix + marker[:24] + "1793946543794605401" + marker[43:] + "\r\n", false},
		{"trailing data", prefix + marker + "extra\r\n", false},
		{"trailing erase", prefix + marker + "\x1b[K\r\n", false},
		{"incomplete LF framing", prefix + marker + "\r", false},
		{"later mismatched CAP", prefix + marker + "CAP I 00000314 00000008 1793946543794605400\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := geometryHasMarker([]byte(tc.output), []byte(marker)); got != tc.want {
				t.Fatalf("geometryHasMarker(%q) = %t, want %t", tc.output, got, tc.want)
			}
		})
	}
}

func (o *geometryOutput) wait(t *testing.T, marker []byte) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		o.mu.Lock()
		found := geometryHasMarker(o.data.Bytes(), marker)
		o.mu.Unlock()
		if found {
			return
		}
		select {
		case <-o.changed:
		case <-timer.C:
			o.mu.Lock()
			data := o.data.Bytes()
			start := max(0, len(data)-4096)
			diagnostic := fmt.Sprintf("helper response missing: marker=%q output_bytes=%d marker_offset=%d output_tail[%d:]=%q",
				marker, len(data), bytes.Index(data, marker), start, data[start:])
			o.mu.Unlock()
			t.Fatal(diagnostic)
		}
	}
}

func waitGeometryFile(t *testing.T, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		if err := pause(ctx, 10*time.Millisecond); err != nil {
			t.Fatal("helper geometry report missing")
		}
	}
}

func TestCapacityHelperStartsPinnedAndDoesNotRepaintOnJoin(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "geometry")
			c := faultHelper(t, "geometry", report)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			ctx, cancel := context.WithCancelCause(t.Context())
			dir, err := os.MkdirTemp("", "capgeo-")
			if err != nil {
				t.Fatal(err)
			}
			r := &runState{cfg: c, ctx: ctx, cancel: cancel, guard: newGuard(c), rec: newRecorder(io.Discard, c), helper: c.HelperExecutable, dir: dir, hosts: make([]*hostRun, 1), guestIdentity: signer(t)}
			t.Cleanup(func() {
				if err := r.cleanup(); err != nil {
					t.Error(err)
				}
			})
			target := c.Manifest.Targets[0]
			if err := r.startHost(0, target, nil); err != nil {
				t.Fatal(err)
			}
			if got := waitGeometryFile(t, report+"-startup"); got != "2048x100" {
				t.Errorf("startup geometry = %s, want 2048x100", got)
			}
			endpoint, err := transport(target, ws, 0, 1, false)
			if err != nil {
				t.Fatal(err)
			}
			proxy, err := newTunnelProxy(ctx, r.guard, target)
			if err != nil {
				t.Fatal(err)
			}
			r.proxies = append(r.proxies, proxy)
			connect := func(cols, rows int) (*ssh.Session, io.WriteCloser, *geometryOutput) {
				attempt, end := context.WithTimeout(ctx, 5*time.Second)
				defer end()
				client, raw, err := openGuest(attempt, r.guard, target, endpoint, r.hosts[0].initial, r.guestIdentity, proxy)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close(); _ = raw.Close() })
				sess, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				if err := sess.RequestPty("dumb", rows, cols, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
					t.Fatal(err)
				}
				in, err := sess.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				out := &geometryOutput{changed: make(chan struct{}, 1)}
				sess.Stdout, sess.Stderr = out, io.Discard
				if err := sess.Shell(); err != nil {
					t.Fatal(err)
				}
				return sess, in, out
			}
			_, first, output := connect(2048, 100)
			stamp := time.Now()
			marker := frame("I", 314, 7, stamp, 128)
			if _, err := first.Write(marker); err != nil {
				t.Fatal(err)
			}
			output.wait(t, marker[:127])
			second, _, _ := connect(80, 24)
			if err := second.WindowChange(31, 90); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(first, "geometry\n"); err != nil {
				t.Fatal(err)
			}
			if got := waitGeometryFile(t, report+"-after"); got != "2048x100" {
				t.Errorf("joined/resized geometry = %s, want 2048x100", got)
			}
			barrier := frame("Q", 314, 8, stamp, 128)
			if _, err := first.Write(barrier); err != nil {
				t.Fatal(err)
			}
			output.wait(t, frame("B", 314, 8, stamp, 128)[:127])
			output.mu.Lock()
			count := bytes.Count(output.data.Bytes(), marker[:127])
			captured := output.data.String()
			output.mu.Unlock()
			if count != 1 {
				t.Fatalf("one-time marker rendered %d times: %q", count, captured)
			}
		})
	}
}
