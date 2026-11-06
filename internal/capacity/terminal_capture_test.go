package capacity

import (
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// Capture the same concurrent admissions as the churn test, before parsing or
// terminal normalization. Keep diagnostics bounded and print only on failure.
func captureChurnTerminals(t *testing.T, c *Config) {
	t.Helper()
	var mu sync.Mutex
	var captures []*terminalCapture
	c.terminalIO = func(guest, channel, generation int, in io.WriteCloser, out io.Reader) (io.WriteCloser, io.Reader) {
		capture := &terminalCapture{name: fmt.Sprintf("guest=%d channel=%d generation=%d", guest, channel, generation), started: time.Now()}
		mu.Lock()
		captures = append(captures, capture)
		mu.Unlock()
		return terminalCaptureInput{in, capture}, io.TeeReader(out, terminalCaptureOutput{capture})
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, capture := range captures {
			capture.mu.Lock()
			t.Logf("terminal %s (last 16384 diagnostic bytes):\n%s", capture.name, capture.tail)
			capture.mu.Unlock()
		}
	})
}

type terminalCapture struct {
	mu      sync.Mutex
	name    string
	started time.Time
	tail    []byte
}

func (c *terminalCapture) record(direction string, p []byte) {
	line := fmt.Appendf(nil, "%s %s %q\n", time.Since(c.started), direction, p)
	c.mu.Lock()
	c.tail = append(c.tail, line...)
	if len(c.tail) > 16384 {
		c.tail = c.tail[len(c.tail)-16384:]
	}
	c.mu.Unlock()
}

type terminalCaptureInput struct {
	io.WriteCloser
	capture *terminalCapture
}

func (w terminalCaptureInput) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	w.capture.record("sent", p[:n])
	return n, err
}

type terminalCaptureOutput struct{ capture *terminalCapture }

func (w terminalCaptureOutput) Write(p []byte) (int, error) {
	w.capture.record("received", p)
	return len(p), nil
}
