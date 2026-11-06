package capacity

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTunnelProxyJoinsBothCopiesWhenEitherEndpointCloses(t *testing.T) {
	for _, side := range []string{"downstream", "upstream", "shutdown"} {
		t.Run(side, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			c := validConfig(t)
			c.Manifest.Targets[0].SSHURL = "ssh://" + ln.Addr().String()
			g := newGuard(c)
			p, err := newTunnelProxy(t.Context(), g, c.Manifest.Targets[0])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.close)
			client, err := net.Dial("tcp", p.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr()); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT failed: response=%v err=%v", response, err)
			}
			var upstream net.Conn
			select {
			case upstream = <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream was never connected")
			}
			t.Cleanup(func() { _ = upstream.Close() })
			joined := make(chan struct{})
			go func() { p.workers.Wait(); close(joined) }()
			switch side {
			case "downstream":
				_ = client.Close()
			case "upstream":
				_ = upstream.Close()
			case "shutdown":
				p.close()
			}
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("CONNECT handler remained blocked after one endpoint closed")
			}
			peer := upstream
			if side == "upstream" {
				peer = client
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("opposite silent endpoint was not released: %v", err)
			}
			g.mu.Lock()
			active, peak := g.active, g.peak
			g.mu.Unlock()
			p.mu.Lock()
			tracked := len(p.conns)
			p.mu.Unlock()
			if active != 0 || peak != 1 || tracked != 0 || len(g.gate) != 0 {
				t.Fatalf("tunnel leaked accounting/tracking/permit: active=%d peak=%d tracked=%d gate=%d", active, peak, tracked, len(g.gate))
			}
		})
	}
}

func TestParseFrameRequiresCompleteDeterministicPayload(t *testing.T) {
	at := time.Unix(1700000000, 123)
	for _, kind := range []string{"I", "H", "R", "A", "Q", "F", "B"} {
		t.Run(kind, func(t *testing.T) {
			size := 128
			if kind == "H" {
				size = 1024
			}
			line := strings.TrimSuffix(string(frame(kind, 7, 3, at, size)), "\n")
			for _, prefix := range []string{"", "old row\x1b[0m", "CAP I old partial row "} {
				for _, ending := range []string{"", "\n", "\r\n"} {
					o, ok := parseFrame(prefix + line + ending)
					if !ok || o.kind != kind || o.id != 7 || o.seq != 3 || !o.sent.Equal(at) {
						t.Fatalf("valid %d-byte frame rejected with prefix=%q ending=%q: %+v valid=%v", size, prefix, ending, o, ok)
					}
				}
			}
			for _, bad := range []struct{ name, line string }{
				{"truncated padding", line[:len(line)-1]},
				{"expanded padding", line + "x"},
				{"corrupt padding", line[:len(line)-1] + "y"},
				{"extra header space", strings.Replace(line, " 00000007", "  00000007", 1)},
				{"tab in header", strings.Replace(line, " 00000007", "\t00000007", 1)},
				{"short numeric field", strings.Replace(line, "00000007", "7", 1)},
				{"space in padding", line[:len(line)-1] + " "},
			} {
				t.Run(bad.name, func(t *testing.T) {
					if _, ok := parseFrame("old screen row" + bad.line); ok {
						t.Fatal("damaged payload was accepted as a complete frame")
					}
				})
			}
		})
	}
}

func TestCorruptOutputCannotAcknowledgeDelivery(t *testing.T) {
	// A valid header with one damaged padding byte used to acknowledge the
	// outstanding input and let completeDelivery return successfully.
	c := validConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	at := time.Unix(1700000000, 0)
	q := &guest{pending: map[string]time.Time{"0:3": at}, canary: true}
	r := &runState{cfg: c, ctx: ctx, rec: newRecorder(io.Discard, c), guests: []*guest{q}}
	damaged := frame("I", 0, 3, at, 128)
	damaged[126] = 'y'
	err := scanFrames(strings.NewReader(string(damaged)), func(o observation) error {
		if _, ok := q.acknowledge(o); ok {
			r.rec.summary.ReceivedFrames++
			r.actual(int64(frameLength(o.kind)))
		}
		return nil
	}, func(observation) { t.Error("corrupt input became readiness proof") })
	if err != io.EOF {
		t.Fatal(err)
	}
	if err := r.completeDelivery(); err == nil {
		t.Error("corrupt payload satisfied terminal delivery completion")
	}
	if len(q.pending) != 1 || r.rec.summary.ReceivedFrames != 0 || r.rec.summary.PayloadBytes != 0 {
		t.Fatalf("corrupt output inflated acknowledgments or nominal accounting: pending=%d received=%d bytes=%d", len(q.pending), r.rec.summary.ReceivedFrames, r.rec.summary.PayloadBytes)
	}
}

func TestCorruptHostedOutputCannotCompleteDelivery(t *testing.T) {
	c := faultHelper(t, "corrupt", "")
	c.DurationSeconds = 1
	s, err := Run(t.Context(), c, io.Discard)
	if s.EstablishedGuests != 1 || s.ActiveFrames != 1 {
		t.Fatalf("corrupt helper did not reach the steady workload: %+v err=%v", s, err)
	}
	if err == nil || s.DeliveryComplete {
		t.Fatalf("corrupt hosted output satisfied delivery completion: %+v err=%v", s, err)
	}
	if s.RTTCount != 1 || s.ReceivedFrames != 1 {
		t.Fatalf("corrupt output inflated delivered frames beyond the valid readiness input: %+v", s)
	}
	if !s.CleanupComplete {
		t.Fatal("corrupt delivery did not clean up")
	}
}
