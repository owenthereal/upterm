package command

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
	"github.com/owenthereal/upterm/ws"
)

// This real-socket control guards the cleanup classification used by proxy:
// a remote WebSocket close is a failure, whereas closing the owned socket
// locally releases Read with net.ErrClosed on this adapter.
func TestProxyWebSocketCloseClassification(t *testing.T) {
	for _, remote := range []bool{true, false} {
		name := "local"
		if remote {
			name = "remote"
		}
		t.Run(name, func(t *testing.T) {
			peer := make(chan *websocket.Conn, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err == nil {
					peer <- c
				}
			}))
			t.Cleanup(server.Close)
			u, err := url.Parse("ws://session@" + strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := ws.NewWSConn(u, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			other := <-peer
			t.Cleanup(func() { _ = other.Close() })
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			read := make(chan error, 1)
			go func() {
				_, err := conn.Read(make([]byte, 1))
				read <- err
			}()
			if remote {
				err = other.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), time.Now().Add(5*time.Second))
			} else {
				err = conn.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			err = <-read
			if remote {
				var closeErr *websocket.CloseError
				if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseNormalClosure || errors.Is(err, net.ErrClosed) {
					t.Fatalf("remote close = %T %v; want remote CloseError, not net.ErrClosed", err, err)
				}
			} else if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("local close = %T %v; want net.ErrClosed", err, err)
			}
		})
	}
}

type proxyTestRead struct {
	data string
	err  error
}

type proxyTestInput struct {
	entered chan struct{}
	results chan proxyTestRead
	release chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (r *proxyTestInput) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case result := <-r.results:
		return copy(p, result.data), result.err
	case <-r.release:
		return 0, io.EOF
	}
}

func (r *proxyTestInput) Close() error { r.closes.Add(1); return nil }

type proxyTestOutput struct {
	write  func([]byte) (int, error)
	closes atomic.Int32
}

func (w *proxyTestOutput) Write(p []byte) (int, error) { return w.write(p) }
func (w *proxyTestOutput) Close() error                { w.closes.Add(1); return nil }

type proxyTestConn struct {
	net.Conn
	readEntered  chan struct{}
	readExited   chan struct{}
	readResults  chan proxyTestRead
	writeEntered chan struct{}
	writeExited  chan struct{}
	closed       chan struct{}
	release      chan struct{}
	readOnce     sync.Once
	readExitOnce sync.Once
	writeOnce    sync.Once
	closeOnce    sync.Once
	closes       atomic.Int32
	writeErr     error
	blockWrite   bool
	holdRead     bool
}

func (c *proxyTestConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	defer c.readExitOnce.Do(func() { close(c.readExited) })
	closed := c.closed
	if c.holdRead {
		closed = nil
	}
	select {
	case result := <-c.readResults:
		return copy(p, result.data), result.err
	case <-closed:
		return 0, net.ErrClosed
	case <-c.release:
		return 0, net.ErrClosed
	}
}

func (c *proxyTestConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	defer close(c.writeExited)
	if c.blockWrite {
		select {
		case <-c.closed:
		case <-c.release:
		}
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *proxyTestConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type proxyTestFixture struct {
	input  *proxyTestInput
	output *proxyTestOutput
	conn   *proxyTestConn
}

func newProxyTestFixture() *proxyTestFixture {
	return &proxyTestFixture{
		input: &proxyTestInput{entered: make(chan struct{}), results: make(chan proxyTestRead, 1), release: make(chan struct{})},
		output: &proxyTestOutput{write: func(p []byte) (int, error) {
			return len(p), nil
		}},
		conn: &proxyTestConn{
			readEntered: make(chan struct{}), readExited: make(chan struct{}), readResults: make(chan proxyTestRead, 1),
			writeEntered: make(chan struct{}), writeExited: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{}),
		},
	}
}

// Every blocking fake operation has a fixture release independent of the
// production Close, so a broken ownership assertion still finishes on Fatal.
func (f *proxyTestFixture) release() {
	close(f.input.release)
	close(f.conn.release)
}

func (f *proxyTestFixture) start(hook func(proxyDirection)) <-chan error {
	done := make(chan error, 1)
	go func() {
		s := proxyStream{conn: f.conn, input: f.input, output: f.output, onCopyResult: hook}
		done <- s.run()
	}()
	return done
}

func proxyAssertClosed(t *testing.T, c <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-c:
	default:
		t.Fatalf("%s is still pending", name)
	}
}

func proxyResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	default:
		t.Fatal("proxy did not release its copy workers")
		return nil
	}
}

func TestProxyStreamOutcomes(t *testing.T) {
	inputErr := errors.New("ssh input failed")
	remoteErr := &websocket.CloseError{Code: websocket.CloseNormalClosure, Text: "remote"}
	for _, tc := range []struct {
		name      string
		input     *proxyTestRead
		relay     *proxyTestRead
		writeErr  error
		outputErr error
		both      bool
		first     proxyDirection
		want      error
	}{
		{name: "input EOF", input: &proxyTestRead{err: io.EOF}},
		{name: "input bytes and EOF", input: &proxyTestRead{data: "ssh", err: io.EOF}},
		{name: "remote WebSocket close", relay: &proxyTestRead{err: remoteErr}, want: remoteErr},
		{name: "input error", input: &proxyTestRead{err: inputErr}, want: inputErr},
		{name: "input context canceled", input: &proxyTestRead{err: context.Canceled}, want: context.Canceled},
		{name: "stdout EPIPE", relay: &proxyTestRead{data: "relay"}, outputErr: syscall.EPIPE, want: syscall.EPIPE},
		{name: "relay write reset", input: &proxyTestRead{data: "ssh"}, writeErr: syscall.ECONNRESET, want: syscall.ECONNRESET},
		{name: "EOF then failure recorded", input: &proxyTestRead{err: io.EOF}, relay: &proxyTestRead{err: remoteErr}, both: true, first: proxyToRelay, want: remoteErr},
		{name: "failure then EOF recorded", input: &proxyTestRead{err: io.EOF}, relay: &proxyTestRead{err: remoteErr}, both: true, first: proxyFromRelay, want: remoteErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newProxyTestFixture()
				defer f.release()
				f.conn.writeErr = tc.writeErr
				if tc.outputErr != nil {
					f.output.write = func([]byte) (int, error) { return 0, tc.outputErr }
				}
				recorded := make(chan proxyDirection, 2)
				gates := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
				if tc.both {
					defer func() {
						for _, gate := range gates {
							select {
							case <-gate:
							default:
								close(gate)
							}
						}
					}()
				}
				done := f.start(func(d proxyDirection) {
					recorded <- d
					if tc.both {
						<-gates[d]
					}
				})
				synctest.Wait()
				proxyAssertClosed(t, f.input.entered, "input read entered")
				proxyAssertClosed(t, f.conn.readEntered, "relay read entered")
				if tc.both {
					// Hold each actor after recording; both results must exist
					// before the selected first actor returns to run.Group.
					for _, d := range []proxyDirection{tc.first, 1 - tc.first} {
						if d == proxyToRelay {
							f.input.results <- *tc.input
						} else {
							f.conn.readResults <- *tc.relay
						}
						synctest.Wait()
						select {
						case got := <-recorded:
							if got != d {
								t.Fatalf("recorded direction = %v, want %v", got, d)
							}
						default:
							t.Fatal("copy result was not recorded")
						}
					}
					close(gates[tc.first])
					synctest.Wait()
					proxyAssertClosed(t, f.conn.closed, "owned close after first report")
					close(gates[1-tc.first])
				} else {
					if tc.input != nil {
						f.input.results <- *tc.input
					}
					if tc.relay != nil {
						f.conn.readResults <- *tc.relay
					}
				}
				synctest.Wait()
				if got := proxyResult(t, done); !errors.Is(got, tc.want) {
					t.Fatalf("proxy status error = %v, want %v", got, tc.want)
				}
			})
		})
	}
}

func TestProxyStreamKeepsIndependentErrorsDuringCleanup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		relay bool
		err   error
	}{
		{name: "stdout EPIPE", err: syscall.EPIPE},
		{name: "stdout context canceled", err: context.Canceled},
		{name: "relay context canceled", relay: true, err: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newProxyTestFixture()
				defer f.release()
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				defer releaseOnce.Do(func() { close(release) })
				if tc.relay {
					f.conn.holdRead = true
				} else {
					f.output.write = func([]byte) (int, error) {
						close(entered)
						<-release
						return 0, tc.err
					}
				}
				done := f.start(nil)
				synctest.Wait()
				proxyAssertClosed(t, f.input.entered, "input read entered")
				proxyAssertClosed(t, f.conn.readEntered, "relay read entered")
				if !tc.relay {
					f.conn.readResults <- proxyTestRead{data: "relay"}
					synctest.Wait()
					proxyAssertClosed(t, entered, "stdout write entered")
				}
				f.input.results <- proxyTestRead{err: io.EOF}
				synctest.Wait()
				proxyAssertClosed(t, f.conn.closed, "cleanup started")
				if tc.relay {
					f.conn.readResults <- proxyTestRead{err: tc.err}
				} else {
					// Keep the deferred release safe if an assertion fails.
					releaseOnce.Do(func() { close(release) })
				}
				synctest.Wait()
				if got := proxyResult(t, done); !errors.Is(got, tc.err) {
					t.Fatalf("independent error after cleanup = %v, want %v", got, tc.err)
				}
			})
		})
	}
	t.Run("input context canceled before seal", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newProxyTestFixture()
			defer f.release()
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			done := f.start(func(d proxyDirection) {
				if d == proxyToRelay {
					<-release
				}
			})
			synctest.Wait()
			proxyAssertClosed(t, f.input.entered, "borrowed input entered")
			f.conn.readResults <- proxyTestRead{err: io.EOF}
			synctest.Wait()
			proxyAssertClosed(t, f.conn.closed, "private cancellation started")
			// contextReader already returned its private cancellation, but the
			// underlying borrowed read reports a separate failure before join.
			f.input.results <- proxyTestRead{err: context.Canceled}
			synctest.Wait()
			releaseOnce.Do(func() { close(release) })
			synctest.Wait()
			if got := proxyResult(t, done); !errors.Is(got, context.Canceled) {
				t.Fatalf("borrowed input failure before seal = %v, want context.Canceled", got)
			}
		})
	})
}

func TestProxyStreamIgnoresItsOwnCleanupErrors(t *testing.T) {
	t.Run("owned close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newProxyTestFixture()
			defer f.release()
			f.conn.blockWrite = true
			done := f.start(nil)
			synctest.Wait()
			// EOF is recorded with the last bytes before the owned write blocks.
			f.input.results <- proxyTestRead{data: "last ssh bytes", err: io.EOF}
			synctest.Wait()
			proxyAssertClosed(t, f.conn.writeEntered, "relay write entered")
			f.conn.readResults <- proxyTestRead{err: io.EOF}
			synctest.Wait()
			if got := proxyResult(t, done); got != nil {
				t.Fatalf("owned-close errors changed EOF status: %v", got)
			}
		})
	})
	t.Run("private input cancellation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newProxyTestFixture()
			defer f.release()
			done := f.start(nil)
			synctest.Wait()
			proxyAssertClosed(t, f.input.entered, "borrowed input entered")
			f.conn.readResults <- proxyTestRead{err: io.EOF}
			synctest.Wait()
			if got := proxyResult(t, done); got != nil {
				t.Fatalf("private cancellation changed EOF status: %v", got)
			}
		})
	})
}

func TestProxyStreamOwnsOnlyTheConnection(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		name := "blocked relay read"
		if blockedWrite {
			name = "blocked relay write"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newProxyTestFixture()
				defer f.release()
				f.conn.blockWrite = blockedWrite
				recorded := make(chan proxyDirection, 2)
				done := f.start(func(d proxyDirection) { recorded <- d })
				synctest.Wait()
				proxyAssertClosed(t, f.input.entered, "input read entered")
				proxyAssertClosed(t, f.conn.readEntered, "relay read entered")
				if blockedWrite {
					f.input.results <- proxyTestRead{data: "ssh"}
					synctest.Wait()
					proxyAssertClosed(t, f.conn.writeEntered, "relay write entered")
					f.conn.readResults <- proxyTestRead{err: io.EOF}
				} else {
					f.input.results <- proxyTestRead{err: io.EOF}
				}
				synctest.Wait()
				if n := f.conn.closes.Load(); n != 1 {
					t.Fatalf("owned connection Close count = %d, want exactly 1", n)
				}
				if got := proxyResult(t, done); got != nil {
					t.Fatalf("cleanup-only result = %v", got)
				}
				proxyAssertClosed(t, f.conn.readExited, "owned read exited")
				if blockedWrite {
					proxyAssertClosed(t, f.conn.writeExited, "owned write exited")
				}
				if len(recorded) != 2 {
					t.Fatalf("completed copy workers = %d, want 2", len(recorded))
				}
				if f.input.closes.Load() != 0 || f.output.closes.Load() != 0 {
					t.Fatal("proxy closed a borrowed stream")
				}
			})
		})
	}
}

func TestProxyStreamSealsLateInputResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newProxyTestFixture()
		defer f.release()
		done := f.start(nil)
		synctest.Wait()
		proxyAssertClosed(t, f.input.entered, "borrowed input read entered")
		f.conn.readResults <- proxyTestRead{err: io.EOF}
		synctest.Wait()
		if got := proxyResult(t, done); got != nil {
			t.Fatalf("EOF status = %v", got)
		}
		// The borrowed operation may outlive run, but must be free to finish
		// without changing its already-returned status or racing its reader.
		f.input.results <- proxyTestRead{err: errors.New("late borrowed input error")}
		synctest.Wait()
	})
}
