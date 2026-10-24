package command

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync"

	"github.com/oklog/run"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/ws"
	"github.com/spf13/cobra"
)

func proxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy [flags] URL",
		Short: "Proxy a terminal session via WebSocket",
		Long: `Carry ssh's connection to a session over a WebSocket, as its ProxyCommand:
the SSH line of a host on a ws:// or wss:// relay runs it.

URL is the ws:// or wss:// URL in the ProxyCommand of the host's SSH line.
upterm join is the simpler way to join such a session: it takes the
connect string on the host's Join line, and needs no ssh options.

Exit status: 1 when it can't connect to the relay, including a usage or
configuration error. Once connected, 0 for end-of-input from ssh unless a
relay close or read or write failure is also reported; those failures take
precedence and give 1. Errors caused by proxy's own cleanup do not change
the result.`,
		Example: `  # A host shares a session over a WebSocket:
  upterm host --server wss://uptermd.upterm.dev

  # A guest joins with the SSH line the host prints, which runs upterm proxy:
  ssh -o ProxyCommand='upterm proxy wss://ID@uptermd.upterm.dev' ID@uptermd.upterm.dev:443

  # The simpler way:
  upterm join wss://ID@uptermd.upterm.dev`,
		Args: cobra.ExactArgs(1),
		RunE: proxyRunE,
	}

	cmd.Flags().StringVar(&flagProxy, "proxy", "", "HTTP proxy to reach the relay through (e.g. http://proxy.example.com:3128). Without it, HTTPS_PROXY/HTTP_PROXY are used.")

	return cmd
}

func proxyRunE(c *cobra.Command, args []string) error {
	u, err := url.Parse(args[0])
	if err != nil {
		return err
	}

	proxyURL, err := parseProxyURL(flagProxy)
	if err != nil {
		return err
	}

	conn, err := ws.NewWSConn(u, true, proxyURL)
	if err != nil {
		return err
	}

	return (&proxyStream{conn: conn, input: os.Stdin, output: os.Stdout}).run()
}

type proxyDirection uint8

const (
	proxyToRelay proxyDirection = iota
	proxyFromRelay
)

type proxyStream struct {
	conn         net.Conn
	input        io.Reader
	output       io.Writer
	onCopyResult func(proxyDirection)
}

// proxyOutcomes is sealed once the copy workers join. An abandoned borrowed
// input read can finish later, but cannot change the status already returned.
type proxyOutcomes struct {
	mu          sync.Mutex
	closed      bool
	sealed      bool
	inputResult error
	copyResults [2]error
}

func (s *proxyStream) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var outcomes proxyOutcomes
	var closeOnce sync.Once
	cleanup := func(error) {
		closeOnce.Do(func() {
			outcomes.mu.Lock()
			outcomes.closed = true
			outcomes.mu.Unlock()
			_ = s.conn.Close()
			cancel()
		})
	}
	finish := func(direction proxyDirection, err error) error {
		outcomes.mu.Lock()
		// Every input-read and relay-write error is tagged at its source.
		// Only the private contextReader can return an untagged cancellation
		// to this copy; an independent context.Canceled remains a failure.
		if direction == proxyToRelay && err == context.Canceled {
			err = nil
		}
		owned := direction == proxyFromRelay
		if source, ok := err.(*proxySourceError); ok {
			err, owned = source.err, source.owned
		}
		// Only this owner closes the connection. Remote WebSocket closes and
		// resets have different errors; borrowed stream errors stay failures.
		if owned && outcomes.closed && errors.Is(err, net.ErrClosed) {
			err = nil
		}
		outcomes.copyResults[direction] = err
		outcomes.mu.Unlock()
		if s.onCopyResult != nil {
			s.onCopyResult(direction)
		}
		return err
	}
	var g run.Group
	g.Add(func() error {
		input := proxyInputReader{reader: s.input, outcomes: &outcomes}
		_, err := io.Copy(proxySourceWriter{writer: s.conn, owned: true}, uio.NewContextReader(ctx, input))
		return finish(proxyToRelay, err)
	}, cleanup)
	g.Add(func() error {
		// The owned connection is read directly: private reader cancellation
		// must not swallow a remote close or read error during cleanup.
		_, err := io.Copy(proxySourceWriter{writer: s.output}, s.conn)
		return finish(proxyFromRelay, err)
	}, cleanup)
	_ = g.Run() // join both actors; first-finisher ordering does not choose status
	outcomes.mu.Lock()
	defer outcomes.mu.Unlock()
	outcomes.sealed = true
	if err := outcomes.inputResult; err != nil && err != io.EOF {
		return err
	}
	for _, err := range outcomes.copyResults {
		if err != nil {
			return err
		}
	}
	return nil
}

// Tag source errors before contextReader's result/cancellation selection so a
// private cancellation cannot be confused with a borrowed read or relay write.
type proxySourceError struct {
	err   error
	owned bool
}

func (e *proxySourceError) Error() string { return e.err.Error() }
func (e *proxySourceError) Unwrap() error { return e.err }

type proxyInputReader struct {
	reader   io.Reader
	outcomes *proxyOutcomes
}

func (r proxyInputReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil {
		r.outcomes.mu.Lock()
		if !r.outcomes.sealed {
			r.outcomes.inputResult = err
		}
		r.outcomes.mu.Unlock()
		if err != io.EOF {
			err = &proxySourceError{err: err}
		}
	}
	return n, err
}

type proxySourceWriter struct {
	writer io.Writer
	owned  bool
}

func (w proxySourceWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		err = &proxySourceError{err: err, owned: w.owned}
	}
	return n, err
}
