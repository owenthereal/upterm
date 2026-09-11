package internal

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// recordingWriter accumulates what it is given. The drain runs on its own
// goroutine, so every field is read under the mutex.
type recordingWriter struct {
	mu      sync.Mutex
	written []byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	return len(p), nil
}

func (r *recordingWriter) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.written)
}

// A guest that reaches the door after the fan-out has quiesced is refused, and
// the sink built for it must not outlive the attempt.
//
// The assertion is on the sink, not on the error: checking only ErrClosed would
// pass just as happily with the release deleted. A closed sink refuses writes,
// which is the observable consequence of its goroutine being released.
func TestAttachGuestOutputReleasesTheSinkWhenRefused(t *testing.T) {
	writers := uio.NewMultiWriter(5)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, writers.Shutdown(ctx))

	var out recordingWriter
	sink := uio.NewAsyncWriter(&out, uio.DefaultGuestBufferSize, nil)

	require.ErrorIs(t, attachGuestOutput(writers, sink), uio.ErrClosed)

	_, err := sink.Write([]byte("output"))
	require.ErrorIs(t, err, uio.ErrWriterClosed,
		"a refused attach must release the sink it was given")
}
