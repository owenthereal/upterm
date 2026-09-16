package httpproxy

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shrinkHeaderLimit lowers the response-header cap for the duration of a test,
// so the boundary can be exercised without moving 10 MiB.
func shrinkHeaderLimit(t *testing.T, n int64) {
	t.Helper()
	orig := maxResponseHeaderBytes
	maxResponseHeaderBytes = n
	t.Cleanup(func() { maxResponseHeaderBytes = orig })
}

// http.ReadResponse imposes no limit of its own, so without the cap a proxy
// streaming a header line that never terminates is buffered into memory until
// the deadline.
func TestDialRejectsAnOversizedCONNECTResponseHeader(t *testing.T) {
	shrinkHeaderLimit(t, 64)
	proxy := httpproxytest.StartRaw(t,
		"HTTP/1.1 200 Connection Established\r\nX-Pad: "+strings.Repeat("x", 512)+"\r\n\r\n")

	_, err := Dial(t.Context(), proxy.URL, "uptermd.example.com:22")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading CONNECT response")
}

// The cap covers the response header only. Left in place it would truncate the
// tunnel itself once that many bytes had crossed it — silently, and far from
// where the limit is written.
func TestDialDoesNotCapTheTunnel(t *testing.T) {
	const reply = "HTTP/1.1 200 Connection Established\r\n\r\n"
	body := strings.Repeat("upterm", 256)

	// Eight bytes past the header, so some of the body is already buffered and
	// the rest has to come from a reader whose limit must have been lifted.
	shrinkHeaderLimit(t, int64(len(reply))+8)
	proxy := httpproxytest.StartRaw(t, reply+body)

	conn, err := Dial(t.Context(), proxy.URL, "uptermd.example.com:22")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, len(body))
	n, err := io.ReadFull(conn, got)
	require.NoError(t, err, "tunnel truncated after %d of %d bytes", n, len(body))
	assert.Equal(t, body, string(got))
}
