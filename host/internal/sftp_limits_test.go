package internal

import (
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func limitedSession(t *testing.T, root *os.Root, state *rootedSFTPWriteLimits) *SFTPSession {
	t.Helper()
	return &SFTPSession{root: root, writeLimits: state, autoAccept: true, ctx: t.Context(), logger: discardLogger()}
}

func openLimitedFile(s *SFTPSession, name string, flags uint32) (io.WriterAt, error) {
	r := sftp.NewRequest("Put", filepath.Join(s.root.Name(), name))
	r.Flags = flags
	return (&sftpFileWriter{session: s, logger: s.logger}).Filewrite(r)
}

// SFTP wire flags: WRITE | CREAT | TRUNC. Client.Create also sets READ;
// pkg/sftp still routes it to Filewrite for a write-only handler.
const limitedCreateFlags = 2 | 8 | 16

func TestRootedSFTPLimitsValidateBeforeServing(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	for _, tc := range []struct {
		name   string
		root   *os.Root
		limits *SFTPWriteLimits
	}{
		{"no root", nil, &SFTPWriteLimits{}},
		{"negative total", root, &SFTPWriteLimits{TotalBytes: -1}},
		{"negative file", root, &SFTPWriteLimits{Files: map[string]int64{"file": -1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{SFTPRoot: tc.root, SFTPWriteLimits: tc.limits}
			require.ErrorContains(t, s.ServeWithContext(t.Context(), nil, nil), "SFTPWriteLimits")
		})
	}
	for _, name := range []string{"", ".", "..", "../outside", "/absolute", "a/../file", "a//file", "file/", `a\file`, "file:stream", "NUL", "dir/COM1"} {
		_, err := CopySFTPWriteLimits(root, &SFTPWriteLimits{Files: map[string]int64{name: 1}, TotalBytes: 1})
		require.Error(t, err, "invalid policy name %q", name)
	}
	for _, limits := range []*SFTPWriteLimits{nil, {}, {Files: map[string]int64{"empty": 0}}, {Files: map[string]int64{"dir/file": 8}, TotalBytes: 8}} {
		copy, err := CopySFTPWriteLimits(root, limits)
		require.NoError(t, err)
		_, err = CopySFTPWriteLimits(root, copy)
		require.NoError(t, err, "a valid declaration remains canonical when copied again")
	}
}

func TestRootedSFTPLimitsShareExtentFileAndTotalBudgets(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	declaration := &SFTPWriteLimits{Files: map[string]int64{"a": 8, "b": 8}, TotalBytes: 10}
	state, err := newRootedSFTPWriteLimits(root, declaration)
	require.NoError(t, err)
	// Caller changes cannot enlarge a running host's immutable allowance.
	declaration.Files["a"], declaration.Files["unexpected"], declaration.TotalBytes = 100, 100, 100
	one, two := limitedSession(t, root, state), limitedSession(t, root, state)
	_, err = openLimitedFile(one, "unexpected", limitedCreateFlags)
	require.Error(t, err)
	a, err := openLimitedFile(one, "a", limitedCreateFlags)
	require.NoError(t, err)
	defer func() { _ = a.(io.Closer).Close() }()
	for _, offset := range []int64{-1, 8, math.MaxInt64} {
		n, err := a.WriteAt([]byte("x"), offset)
		require.Error(t, err)
		require.Zero(t, n)
	}
	n, err := a.WriteAt([]byte("efgh"), 4)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	n, err = a.WriteAt([]byte("abcd"), 0)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	n, err = a.WriteAt([]byte("x"), 0)
	require.Error(t, err, "overwriting does not replenish the per-file allowance")
	require.Zero(t, n)
	b, err := openLimitedFile(two, "b", limitedCreateFlags)
	require.NoError(t, err)
	defer func() { _ = b.(io.Closer).Close() }()
	n, err = b.WriteAt([]byte("xy"), 0)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = b.WriteAt([]byte("z"), 2)
	require.Error(t, err, "a second session cannot exceed the host aggregate")
	require.Zero(t, n)
	data, err := root.ReadFile("a")
	require.NoError(t, err)
	require.Equal(t, "abcdefgh", string(data))
	data, err = root.ReadFile("b")
	require.NoError(t, err)
	require.Equal(t, "xy", string(data), "denied aggregate write reached disk")
}

func TestRootedSFTPLimitsReserveBeforeConcurrentIO(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	state, err := newRootedSFTPWriteLimits(root, &SFTPWriteLimits{Files: map[string]int64{"a": 8, "b": 8, "c": 8}, TotalBytes: 10})
	require.NoError(t, err)
	var wg sync.WaitGroup
	accepted := make(chan int, 30)
	for _, name := range []string{"a", "b", "c"} {
		f, err := openLimitedFile(limitedSession(t, root, state), name, limitedCreateFlags)
		require.NoError(t, err)
		defer func() { _ = f.(io.Closer).Close() }()
		for range 10 {
			wg.Go(func() { n, _ := f.WriteAt([]byte("x"), 0); accepted <- n })
		}
	}
	wg.Wait()
	close(accepted)
	total := 0
	for n := range accepted {
		total += n
	}
	require.Equal(t, 10, total, "concurrent sessions exceeded the shared aggregate")
}

func TestRootedSFTPLimitsNeverRefundFailedWritesOrOpens(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	state, err := newRootedSFTPWriteLimits(root, &SFTPWriteLimits{Files: map[string]int64{"a": 2, "b": 2, "dir/file": 2}, TotalBytes: 2})
	require.NoError(t, err)
	s := limitedSession(t, root, state)
	_, err = openLimitedFile(s, "dir/file", limitedCreateFlags)
	require.Error(t, err, "missing parent should fail OPEN")
	require.NoError(t, root.Mkdir("dir", 0700))
	_, err = openLimitedFile(s, "dir/file", limitedCreateFlags)
	require.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied, "failed OPEN recycled a creation slot")
	f, err := openLimitedFile(s, "a", limitedCreateFlags)
	require.NoError(t, err)
	require.NoError(t, f.(io.Closer).Close())
	n, err := f.WriteAt([]byte("xx"), 0)
	require.Error(t, err, "underlying handle is closed")
	require.Zero(t, n)
	b, err := openLimitedFile(s, "b", limitedCreateFlags)
	require.NoError(t, err)
	defer func() { _ = b.(io.Closer).Close() }()
	n, err = b.WriteAt([]byte("x"), 0)
	require.ErrorIs(t, err, sftp.ErrSSHFxPermissionDenied, "failed I/O refunded the host budget")
	require.Zero(t, n)
}

func TestRootedSFTPLimitsKeepConsentAndRejectReopenModes(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	state, err := newRootedSFTPWriteLimits(root, &SFTPWriteLimits{Files: map[string]int64{"a": 8}, TotalBytes: 8})
	require.NoError(t, err)
	s := limitedSession(t, root, state)
	s.autoAccept = false
	_, err = openLimitedFile(s, "a", limitedCreateFlags)
	require.Error(t, err, "limits must not bypass consent")
	s.autoAccept, s.readOnly = true, true
	_, err = openLimitedFile(s, "a", limitedCreateFlags)
	require.Error(t, err, "limits must not bypass read-only")
	s.readOnly = false
	for _, flags := range []uint32{2, 2 | 16, limitedCreateFlags | 4, 8 | 16} {
		_, err = openLimitedFile(s, "a", flags)
		require.Error(t, err, "unsupported writable mode %d", flags)
	}
	f, err := openLimitedFile(s, "a", limitedCreateFlags|1)
	require.NoError(t, err, "normal Client.Create flags remain supported")
	require.NoError(t, f.(io.Closer).Close())
	_, err = openLimitedFile(s, "a", limitedCreateFlags)
	require.Error(t, err, "close recycled the creation slot")
	_, err = newRootedSFTPWriteLimits(root, nil)
	require.NoError(t, err)
	// A rooted host without limits retains ordinary writable reopen behavior.
	s = limitedSession(t, root, nil)
	f, err = openLimitedFile(s, "a", limitedCreateFlags)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("unrestricted"), 100)
	require.NoError(t, err)
	require.NoError(t, f.(io.Closer).Close())
	_, err = root.Stat("a")
	require.NoError(t, err)
}

func TestRootedSFTPLimitsRejectNontruncatingCreateOnExistingFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	for _, name := range []string{"existing", "truncate", "ordinary"} {
		require.NoError(t, root.WriteFile(name, []byte("123456789"), 0600))
	}
	state, err := newRootedSFTPWriteLimits(root, &SFTPWriteLimits{Files: map[string]int64{"existing": 8, "truncate": 8, "exclusive": 8}, TotalBytes: 24})
	require.NoError(t, err)
	s := limitedSession(t, root, state)
	f, openErr := openLimitedFile(s, "existing", 2|8) // WRITE | CREATE, neither TRUNC nor EXCL
	if f != nil {
		require.NoError(t, f.(io.Closer).Close())
	}
	data, err := root.ReadFile("existing")
	require.NoError(t, err)
	require.Equal(t, "123456789", string(data), "rejected mode must not perform I/O")
	// Both supported creation modes still provide a fresh bounded instance.
	f, err = openLimitedFile(s, "truncate", limitedCreateFlags|1)
	require.NoError(t, err, "Client.Create remains supported")
	info, err := root.Stat("truncate")
	require.NoError(t, err)
	require.Zero(t, info.Size())
	_, err = f.WriteAt([]byte("12345678"), 0)
	require.NoError(t, err)
	require.NoError(t, f.(io.Closer).Close())
	f, err = openLimitedFile(s, "exclusive", 2|8|32) // WRITE | CREATE | EXCL
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("12345678"), 0)
	require.NoError(t, err)
	require.NoError(t, f.(io.Closer).Close())
	// Optional limits do not change the existing rooted/nil-policy modes.
	f, err = openLimitedFile(limitedSession(t, root, nil), "ordinary", 2|8)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("x"), 9)
	require.NoError(t, err)
	require.NoError(t, f.(io.Closer).Close())
	info, err = root.Stat("ordinary")
	require.NoError(t, err)
	require.EqualValues(t, 10, info.Size())
	require.ErrorIs(t, openErr, sftp.ErrSSHFxPermissionDenied, "nontruncating create preserved an extent above its limit")
}
