package internal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// shortTempDir returns a directory a unix socket can actually be bound in.
// t.TempDir() on macOS hands out a /var/folders/<hash>/T/<TestName> path that
// is already past the 104-byte limit on sun_path before a filename is
// appended. Windows has no /tmp and its t.TempDir() is long for the same
// reason, so the temp root is used directly there.
func shortTempDir(t *testing.T) string {
	t.Helper()

	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	dir, err := os.MkdirTemp(base, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Test_AdminServer_ListenReportsABindFailure pins the half of the split that
// the host relies on: a socket that cannot be bound has to fail here, in the
// caller's own goroutine, rather than inside an actor where it would race the
// command's start and make the published reason a coin toss.
func Test_AdminServer_ListenReportsABindFailure(t *testing.T) {
	s := AdminServer{
		Session:    &api.GetSessionResponse{},
		ClientRepo: NewClientRepo(),
	}

	// A directory that does not exist, so the bind cannot succeed for a reason
	// that has nothing to do with timing.
	sock := filepath.Join(t.TempDir(), "no-such-directory", "admin.sock")
	require.Error(t, s.Listen(sock), "binding under a missing directory must fail")

	require.NoError(t, s.Shutdown(context.Background()),
		"a failed Listen leaves nothing to shut down")
}

// Test_AdminServer_ServeWithoutListenIsAnError keeps the other half honest:
// Serve must not quietly bind on the caller's behalf, because that is exactly
// the race the split removes.
func Test_AdminServer_ServeWithoutListenIsAnError(t *testing.T) {
	s := AdminServer{
		Session:    &api.GetSessionResponse{},
		ClientRepo: NewClientRepo(),
	}

	require.ErrorContains(t, s.Serve(context.Background()), "before Listen")
}

// Test_AdminServer_ListenSignalsBeforeServe is why the split is worth having:
// readiness is established by the bind, so it must be observable without any
// actor having run yet.
func Test_AdminServer_ListenSignalsBeforeServe(t *testing.T) {
	listening := make(chan struct{})
	s := AdminServer{
		Session:     &api.GetSessionResponse{},
		ClientRepo:  NewClientRepo(),
		OnListening: func() { close(listening) },
	}

	sock := filepath.Join(shortTempDir(t), "admin.sock")
	require.NoError(t, s.Listen(sock))
	select {
	case <-listening:
	default:
		t.Fatal("Listen returned without reporting that the socket is bound")
	}

	require.NoError(t, s.Shutdown(context.Background()))
}
