//go:build !windows

package internal

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestRootedSFTPLimitsSurviveSessionAndTransportReplacement(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	limits := &SFTPWriteLimits{Files: map[string]int64{"a": 8, "b": 8, "c": 8}, TotalBytes: 10}
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPRoot: root, SFTPWriteLimits: limits, SFTPAutoAccept: true})
	connection := h.guestClient(t)
	first, err := sftp.NewClient(connection)
	require.NoError(t, err)
	f, err := first.Create("a")
	require.NoError(t, err)
	// Changing the caller's configuration after serving cannot add allowance.
	limits.Files["extra"], limits.TotalBytes = 100, 100
	_, err = f.Write([]byte("abcdefgh"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, first.Close())
	second, err := sftp.NewClient(connection)
	require.NoError(t, err)
	_, err = second.Create("extra")
	require.Error(t, err)
	_, err = second.Create("a")
	require.Error(t, err, "new channel reset file-instance state")
	f, err = second.Create("b")
	require.NoError(t, err)
	_, err = f.Write([]byte("xy"))
	require.NoError(t, err)
	_, err = f.Write([]byte("z"))
	require.Error(t, err, "new channel reset aggregate accounting")
	require.NoError(t, f.Close())
	require.NoError(t, second.Close())
	require.NoError(t, connection.Close())
	third, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	defer func() { _ = third.Close() }()
	f, err = third.Create("c")
	require.NoError(t, err)
	_, err = f.Write([]byte("x"))
	require.Error(t, err, "new SSH transport reset aggregate accounting")
	require.NoError(t, f.Close())
	h.stop(t)
	require.NoError(t, h.srv.WaitSFTP(t.Context()))
}

// The capacity allowlist deliberately rejects arbitrary namespace names.
// Exercise the descriptor-rooted write path without that optional policy so
// its race protection cannot pass solely because of an allowlist denial.
func TestRootedSFTPNilLimitsConfinesWritesDuringNamespaceReplacement(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPRoot: root, SFTPAutoAccept: true})
	client, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "sentinel"), []byte("outside secret"), 0600))
	race, parked := filepath.Join(root.Name(), "race"), filepath.Join(root.Name(), "parked")
	require.NoError(t, os.Mkdir(race, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(race, "sentinel"), []byte("inside"), 0600))
	// A real successful writable control proves this reaches filesystem I/O.
	f, err := client.Create("race/created")
	require.NoError(t, err)
	_, err = f.Write([]byte("inside"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	control, err := root.ReadFile("race/created")
	require.NoError(t, err)
	require.Equal(t, "inside", string(control))
	require.NoError(t, client.Remove("race/created"))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			if err := os.Rename(race, parked); err != nil {
				done <- err
				return
			}
			if err := os.Symlink(outside, race); err != nil {
				done <- err
				return
			}
			if err := os.Remove(race); err != nil {
				done <- err
				return
			}
			if err := os.Rename(parked, race); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	defer func() { cancel(); require.NoError(t, <-done) }()
	for range 200 {
		if f, err := client.Open("race/sentinel"); err == nil {
			data, readErr := io.ReadAll(f)
			_ = f.Close()
			require.NoError(t, readErr)
			require.Equal(t, "inside", string(data))
		}
		if info, err := client.Stat("race/sentinel"); err == nil {
			require.EqualValues(t, 6, info.Size())
		}
		if infos, err := client.ReadDir("race"); err == nil {
			for _, info := range infos {
				if info.Name() == "sentinel" {
					require.EqualValues(t, 6, info.Size())
				}
			}
		}
		if f, err := client.Create("race/created"); err == nil {
			_, _ = f.Write([]byte("inside"))
			_ = f.Close()
		}
		_ = client.Remove("race/created")
	}
	_, err = os.Stat(filepath.Join(outside, "created"))
	require.True(t, os.IsNotExist(err), "a raced write escaped")
	data, err := os.ReadFile(filepath.Join(outside, "sentinel"))
	require.NoError(t, err)
	require.Equal(t, "outside secret", string(data))
	h.stop(t)
	require.NoError(t, h.srv.WaitSFTP(t.Context()))
}
