package capacity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestCapacityZeroTransferRejectsSFTP(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			r := admittedRun(t, c)
			client, err := sftp.NewClient(r.guests[0].client)
			if err == nil {
				_ = client.Close()
				t.Fatal("zero-transfer host admitted SFTP")
			}
		})
	}
}

func TestCapacitySFTPCancellationClosesWorkersBeforeRoot(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			var root *os.Root
			t.Cleanup(func() {
				if root != nil {
					_, err := root.Stat(".")
					require.Error(t, err, "cleanup did not close the joined root")
				}
			})
			r := admittedRun(t, c)
			h := r.hosts[0]
			root = h.h.SFTPRoot
			client, err := sftp.NewClient(r.guests[0].client)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			file, err := client.Create("open-during-cancel")
			require.NoError(t, err)
			defer func() { _ = file.Close() }()
			_, err = file.Write([]byte("pending transfer"))
			require.NoError(t, err)
			r.cancel(context.Canceled)
			select {
			case err := <-h.done:
				h.done <- err
			case <-time.After(8 * time.Second):
				t.Fatal("host cancellation did not finish promptly")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			require.NoError(t, h.h.WaitSFTP(ctx))
			_, err = root.Stat(".")
			require.NoError(t, err, "host took ownership of caller's root")
			_, err = file.Write([]byte("late"))
			require.Error(t, err, "open handle survived joined cancellation")
		})
	}
}

func TestCapacityRetainsRootWhenQuiescenceCannotBeProved(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	ctx, cancel := context.WithCancelCause(t.Context())
	h := &hostRun{h: &host.Host{SFTPRoot: root}, started: true, done: make(chan error, 1)}
	// A completion notification without the matching Host lifecycle is not
	// proof that its rooted workers have stopped. WaitSFTP must reject it.
	h.done <- nil
	r := &runState{ctx: ctx, cancel: cancel, hosts: []*hostRun{h}, dir: dir, rec: newRecorder(io.Discard, Config{})}
	require.ErrorContains(t, r.cleanup(), "retained transfer root and directory")
	_, err = root.Stat(".")
	require.NoError(t, err)
	_, err = os.Stat(dir)
	require.NoError(t, err)
	require.False(t, r.rec.summary.CleanupComplete)
}

func TestCapacitySFTPConfinesContentAndMetadata(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			q := r.guests[0]
			client, err := sftp.NewClient(q.client)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			outsideDir := t.TempDir()
			outside := filepath.Join(outsideDir, "sentinel")
			payload := []byte("outside private contents")
			if err := os.WriteFile(outside, payload, 0600); err != nil {
				t.Fatal(err)
			}
			control := filepath.Join(filepath.Dir(q.host.socket), "control-secret")
			if err := os.WriteFile(control, payload, 0600); err != nil {
				t.Fatal(err)
			}
			inside := filepath.Join(q.host.h.CommandDir, "allowed")
			f, err := client.Create(inside)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("inside")); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Stat(); err != nil {
				t.Fatal(err)
			}
			if err := f.Chmod(0600); err == nil {
				t.Error("handle setstat was allowed")
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			f, err = client.Open("allowed")
			if err != nil {
				t.Error(err)
			} else {
				got, readErr := io.ReadAll(f)
				_ = f.Close()
				if readErr != nil || string(got) != "inside" {
					t.Errorf("relative in-root contents: %q, %v", got, readErr)
				}
			}
			for _, path := range []string{outside, control, q.host.socket, "../control-secret", "../../h0/control-secret", inside + ":stream", filepath.Join(q.host.h.CommandDir, "NUL")} {
				t.Run(path, func(t *testing.T) {
					if f, err := client.Open(path); err == nil {
						_ = f.Close()
						t.Error("outside/special open succeeded")
					}
					if f, err := client.Create(path); err == nil {
						_ = f.Close()
						t.Error("outside/special create succeeded")
					}
					if _, err := client.Stat(path); err == nil {
						t.Error("outside/special stat succeeded")
					}
					if _, err := client.Lstat(path); err == nil {
						t.Error("outside/special lstat succeeded")
					}
				})
			}
			if _, err := client.ReadDir(outsideDir); err == nil {
				t.Error("outside directory enumerated")
			}
			if err := client.Remove(outside); err == nil {
				t.Error("outside remove succeeded")
			}
			emptyDir := filepath.Join(q.host.h.CommandDir, "empty")
			require.NoError(t, os.Mkdir(emptyDir, 0700))
			require.Error(t, client.RemoveDirectory(emptyDir), "rmdir is unsupported")
			require.NoError(t, client.Remove(emptyDir), "Root.Remove also permits an empty in-root directory")
			_, err = client.RealPath(outside)
			require.Error(t, err)
			_, err = client.RealPath(".")
			require.NoError(t, err)
			for name, operation := range map[string]func() error{
				"mkdir":        func() error { return client.Mkdir(filepath.Join(q.host.h.CommandDir, "newdir")) },
				"rename":       func() error { return client.Rename(inside, inside+"-moved") },
				"posix rename": func() error { return client.PosixRename(inside, inside+"-moved") },
				"symlink":      func() error { return client.Symlink(outside, filepath.Join(q.host.h.CommandDir, "link")) },
				"hardlink":     func() error { return client.Link(outside, filepath.Join(q.host.h.CommandDir, "hardlink")) },
				"setstat":      func() error { return client.Truncate(inside, 0) },
				"readlink":     func() error { _, err := client.ReadLink("link"); return err },
				"statvfs":      func() error { _, err := client.StatVFS(inside); return err },
			} {
				t.Run(name, func(t *testing.T) {
					if err := operation(); err == nil {
						t.Error("unsupported operation was allowed")
					}
				})
			}
			if data, err := os.ReadFile(outside); err != nil || !bytes.Equal(data, payload) {
				t.Errorf("outside changed: %q, %v", data, err)
			}
			if data, err := os.ReadFile(control); err != nil || !bytes.Equal(data, payload) {
				t.Errorf("control file changed: %q, %v", data, err)
			}
		})
	}
}
