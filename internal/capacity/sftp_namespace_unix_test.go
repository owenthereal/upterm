//go:build !windows

package capacity

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

// Unix permits replacing/renaming directories while they are open. All of the
// reads, writes and entry metadata must stay on the directory descriptors.
func TestCapacitySFTPNamespaceReplacement(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			client, err := sftp.NewClient(r.guests[0].client)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			root := r.hosts[0].h.CommandDir
			outside := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(outside, "sentinel"), []byte("outside secret"), 0600))
			race, parked := filepath.Join(root, "race"), filepath.Join(root, "parked")
			require.NoError(t, os.Mkdir(race, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(race, "sentinel"), []byte("inside"), 0600))
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
							require.EqualValues(t, 6, info.Size(), "entry metadata escaped through a replaced parent")
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
		})
	}
}

func TestCapacitySFTPMetadataSurvivesRootRename(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			client, err := sftp.NewClient(r.guests[0].client)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			root := r.hosts[0].h.CommandDir
			require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("inside"), 0600))
			moved := root + "-moved"
			require.NoError(t, os.Rename(root, moved))
			require.NoError(t, os.Mkdir(root, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("outside substitute"), 0600))
			infos, err := client.ReadDir(root)
			require.NoError(t, err)
			require.Len(t, infos, 1)
			require.EqualValues(t, 6, infos[0].Size(), "listing reopened the old path for entry metadata")
			info, err := client.Stat(filepath.Join(root, "file"))
			require.NoError(t, err)
			require.EqualValues(t, 6, info.Size())
			f, err := client.Open(filepath.Join(root, "file"))
			require.NoError(t, err)
			data, err := io.ReadAll(f)
			_ = f.Close()
			require.NoError(t, err)
			require.Equal(t, "inside", string(data))
		})
	}
}
