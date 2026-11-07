package capacity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestCapacitySFTPRejectsOutsideSymlinks(t *testing.T) {
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
			secret := filepath.Join(outside, "secret")
			require.NoError(t, os.WriteFile(secret, []byte("outside secret"), 0600))
			require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))
			require.NoError(t, os.Symlink(secret, filepath.Join(root, "link")))
			for _, path := range []string{"link", "escape/secret", filepath.Join(root, "escape", "secret")} {
				f, err := client.Open(path)
				if f != nil {
					_ = f.Close()
				}
				require.Error(t, err, "outside content via %s", path)
				f, err = client.Create(path)
				if f != nil {
					_ = f.Close()
				}
				require.Error(t, err, "outside write via %s", path)
				_, err = client.Stat(path)
				require.Error(t, err, "outside stat via %s", path)
			}
			_, err = client.ReadDir("escape")
			require.Error(t, err)
			_, err = client.ReadLink("link")
			require.Error(t, err)
			info, err := client.Lstat("link")
			require.NoError(t, err)
			require.NotZero(t, info.Mode()&os.ModeSymlink, "lstat returns in-root link metadata without following it")
			require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("inside"), 0600))
			f, err := client.Open("file")
			require.NoError(t, err)
			defer func() { _ = f.Close() }()
			require.NoError(t, os.Rename(filepath.Join(root, "file"), filepath.Join(root, "saved")))
			require.NoError(t, os.Symlink(secret, filepath.Join(root, "file")))
			_, err = f.Stat()
			require.Error(t, err, "path-based protocol fstat must not follow a replaced path outside")
			require.Error(t, f.Truncate(0), "handle setstat remains denied")
			data, err := io.ReadAll(f)
			require.NoError(t, err)
			require.Equal(t, "inside", string(data), "open content handle stayed on its original file")
			data, err = os.ReadFile(secret)
			require.NoError(t, err)
			require.Equal(t, "outside secret", string(data))
		})
	}
}
