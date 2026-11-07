package capacity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapacitySFTPWriteLimitsAcrossTransports(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			q := r.guests[0]
			client, err := sftp.NewClient(q.client)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			outside := filepath.Join(t.TempDir(), "outside")
			control := filepath.Join(filepath.Dir(q.host.socket), "control-secret")
			for _, name := range []string{outside, control} {
				require.NoError(t, os.WriteFile(name, []byte("unchanged"), 0600))
			}
			t.Run("unassigned name", func(t *testing.T) {
				f, err := client.Create("unexpected")
				if f != nil {
					_ = f.Close()
				}
				require.Error(t, err, "unassigned upload name was created")
			})
			t.Run("extent before IO", func(t *testing.T) {
				f, err := client.Create("transfer-0.bin")
				require.NoError(t, err)
				defer func() { _ = f.Close() }()
				for _, offset := range []int64{TransferSize, -1, math.MaxInt64} {
					n, err := f.WriteAt([]byte("x"), offset)
					assert.Error(t, err, "write outside extent accepted at %d", offset)
					assert.Zero(t, n)
				}
				info, err := f.Stat()
				require.NoError(t, err)
				assert.Zero(t, info.Size(), "rejected write reached the filesystem")
				_, err = f.WriteAt([]byte("z"), TransferSize-1)
				require.NoError(t, err, "last legal byte remains writable")
			})
			t.Run("one lifetime instance including deleted handles", func(t *testing.T) {
				f, err := client.Create("transfer-1.bin")
				require.NoError(t, err)
				defer func() { _ = f.Close() }()
				_, err = f.WriteAt([]byte("old"), 0)
				require.NoError(t, err)
				other, err := sftp.NewClient(q.client)
				require.NoError(t, err)
				defer func() { _ = other.Close() }()
				duplicate, err := other.Create("transfer-1.bin")
				if duplicate != nil {
					_ = duplicate.Close()
				}
				assert.Error(t, err, "second session received a new writable instance")
				require.NoError(t, client.Remove("transfer-1.bin"))
				duplicate, err = other.Create("transfer-1.bin")
				if duplicate != nil {
					_ = duplicate.Close()
				}
				assert.Error(t, err, "remove recycled an outstanding inode's creation slot")
				_, err = f.WriteAt([]byte("still bounded"), 3)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				s, err := q.host.session(r.ctx)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
				defer cancel()
				connection, raw, err := openGuest(ctx, r.guard, q.target, q.endpoint, s, q.identity, q.proxy)
				require.NoError(t, err)
				defer func() { _ = raw.Close(); _ = connection.Close() }()
				reconnected, err := sftp.NewClient(connection)
				require.NoError(t, err)
				defer func() { _ = reconnected.Close() }()
				duplicate, err = reconnected.Create("transfer-1.bin")
				if duplicate != nil {
					_ = duplicate.Close()
				}
				require.Error(t, err, "reconnect replenished the creation slot")
			})
			t.Run("concurrent cumulative overwrites", func(t *testing.T) {
				f, err := client.Create("transfer-2.bin")
				require.NoError(t, err)
				defer func() { _ = f.Close() }()
				payload := bytes.Repeat([]byte("x"), 1<<20)
				var wg sync.WaitGroup
				written := make(chan int, 17)
				for range 17 {
					wg.Go(func() { n, _ := f.WriteAt(payload, 0); written <- n })
				}
				wg.Wait()
				close(written)
				total := 0
				for n := range written {
					total += n
				}
				require.EqualValues(t, TransferSize, total, "overwrites bypassed lifetime accepted-write accounting")
				n, err := f.WriteAt([]byte("x"), 0)
				require.Error(t, err)
				require.Zero(t, n)
			})
			t.Run("out of order read stat remove", func(t *testing.T) {
				f, err := client.Create("transfer-3.bin")
				require.NoError(t, err)
				_, err = f.WriteAt([]byte("world"), 6)
				require.NoError(t, err)
				_, err = f.WriteAt([]byte("hello "), 0)
				require.NoError(t, err)
				require.NoError(t, f.Close())
				f, err = client.Open("transfer-3.bin")
				require.NoError(t, err)
				data, err := io.ReadAll(f)
				require.NoError(t, err)
				require.Equal(t, "hello world", string(data))
				info, err := f.Stat()
				require.NoError(t, err)
				require.EqualValues(t, 11, info.Size())
				require.NoError(t, f.Close())
				require.NoError(t, client.Remove("transfer-3.bin"))
			})
			for _, name := range []string{outside, control} {
				data, err := os.ReadFile(name)
				require.NoError(t, err)
				require.Equal(t, "unchanged", string(data))
			}
		})
	}
}

func TestCapacitySFTPAllowedNameStillUsesRoot(t *testing.T) {
	for _, ws := range []int{0, 100} {
		t.Run(fmt.Sprintf("ws=%d", ws), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.HostWSPercent, c.GuestWSPercent = false, ws, ws
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			client, err := sftp.NewClient(r.guests[0].client)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			outside := filepath.Join(t.TempDir(), "sentinel")
			require.NoError(t, os.WriteFile(outside, []byte("outside"), 0600))
			require.NoError(t, os.Symlink(outside, filepath.Join(r.hosts[0].h.CommandDir, "transfer-0.bin")))
			f, err := client.Create("transfer-0.bin")
			if f != nil {
				_ = f.Close()
			}
			require.Error(t, err, "an allowed filename followed a symlink outside Root")
			f, err = client.Create("transfer-1.bin")
			require.NoError(t, err, "allowed in-root writable control")
			_, err = f.Write([]byte("inside"))
			require.NoError(t, err)
			require.NoError(t, f.Close())
			data, err := os.ReadFile(outside)
			require.NoError(t, err)
			require.Equal(t, "outside", string(data))
		})
	}
}

func TestCapacitySFTPAssignsOnlyEachHostsTransfers(t *testing.T) {
	for _, guestsPerHost := range []int{1, 2} {
		t.Run(fmt.Sprintf("guests=%d", guestsPerHost), func(t *testing.T) {
			c := localRelay(t)
			c.Active, c.Hosts, c.GuestsPerHost = false, 5, guestsPerHost
			c.TransferConcurrency, c.PayloadBudgetBytes = 4, 256<<20
			r := admittedRun(t, c)
			for hostID := range 5 {
				client, err := sftp.NewClient(r.guests[hostID*guestsPerHost].client)
				require.NoError(t, err)
				for transfer := range 4 {
					f, err := client.Create(fmt.Sprintf("transfer-%d.bin", transfer))
					if f != nil {
						_ = f.Close()
					}
					if transfer/guestsPerHost == hostID {
						require.NoError(t, err, "assigned transfer %d on host %d", transfer, hostID)
					} else {
						require.Error(t, err, "unassigned transfer %d on host %d", transfer, hostID)
					}
				}
				require.NoError(t, client.Close())
			}
		})
	}
}
