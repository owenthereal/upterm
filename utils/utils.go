package utils

import (
	"context"
	"path/filepath"
	"time"
)

func SocketFile(name string) string {
	return filepath.Join("/", name+".sock")
}

func KeepAlive(ctx context.Context, d time.Duration, fn func()) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}
