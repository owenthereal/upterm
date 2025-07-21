package utils

import (
	"context"
	"fmt"
	"net"
	"time"
)

// WaitForServer waits for a server to be available at the given address with context support
func WaitForServer(ctx context.Context, addr string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for server at %s: %w", addr, ctx.Err())
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err != nil {
				continue
			}

			if err := conn.Close(); err != nil {
				return fmt.Errorf("error closing connection: %w", err)
			}

			return nil
		}
	}
}
