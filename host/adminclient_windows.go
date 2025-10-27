//go:build windows
// +build windows

package host

import (
	"fmt"
	"os"
)

// getAdminTarget returns the gRPC target for connecting to the admin server on Windows
// On Windows, we use TCP instead of Unix sockets, and the socket file contains the TCP address
func getAdminTarget(sockPath string) (string, error) {
	// Read the TCP address from the socket file
	addr, err := os.ReadFile(sockPath)
	if err != nil {
		return "", fmt.Errorf("failed to read socket file: %w", err)
	}

	return string(addr), nil
}
