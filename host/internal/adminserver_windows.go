//go:build windows
// +build windows

package internal

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// createListener creates a TCP listener on Windows (since Windows doesn't support Unix domain sockets)
// It writes the actual TCP address to the socket file for clients to read
func createListener(sockPath string) (net.Listener, error) {
	// Listen on localhost with a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %w", err)
	}

	// Write the actual address to a file so clients can find it
	// This mimics the Unix socket behavior where the socket path is known
	addr := ln.Addr().String()

	// Create directory if it doesn't exist
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		ln.Close()
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Write the TCP address to the socket path file
	if err := os.WriteFile(sockPath, []byte(addr), 0600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("failed to write socket file: %w", err)
	}

	return ln, nil
}
