//go:build !windows
// +build !windows

package internal

import (
	"net"
)

// createListener creates a Unix domain socket listener on Unix systems
func createListener(sock string) (net.Listener, error) {
	return net.Listen("unix", sock)
}
