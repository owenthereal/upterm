//go:build !windows
// +build !windows

package command

import (
	"os"
)

// getDefaultShell returns the default shell on Unix systems
func getDefaultShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return shell
}
