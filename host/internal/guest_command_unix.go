//go:build !windows

package internal

import (
	"os"
	"os/exec"
)

func guestExecArgv(raw string) ([]string, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return []string{shell, "-c", raw}, nil
}
func prepareGuestCommand(*exec.Cmd) {}
