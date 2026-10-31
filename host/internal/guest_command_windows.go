//go:build windows

package internal

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func guestExecArgv(raw string) ([]string, error) {
	for _, name := range []string{"pwsh", "powershell"} {
		if path, err := exec.LookPath(name); err == nil {
			return []string{path, "-NoLogo", "-NoProfile", "-Command", raw}, nil
		}
	}
	path, err := exec.LookPath("cmd.exe")
	if err != nil {
		path = "cmd.exe"
	}
	return []string{path, "/D", "/S", "/C", raw}, nil
}

func prepareGuestCommand(cmd *exec.Cmd) {
	if strings.EqualFold(filepath.Base(cmd.Path), "cmd.exe") && len(cmd.Args) == 5 && cmd.Args[1] == "/D" && cmd.Args[2] == "/S" && cmd.Args[3] == "/C" {
		// cmd.exe parses /C with its own quoting rules, rather than CommandLineToArgvW.
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: syscall.EscapeArg(cmd.Path) + ` /D /S /C "` + cmd.Args[4] + `"`}
	}
}
