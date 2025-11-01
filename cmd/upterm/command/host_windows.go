//go:build windows
// +build windows

package command

import (
	"os/exec"
)

// getDefaultShell returns the default shell on Windows
// Prefers PowerShell Core (pwsh) if available, otherwise falls back to cmd.exe
func getDefaultShell() string {
	// Check for PowerShell Core first
	if _, err := exec.LookPath("pwsh"); err == nil {
		return "pwsh"
	}

	// Check for PowerShell
	if _, err := exec.LookPath("powershell"); err == nil {
		return "powershell"
	}

	// Fallback to cmd.exe (always available on Windows)
	return "cmd.exe"
}
