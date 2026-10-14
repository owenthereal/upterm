//go:build windows

package command

import (
	"strings"

	"golang.org/x/sys/windows"
)

// editorArgs splits an editor variable by the Windows command-line rules,
// which leave a path's backslashes alone: C:\Windows\notepad.exe is one word,
// where POSIX quoting would eat the backslashes.
func editorArgs(s string) ([]string, error) {
	// For a blank line CommandLineToArgv answers with the running program's
	// own path, which must not become the editor.
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return windows.DecomposeCommandLine(s)
}
