//go:build !windows

package command

import "github.com/google/shlex"

// editorArgs splits an editor variable the way a POSIX shell does: words,
// quotes and backslash escapes.
func editorArgs(s string) ([]string, error) {
	return shlex.Split(s)
}
