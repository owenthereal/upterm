//go:build !windows

package sessiondir

import "os"

// replaceFile moves from onto to, replacing whatever is there.
//
// POSIX rename is already this: atomic, and indifferent to anyone holding the
// destination open, because a reader's descriptor outlives the name it was
// opened by. Windows has neither property for free; see rename_windows.go.
func replaceFile(from, to string) error { return os.Rename(from, to) }
