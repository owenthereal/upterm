//go:build !windows

package sessiondir

// secureSessionDir is a no-op here: Claim creates the directory 0700, and on
// a POSIX filesystem that is the boundary. See secure_windows.go.
func secureSessionDir(string) error { return nil }
