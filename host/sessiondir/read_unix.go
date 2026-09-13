//go:build !windows

package sessiondir

import "os"

func readFileShareDelete(path string) ([]byte, error) { return os.ReadFile(path) }
