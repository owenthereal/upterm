package upterm

import "path/filepath"

func SocketFile(name string) string {
	return filepath.Join("/", name+".sock")
}
