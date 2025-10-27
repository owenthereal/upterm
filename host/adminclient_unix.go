//go:build !windows
// +build !windows

package host

// getAdminTarget returns the gRPC target for connecting to the admin server on Unix
func getAdminTarget(socket string) (string, error) {
	return "unix://" + socket, nil
}
