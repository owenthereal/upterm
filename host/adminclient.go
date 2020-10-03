package host

import (
	"fmt"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
)

const (
	AdminSockExt = ".sock"
)

func AdminSocketFile(sessionID string) string {
	return fmt.Sprintf("%s%s", sessionID, AdminSockExt)
}

func AdminClient(socket string) (api.AdminServiceClient, error) {
	// Use mtls
	conn, err := grpc.Dial("unix://"+socket, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	return api.NewAdminServiceClient(conn), nil
}
