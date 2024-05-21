package host

import (
	"fmt"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	AdminSockExt = ".sock"
)

func AdminSocketFile(sessionID string) string {
	return fmt.Sprintf("%s%s", sessionID, AdminSockExt)
}

func AdminClient(socket string) (api.AdminServiceClient, error) {
	// Use mtls
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return api.NewAdminServiceClient(conn), nil
}
