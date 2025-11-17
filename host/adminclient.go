package host

import (
	"context"
	"fmt"
	"net"

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
	// Workaround for gRPC Unix socket support on Windows: https://github.com/grpc/grpc-go/issues/8675
	conn, err := grpc.NewClient(
		"passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
	if err != nil {
		return nil, err
	}

	return api.NewAdminServiceClient(conn), nil
}
