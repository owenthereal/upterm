package host

import (
	"context"
	"net"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func AdminClient(socket string) (api.AdminServiceClient, error) {
	conn, err := AdminConn(socket)
	if err != nil {
		return nil, err
	}

	return api.NewAdminServiceClient(conn), nil
}

// AdminConn is AdminClient's connection, for a caller that has to close it: a
// process that asks more than once in its life, such as an attached
// terminal's ~?, would otherwise keep a connection open per question.
func AdminConn(socket string) (*grpc.ClientConn, error) {
	// Use mtls
	// Workaround for gRPC Unix socket support on Windows: https://github.com/grpc/grpc-go/issues/8675
	return grpc.NewClient(
		"passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
}
