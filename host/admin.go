package host

import (
	"context"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/jingweno/upterm/host/api"
)

type adminServer struct {
	SessionID string
	ln        net.Listener
	srv       *http.Server
}

func (s *adminServer) Serve(ctx context.Context, sock string) error {
	var err error
	s.ln, err = net.Listen("unix", sock)
	if err != nil {
		return err
	}

	mux := runtime.NewServeMux()
	api.RegisterAdminServiceHandlerServer(ctx, mux, &adminServiceServer{SessionID: s.SessionID})

	s.srv = &http.Server{
		Handler: mux,
	}

	return s.srv.Serve(s.ln)
}

func (s *adminServer) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

type adminServiceServer struct {
	SessionID string
}

func (s *adminServiceServer) GetSession(ctx context.Context, in *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return &api.GetSessionResponse{SessionId: s.SessionID}, nil
}
