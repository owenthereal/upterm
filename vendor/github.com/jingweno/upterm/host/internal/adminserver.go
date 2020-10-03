package internal

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/models"
)

type AdminServer struct {
	Session    *models.APIGetSessionResponse
	ClientRepo *ClientRepo
	srv        *http.Server
	sync.Mutex
}

func (s *AdminServer) Serve(ctx context.Context, sock string) error {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}

	mux := runtime.NewServeMux()
	if err := api.RegisterAdminServiceHandlerServer(
		ctx,
		mux,
		&adminServiceServer{
			Session:    s.Session,
			ClientRepo: s.ClientRepo,
		},
	); err != nil {
		return err
	}

	s.Lock()
	s.srv = &http.Server{
		Handler: mux,
	}
	s.Unlock()

	return s.srv.Serve(ln)
}

func (s *AdminServer) Shutdown(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	return s.srv.Shutdown(ctx)
}

type adminServiceServer struct {
	Session    *models.APIGetSessionResponse
	ClientRepo *ClientRepo
}

func (s *adminServiceServer) GetSession(ctx context.Context, in *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return &api.GetSessionResponse{
		SessionId:        s.Session.SessionID,
		Host:             s.Session.Host,
		NodeAddr:         s.Session.NodeAddr,
		Command:          s.Session.Command,
		ForceCommand:     s.Session.ForceCommand,
		ConnectedClients: s.ClientRepo.Clients(),
	}, nil
}
