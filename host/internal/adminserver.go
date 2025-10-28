package internal

import (
	"context"
	"net"
	"sync"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
)

type AdminServer struct {
	Session    *api.GetSessionResponse
	ClientRepo *ClientRepo
	srv        *grpc.Server
	sync.Mutex
}

func (s *AdminServer) Serve(ctx context.Context, sock string) error {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}

	s.Lock()
	s.srv = grpc.NewServer()
	api.RegisterAdminServiceServer(s.srv, &adminServiceServer{
		Session:    s.Session,
		ClientRepo: s.ClientRepo,
	})
	s.Unlock()

	return s.srv.Serve(ln)
}

func (s *AdminServer) Shutdown(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	if s.srv != nil {
		s.srv.GracefulStop()
	}

	return nil
}

type adminServiceServer struct {
	Session    *api.GetSessionResponse
	ClientRepo *ClientRepo
}

func (s *adminServiceServer) GetSession(ctx context.Context, in *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return &api.GetSessionResponse{
		SessionId:        s.Session.SessionId,
		Host:             s.Session.Host,
		NodeAddr:         s.Session.NodeAddr,
		SshUser:          s.Session.SshUser,
		Command:          s.Session.Command,
		ForceCommand:     s.Session.ForceCommand,
		AuthorizedKeys:   s.Session.AuthorizedKeys,
		ConnectedClients: s.ClientRepo.Clients(),
	}, nil
}
