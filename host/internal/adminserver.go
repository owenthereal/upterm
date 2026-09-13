package internal

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
)

type AdminServer struct {
	Session    *api.GetSessionResponse
	ClientRepo *ClientRepo

	// OnListening, if set, is called once the socket is bound. It is the other
	// half of readiness: a caller told "ready" must be able to connect, which
	// registering the actor does not establish and binding does.
	OnListening func()

	srv *grpc.Server
	ln  net.Listener
	sync.Mutex
}

// Listen binds the admin socket. It is separate from Serve so the caller can
// bind synchronously, before any concurrent actor exists.
//
// Binding inside the serving goroutine made a bind failure race the command's
// start: whichever lost the race decided how the run was classified, so the
// same broken socket path was reported as startup_failed on one run and
// signaled on the next. Bound up front, the failure is the caller's to return
// and there is nothing to race.
func (s *AdminServer) Listen(sock string) error {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}

	s.Lock()
	s.ln = ln
	s.Unlock()

	// Bound, so a caller that is told "ready" can connect.
	if s.OnListening != nil {
		s.OnListening()
	}

	return nil
}

// Serve serves the listener Listen bound. Listen must have succeeded first:
// this deliberately refuses to bind on the caller's behalf, because doing so
// is exactly the race Listen exists to remove.
func (s *AdminServer) Serve(ctx context.Context) error {
	s.Lock()
	ln := s.ln
	if ln == nil {
		s.Unlock()
		return errors.New("admin server: Serve called before Listen")
	}
	s.srv = grpc.NewServer()
	api.RegisterAdminServiceServer(s.srv, &adminServiceServer{
		Session:    s.Session,
		ClientRepo: s.ClientRepo,
	})
	srv := s.srv
	s.Unlock()

	return srv.Serve(ln)
}

func (s *AdminServer) Shutdown(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	if s.srv != nil {
		// Closes the listener too.
		s.srv.GracefulStop()
		return nil
	}

	// Bound but never served, which a teardown that arrives before the serving
	// actor starts leaves behind. Nothing else would close it.
	if s.ln != nil {
		return s.ln.Close()
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
		SftpDisabled:     s.Session.SftpDisabled,
	}, nil
}
