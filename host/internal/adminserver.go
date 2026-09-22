package internal

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AdminServer struct {
	Session    *api.GetSessionResponse
	ClientRepo *ClientRepo

	// LaunchID is the launch this server speaks for, from the record the
	// session claimed. StopSession refuses a request that names any other
	// launch, so that a client whose session ended between reading the
	// record and dialling the socket does not stop the session that took
	// the name over. Empty means no name was claimed -- a caller that
	// supplied its own admin socket -- and then no stop can be bound to a
	// launch, so none is accepted.
	LaunchID string

	// OnListening, if set, is called once the socket is bound. It is the other
	// half of readiness: a caller told "ready" must be able to connect, which
	// registering the actor does not establish and binding does.
	OnListening func()

	// OnStop is called when a client asks the session to end. The daemon
	// wires it to an explicit stop cause; the RPC returns at
	// once and the teardown follows.
	OnStop func()

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
		LaunchID:   s.LaunchID,
		OnStop:     s.OnStop,
	})
	srv := s.srv
	s.Unlock()

	return srv.Serve(ln)
}

// Shutdown drains RPCs until ctx expires, then initiates forced transport closure.
// It cannot terminate a callback that ignores cancellation: gRPC Serve and its
// shutdown goroutines may still wait for that callback to return.
func (s *AdminServer) Shutdown(ctx context.Context) error {
	s.Lock()
	srv, ln := s.srv, s.ln
	// A serving actor that has not started must not resurrect a closed listener.
	s.ln = nil
	s.Unlock()

	if srv != nil {
		drained := make(chan struct{})
		go func() { srv.GracefulStop(); close(drained) }()
		select {
		case <-drained:
		case <-ctx.Done():
			// Stop closes active transports, including incomplete request bodies.
			// It can itself block behind GracefulStop's handler-wait mutex, so
			// neither shutdown call may be awaited after the caller's deadline.
			go srv.Stop()
		}
		return nil
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

type adminServiceServer struct {
	Session    *api.GetSessionResponse
	ClientRepo *ClientRepo
	LaunchID   string
	OnStop     func()
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

// StopSession ends the launch the request names, and only that one.
//
// The name and the socket path are the session's, not the run's: a session
// that ends gives both back, and the next `upterm host` to claim the name
// binds the same path. A client reads a record, finds the socket, dials it,
// and asks -- and in between, the run it read can have ended and been
// replaced. Unbound, the replacement would accept the stop and die, and the
// client's own check (the launch ID changed, so the session it asked about
// is gone) would report that as success. So the request carries the launch
// the client inspected and anything else is refused, an empty value
// included: the RPC is unreleased, so no caller that omits it exists, and a
// caller that cannot name a launch is one that has not read a record.
//
// Plain equality: a launch ID is published in the record for anyone to
// read, so it is an identifier and not a secret, and nothing here is
// protected by keeping its comparison time constant.
func (s *adminServiceServer) StopSession(ctx context.Context, in *api.StopSessionRequest) (*api.StopSessionResponse, error) {
	if s.LaunchID == "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this session has no launch to be stopped by name; the request named %q", in.GetLaunchId())
	}
	if in.GetLaunchId() != s.LaunchID {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this socket holds launch %s; the request named %q", s.LaunchID, in.GetLaunchId())
	}
	if s.OnStop != nil {
		s.OnStop()
	}
	return &api.StopSessionResponse{}, nil
}
