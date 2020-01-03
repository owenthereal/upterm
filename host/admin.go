package host

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/client"
	"github.com/jingweno/upterm/host/api/swagger/client/admin_service"
	"github.com/jingweno/upterm/host/api/swagger/models"
)

func AdminSocketFile(dir ...string) string {
	p := append(dir, "admin.sock")
	return filepath.Join(p...)
}

func AdminClient(socket string) *admin_service.Client {
	cfg := client.DefaultTransportConfig()
	t := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	t.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socket)
		},
	}

	c := client.New(t, nil)
	return c.AdminService
}

type adminServer struct {
	Session *models.APIGetSessionResponse
	srv     *http.Server
	sync.Mutex
}

func (s *adminServer) Serve(ctx context.Context, sock string) error {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}

	mux := runtime.NewServeMux()
	if err := api.RegisterAdminServiceHandlerServer(
		ctx,
		mux,
		&adminServiceServer{
			Session: s.Session,
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

func (s *adminServer) Shutdown(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	return s.srv.Shutdown(ctx)
}

type adminServiceServer struct {
	Session *models.APIGetSessionResponse
}

func (s *adminServiceServer) GetSession(ctx context.Context, in *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return &api.GetSessionResponse{
		SessionId:    s.Session.SessionID,
		Host:         s.Session.Host,
		NodeAddr:     s.Session.NodeAddr,
		Command:      s.Session.Command,
		ForceCommand: s.Session.ForceCommand,
	}, nil
}
