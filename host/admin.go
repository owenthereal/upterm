package host

import (
	"context"
	"net"
	"net/http"
	"path/filepath"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/client"
	"github.com/jingweno/upterm/host/api/swagger/client/admin_service"
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
	Host         string
	NodeAddr     string
	SessionID    string
	Command      []string
	ForceCommand []string
	ln           net.Listener
	srv          *http.Server
}

func (s *adminServer) Serve(ctx context.Context, sock string) error {
	var err error
	s.ln, err = net.Listen("unix", sock)
	if err != nil {
		return err
	}

	mux := runtime.NewServeMux()
	if err := api.RegisterAdminServiceHandlerServer(
		ctx,
		mux,
		&adminServiceServer{
			SessionID:    s.SessionID,
			Host:         s.Host,
			NodeAddr:     s.NodeAddr,
			Command:      s.Command,
			ForceCommand: s.ForceCommand,
		},
	); err != nil {
		return err
	}

	s.srv = &http.Server{
		Handler: mux,
	}

	return s.srv.Serve(s.ln)
}

func (s *adminServer) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

type adminServiceServer struct {
	Host         string
	NodeAddr     string
	SessionID    string
	Command      []string
	ForceCommand []string
}

func (s *adminServiceServer) GetSession(ctx context.Context, in *api.GetSessionRequest) (*api.GetSessionResponse, error) {
	return &api.GetSessionResponse{
		SessionId:    s.SessionID,
		Host:         s.Host,
		NodeAddr:     s.NodeAddr,
		Command:      s.Command,
		ForceCommand: s.ForceCommand,
	}, nil
}
