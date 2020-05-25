package host

import (
	"context"
	"net"
	"net/http"
	"path/filepath"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/jingweno/upterm/host/api/swagger/client"
	"github.com/jingweno/upterm/host/api/swagger/client/admin_service"
)

func AdminSocketFile(dir ...string) string {
	p := append(dir, "admin.sock")
	return filepath.Join(p...)
}

func AdminClient(socket string) admin_service.ClientService {
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
