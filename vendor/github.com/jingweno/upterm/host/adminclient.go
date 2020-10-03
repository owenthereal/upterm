package host

import (
	"context"
	"fmt"
	"net"
	"net/http"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/jingweno/upterm/host/api/swagger/client"
	"github.com/jingweno/upterm/host/api/swagger/client/admin_service"
)

const (
	AdminSockExt = ".sock"
)

func AdminSocketFile(sessionID string) string {
	return fmt.Sprintf("%s%s", sessionID, AdminSockExt)
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
