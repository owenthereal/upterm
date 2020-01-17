package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsServer struct {
	server *http.Server
	mux    sync.Mutex
}

func (m *MetricsServer) Shutdown(ctx context.Context) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.server == nil {
		return nil
	}

	return m.server.Shutdown(ctx)
}

func (m *MetricsServer) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	m.mux.Lock()
	m.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	m.mux.Unlock()

	return m.server.ListenAndServe()
}
