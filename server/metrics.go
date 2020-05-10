package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metricServer struct {
	server *http.Server
	mux    sync.Mutex
}

func (m *metricServer) Shutdown(ctx context.Context) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.server == nil {
		return nil
	}

	return m.server.Shutdown(ctx)
}

func (m *metricServer) ListenAndServe(addr string) error {
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
