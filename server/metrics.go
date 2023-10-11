package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
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

const (
	metricControllerLabel = "controller"
	metricControllerValue = "upterm"

	metricNamespace           = "uptermd"
	metricSubsystemUptermHost = "upterm_host"
)

var (
	PreparedSession = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystemUptermHost,
			Name:      "info",
			Help:      "Info about started upterm host session",
			ConstLabels: prometheus.Labels{
				metricControllerLabel: metricControllerValue,
			},
		}, []string{
			"session_id",
			"label",
			// future ideas: upterm version, host version, host os, host arch, host kernel version, host kernel arch
		})

	ConnectedClients = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystemUptermHost,
			Name:      "current_clients",
			Help:      "Info about started upterm host session",
			ConstLabels: prometheus.Labels{
				metricControllerLabel: metricControllerValue,
			},
		}, []string{
			"session_id",
		})
)

func init() {
	prometheus.Register(PreparedSession)
	prometheus.Register(ConnectedClients)
}
