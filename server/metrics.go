package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/go-kit/kit/metrics"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-kit/kit/metrics/provider"
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

// prometheusProvider is a provider.Provider whose counters can carry labels.
// go-kit's provider.NewPrometheusProvider registers every metric with zero
// label names, so calling With on one of its counters panics inside
// client_golang. Unlabeled metrics are registered exactly as go-kit does,
// including histograms as summaries, so existing series keep their shape.
type prometheusProvider struct {
	namespace  string
	subsystem  string
	registerer prometheus.Registerer
}

func newPrometheusProvider(namespace, subsystem string, registerer prometheus.Registerer) *prometheusProvider {
	return &prometheusProvider{
		namespace:  namespace,
		subsystem:  subsystem,
		registerer: registerer,
	}
}

// NewCounter implements provider.Provider.
func (p *prometheusProvider) NewCounter(name string) metrics.Counter {
	return p.NewCounterWithLabels(name)
}

// NewCounterWithLabels returns a registered counter whose With accepts the
// given label names.
func (p *prometheusProvider) NewCounterWithLabels(name string, labelNames ...string) metrics.Counter {
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name,
		Help:      name,
	}, labelNames)
	p.registerer.MustRegister(cv)
	return kitprometheus.NewCounter(cv)
}

// NewGauge implements provider.Provider.
func (p *prometheusProvider) NewGauge(name string) metrics.Gauge {
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name,
		Help:      name,
	}, []string{})
	p.registerer.MustRegister(gv)
	return kitprometheus.NewGauge(gv)
}

// NewHistogram implements provider.Provider. Buckets are ignored, as in
// go-kit's Prometheus provider, which exports histograms as summaries.
func (p *prometheusProvider) NewHistogram(name string, _ int) metrics.Histogram {
	sv := prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      name,
		Help:      name,
	}, []string{})
	p.registerer.MustRegister(sv)
	return kitprometheus.NewSummary(sv)
}

// Stop implements provider.Provider.
func (p *prometheusProvider) Stop() {}

// newLabeledCounter returns a counter on which With(labelNames...) is honoured
// when the provider supports labels. Otherwise it returns a plain counter that
// drops labels, so all kinds fold into one series. Forwarding With to a
// provider that registered zero label names, such as go-kit's own Prometheus
// provider, would panic inside client_golang.
func newLabeledCounter(p provider.Provider, name string, labelNames ...string) metrics.Counter {
	if lp, ok := p.(interface {
		NewCounterWithLabels(name string, labelNames ...string) metrics.Counter
	}); ok {
		return lp.NewCounterWithLabels(name, labelNames...)
	}
	return labelDroppingCounter{p.NewCounter(name)}
}

// labelDroppingCounter ignores With, folding every label value into the
// underlying unlabeled counter.
type labelDroppingCounter struct {
	metrics.Counter
}

func (c labelDroppingCounter) With(...string) metrics.Counter { return c }
