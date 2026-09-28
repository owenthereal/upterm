package server

import (
	"testing"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// newTestMetrics returns a Prometheus-backed provider on a private registry so
// tests can assert on gathered values without touching the global registry.
func newTestMetrics(t *testing.T) (*prometheusProvider, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	return newPrometheusProvider("test", "server", reg), reg
}

// gatherValue returns the value of the counter or gauge sample in family name
// whose label set equals labels. ok is false when no such sample exists.
func gatherValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) (v float64, ok bool) {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	metric:
		for _, m := range f.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			for _, l := range m.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					continue metric
				}
			}
			switch {
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue(), true
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func Test_prometheusProvider_labeledCounter(t *testing.T) {
	p, reg := newTestMetrics(t)

	c := p.NewCounterWithLabels("labeled_count", "kind")
	c.With("kind", "host").Add(2)
	c.With("kind", "client").Add(1)

	v, ok := gatherValue(t, reg, "test_server_labeled_count", map[string]string{"kind": "host"})
	require.True(t, ok)
	require.Equal(t, 2.0, v)

	v, ok = gatherValue(t, reg, "test_server_labeled_count", map[string]string{"kind": "client"})
	require.True(t, ok)
	require.Equal(t, 1.0, v)
}

func Test_prometheusProvider_unlabeled(t *testing.T) {
	p, reg := newTestMetrics(t)

	p.NewCounter("c").Add(1)
	p.NewGauge("g").Set(3)
	p.NewHistogram("h", 50).Observe(1.5)

	v, ok := gatherValue(t, reg, "test_server_c", nil)
	require.True(t, ok)
	require.Equal(t, 1.0, v)

	v, ok = gatherValue(t, reg, "test_server_g", nil)
	require.True(t, ok)
	require.Equal(t, 3.0, v)

	// Histograms are exported as summaries, matching go-kit's provider, so the
	// existing routing_connection_duration_seconds_{sum,count} series keep
	// their shape.
	families, err := reg.Gather()
	require.NoError(t, err)
	var found bool
	for _, f := range families {
		if f.GetName() == "test_server_h" {
			found = true
			require.Equal(t, uint64(1), f.GetMetric()[0].GetSummary().GetSampleCount())
		}
	}
	require.True(t, found, "summary family test_server_h not gathered")
}

func Test_newLabeledCounter(t *testing.T) {
	// Providers without label support fall back to a plain counter; With must
	// not panic on them.
	c := newLabeledCounter(provider.NewDiscardProvider(), "x", "kind")
	c.With("kind", "host").Add(1)

	// Server.MetricsProvider is exported, so embedders may still pass go-kit's
	// own Prometheus provider, whose counters panic on With. The fallback must
	// drop the labels rather than forward them. go-kit registers on the
	// default registerer, so swap it out for the test's lifetime.
	defaultRegisterer := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = defaultRegisterer })
	c = newLabeledCounter(provider.NewPrometheusProvider("test", "fallback"), "labels_dropped_count", "kind")
	c.With("kind", "host").Add(1)

	p, reg := newTestMetrics(t)
	newLabeledCounter(p, "y", "kind").With("kind", "host").Add(1)
	v, ok := gatherValue(t, reg, "test_server_y", map[string]string{"kind": "host"})
	require.True(t, ok)
	require.Equal(t, 1.0, v)
}
