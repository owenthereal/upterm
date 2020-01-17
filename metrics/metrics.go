package metrics

import (
	"time"

	"github.com/go-kit/kit/metrics"
)

const defaultTimingUnit = time.Millisecond

func MeasureSince(h metrics.Histogram, t0 time.Time) {
	measureSince(h, t0, time.Now(), float64(defaultTimingUnit))
}

func measureSince(h metrics.Histogram, t0, t1 time.Time, unit float64) {
	d := t1.Sub(t0)
	if d < 0 {
		d = 0
	}
	h.Observe(float64(d) / unit)
}
