package exporter

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type collectionMetrics struct {
	duration *prometheus.HistogramVec
	mapRead  prometheus.Histogram
	errors   *prometheus.CounterVec
	success  prometheus.Gauge
	lag      prometheus.Gauge
	overruns prometheus.Counter
	discards prometheus.Counter
}

func newCollectionMetrics(iface string, registry *prometheus.Registry) collectionMetrics {
	labels := prometheus.Labels{"interface": iface}
	buckets := []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	metrics := collectionMetrics{
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "network_collection_duration_seconds", Help: "Duration of one Argus collection attempt.",
			ConstLabels: labels, Buckets: buckets,
		}, []string{"result"}),
		mapRead: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "network_collection_map_read_duration_seconds", Help: "Duration of a sealed flow map walk.",
			ConstLabels: labels, Buckets: buckets,
		}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "network_collection_errors_total", Help: "Argus collections which failed before publication.",
			ConstLabels: labels,
		}, []string{"stage"}),
		success: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_collection_last_success_timestamp_seconds", Help: "Unix timestamp of the last successful publication (zero before startup).",
			ConstLabels: labels,
		}),
		lag: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_collection_lag_seconds", Help: "Delay between the scheduled and actual start of the latest regular collection.",
			ConstLabels: labels,
		}),
		overruns: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_collection_overruns_total", Help: "Regular collections which ran for at least one sampling interval.",
			ConstLabels: labels,
		}),
		discards: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "network_flow_generations_discarded_total", Help: "Sealed detail generations discarded without publication.",
			ConstLabels: labels,
		}),
	}
	registry.MustRegister(metrics.duration, metrics.mapRead, metrics.errors, metrics.success, metrics.lag, metrics.overruns, metrics.discards)
	return metrics
}

func (p *PrometheusExporter) RecordCollection(attempt CollectionResult) {
	metrics := p.collection
	result := "success"
	if attempt.ErrorStage != "" {
		result = "error"
		metrics.errors.WithLabelValues(attempt.ErrorStage).Inc()
	} else {
		metrics.success.Set(float64(attempt.Published.UnixNano()) / float64(time.Second))
	}
	metrics.duration.WithLabelValues(result).Observe(attempt.Duration.Seconds())
	if attempt.MapRead > 0 {
		metrics.mapRead.Observe(attempt.MapRead.Seconds())
	}
	if !attempt.Final {
		metrics.lag.Set(attempt.Lag.Seconds())
	}
	if attempt.Overrun {
		metrics.overruns.Inc()
	}
	if attempt.Discarded {
		metrics.discards.Inc()
	}
}
