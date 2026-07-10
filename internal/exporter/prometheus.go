// Package exporter — Prometheus metrics exporter for Argus.
//
// This file implements a Prometheus exporter that exposes three metrics:
//   - network_bytes_total{interface, protocol, direction}
//   - network_packets_total{interface, protocol, direction}
//   - network_active_connections{interface, protocol}
//
// The exporter registers custom Prometheus collectors rather than using the
// simple counter/gauge helpers. This lets us batch-update all metrics from a
// single BPF map read rather than updating on every packet, which would be
// prohibitively expensive. The Describe/Collect pattern also gives us full
// control over label cardinality.
//
// HTTP server is started on :9090/metrics (configurable) using the .env file.
package exporter

import (
	"context"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/store"
)

// Prometheus label names used across all metrics.
const (
	labelInterface  = "interface"
	labelProtocol   = "protocol"
	labelL7Protocol = "l7_protocol"
	labelDirection  = "direction"
)

// PrometheusExporter implements the Exporter interface and exposes metrics
// via an HTTP /metrics endpoint compatible with Prometheus scraping.
type PrometheusExporter struct {
	mu        sync.RWMutex
	ifaceName string
	log       *logrus.Logger

	// Prometheus descriptors — immutable, defined once at construction.
	bytesDesc   *prometheus.Desc
	pktsDesc    *prometheus.Desc
	activeConns *prometheus.Desc

	// Current metric values — updated atomically by Export(), read by Collect().
	// We accumulate totals across all collection intervals to produce monotonic
	// counters (Prometheus expects counters to only increase).
	bytesByKey map[metricKey]uint64
	pktsByKey  map[metricKey]uint64
	connsByKey map[connKey]uint64
}

// metricKey identifies a unique {interface, protocol, l7_protocol, direction} combination.
type metricKey struct {
	protocol   string
	l7Protocol string
	direction  string
}

// connKey identifies a unique {interface, protocol, l7_protocol} combination for the
// active connections gauge.
type connKey struct {
	protocol   string
	l7Protocol string
}

// NewPrometheusExporter creates a PrometheusExporter and registers it with
// the default Prometheus registry. Returns an error if registration fails
// (e.g., name collision with another exporter).
func NewPrometheusExporter(ifaceName string, log *logrus.Logger) (*PrometheusExporter, error) {
	exp := &PrometheusExporter{
		ifaceName:  ifaceName,
		log:        log,
		bytesByKey: make(map[metricKey]uint64),
		pktsByKey:  make(map[metricKey]uint64),
		connsByKey: make(map[connKey]uint64),

		// --- Descriptor definitions ---
		//
		// prometheus.NewDesc(fqName, help, variableLabels, constLabels)
		//
		// variableLabels are the per-series labels; their values come from
		// the Collect() method when we call prometheus.MustNewConstMetric().
		// constLabels are baked into every series (e.g., a fixed hostname).

		bytesDesc: prometheus.NewDesc(
			"network_bytes_total",
			"Total number of network bytes observed by Argus, partitioned by interface, protocol, l7_protocol, and direction.",
			[]string{labelInterface, labelProtocol, labelL7Protocol, labelDirection},
			nil,
		),

		pktsDesc: prometheus.NewDesc(
			"network_packets_total",
			"Total number of network packets observed by Argus, partitioned by interface, protocol, l7_protocol, and direction.",
			[]string{labelInterface, labelProtocol, labelL7Protocol, labelDirection},
			nil,
		),

		activeConns: prometheus.NewDesc(
			"network_active_connections",
			"Number of distinct active flows observed in the last collection interval.",
			[]string{labelInterface, labelProtocol, labelL7Protocol},
			nil,
		),
	}

	// Register our custom collector with Prometheus's default registry.
	if err := prometheus.Register(exp); err != nil {
		return nil, err
	}

	return exp, nil
}

// Describe implements prometheus.Collector. Prometheus calls this once at
// registration to learn what metrics this collector can produce. We send one
// Desc per metric family.
func (p *PrometheusExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.bytesDesc
	ch <- p.pktsDesc
	ch <- p.activeConns
}

// Collect implements prometheus.Collector. Prometheus calls this every time
// the /metrics endpoint is scraped. We read the current accumulated values
// under the read lock and emit them as const metrics.
//
// Prometheus counter semantics: values must only ever increase. We ensure
// this by accumulating totals in bytesByKey / pktsByKey rather than replacing
// them each interval — the BPF map also accumulates, so we are consistent.
func (p *PrometheusExporter) Collect(ch chan<- prometheus.Metric) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for key, bytes := range p.bytesByKey {
		ch <- prometheus.MustNewConstMetric(
			p.bytesDesc,
			prometheus.CounterValue,
			float64(bytes),
			p.ifaceName, key.protocol, key.l7Protocol, key.direction,
		)
	}

	for key, pkts := range p.pktsByKey {
		ch <- prometheus.MustNewConstMetric(
			p.pktsDesc,
			prometheus.CounterValue,
			float64(pkts),
			p.ifaceName, key.protocol, key.l7Protocol, key.direction,
		)
	}

	for key, count := range p.connsByKey {
		ch <- prometheus.MustNewConstMetric(
			p.activeConns,
			prometheus.GaugeValue,
			float64(count),
			p.ifaceName, key.protocol, key.l7Protocol,
		)
	}
}

// Export implements the Exporter interface. It is called by the collector
// every collection interval with the latest slice of enriched flows.
// We accumulate byte/packet totals and count distinct flows per protocol.
func (p *PrometheusExporter) Export(flows interface{}) {
	// Type assert — the collector package passes []store.Flow.
	flowSlice, ok := flows.([]store.Flow)
	if !ok {
		p.log.Error("PrometheusExporter received unexpected type from collector")
		return
	}

	// Active connection counts are reset each interval (it's a gauge).
	newConnsByKey := make(map[connKey]uint64)

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, flow := range flowSlice {
		l7 := flow.L7Protocol
		if l7 == "" {
			l7 = "unknown"
		}
		ingressKey := metricKey{protocol: flow.Protocol, l7Protocol: l7, direction: "ingress"}
		egressKey := metricKey{protocol: flow.Protocol, l7Protocol: l7, direction: "egress"}
		cKey := connKey{protocol: flow.Protocol, l7Protocol: l7}

		// Accumulate bytes and packets (counters must never decrease).
		p.bytesByKey[ingressKey] += flow.BytesIngress
		p.bytesByKey[egressKey] += flow.BytesEgress
		p.pktsByKey[ingressKey] += uint64(flow.PktsIngress)
		p.pktsByKey[egressKey] += uint64(flow.PktsEgress)

		// Count unique active flows per protocol.
		newConnsByKey[cKey]++
	}

	// Replace the gauge snapshot.
	p.connsByKey = newConnsByKey
}

// ServeMetrics starts the HTTP server. It blocks until ctx is
// cancelled. The caller should run this in a goroutine.
//
// Example:
//
//	go exp.ServeMetrics(ctx, ":9090", nil)
func (p *PrometheusExporter) ServeMetrics(ctx context.Context, addr string, registerExtra func(*http.ServeMux)) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if registerExtra != nil {
		registerExtra(mux)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Shutdown the HTTP server when ctx is cancelled.
	go func() {
		<-ctx.Done()
		p.log.Info("Shutting down HTTP server")
		if err := server.Shutdown(context.Background()); err != nil {
			p.log.WithError(err).Warn("Error during HTTP server shutdown")
		}
	}()

	p.log.WithField("addr", addr).Info("HTTP server listening")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
