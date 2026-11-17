package exporter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/store"
)

type protocolLabels struct {
	protocol string
	l7       string
}

type traffic struct {
	bytes, packets uint64
}

type totals struct {
	ingress, egress traffic
}

type flowKey struct {
	srcIP, dstIP     store.IPv4
	srcPort, dstPort uint16
	protocol         string
}

type flowCounters struct {
	firstSeen uint64
	totals
}

type publishedMetrics struct {
	totals       map[protocolLabels]totals
	active       map[protocolLabels]uint64
	observations bpf.ObservationTotals
	failures     uint64
	entries      int
}

type PrometheusExporter struct {
	mu        sync.Mutex
	current   atomic.Pointer[publishedMetrics]
	cap       atomic.Uint32
	ifaceName string
	log       *logrus.Logger
	registry  *prometheus.Registry

	bytes, packets, active, entries, failures         *prometheus.Desc
	observedBytes, observedPackets, skips, accounting *prometheus.Desc
	capacity                                          *prometheus.Desc
	collection                                        collectionMetrics

	lastGeneration uint64
	previous       map[flowKey]flowCounters
	next           map[flowKey]flowCounters
}

// Each agent has its own registry so it can be started and stopped in process.
func NewPrometheusExporter(ifaceName string, log *logrus.Logger) (*PrometheusExporter, error) {
	directions := []string{"interface", "protocol", "l7_protocol", "direction"}
	observedDirections := []string{"interface", "protocol", "direction"}
	exp := &PrometheusExporter{
		ifaceName: ifaceName,
		log:       log,
		registry:  prometheus.NewRegistry(),
		bytes: prometheus.NewDesc("network_bytes_total",
			"Cumulative skb bytes accounted for in published flow snapshots.", directions, nil),
		packets: prometheus.NewDesc("network_packets_total",
			"Cumulative packets accounted for in published flow snapshots.", directions, nil),
		active: prometheus.NewDesc("network_active_connections",
			"Directional flows with newly observed traffic in the latest complete collection.", []string{"interface", "protocol", "l7_protocol"}, nil),
		entries: prometheus.NewDesc("network_flow_map_entries",
			"Entries in the latest complete flow map collection.", []string{"interface"}, nil),
		failures: prometheus.NewDesc("network_flow_update_failures_total",
			"Eligible hook observations whose flow details could not be recorded.", []string{"interface"}, nil),
		observedBytes: prometheus.NewDesc("network_observed_bytes_total",
			"Cumulative bytes (skb length) in eligible hook observations.", observedDirections, nil),
		observedPackets: prometheus.NewDesc("network_observed_packets_total",
			"Cumulative eligible socket-buffer observations at TCX hooks.", observedDirections, nil),
		skips: prometheus.NewDesc("network_observation_skips_total",
			"Hook observations skipped during protocol parsing.", []string{"interface", "reason"}, nil),
		accounting: prometheus.NewDesc("network_observation_accounting_failures_total",
			"Eligible hook observations that could not update aggregate accounting.", []string{"interface"}, nil),
		capacity: prometheus.NewDesc("network_flow_map_capacity",
			"Configured capacity of a single flow detail generation.", []string{"interface"}, nil),
	}
	exp.current.Store(&publishedMetrics{})
	exp.collection = newCollectionMetrics(ifaceName, exp.registry)
	exp.registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err := exp.registry.Register(exp); err != nil {
		return nil, err
	}
	return exp, nil
}

func (p *PrometheusExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		p.bytes, p.packets, p.active, p.entries, p.failures,
		p.observedBytes, p.observedPackets, p.skips, p.accounting, p.capacity,
	} {
		ch <- desc
	}
}

func (p *PrometheusExporter) Collect(ch chan<- prometheus.Metric) {
	current := p.current.Load()
	for labels, total := range current.totals {
		p.emitTraffic(ch, labels, "ingress", total.ingress)
		p.emitTraffic(ch, labels, "egress", total.egress)
		ch <- prometheus.MustNewConstMetric(p.active, prometheus.GaugeValue,
			float64(current.active[labels]), p.ifaceName, labels.protocol, labels.l7)
	}
	ch <- prometheus.MustNewConstMetric(p.entries, prometheus.GaugeValue, float64(current.entries), p.ifaceName)
	ch <- prometheus.MustNewConstMetric(p.failures, prometheus.CounterValue, float64(current.failures), p.ifaceName)
	ch <- prometheus.MustNewConstMetric(p.capacity, prometheus.GaugeValue, float64(p.cap.Load()), p.ifaceName)

	for _, protocol := range []struct {
		name  string
		pairs [2]bpf.ObservationCount
	}{{"TCP", current.observations.TCP}, {"UDP", current.observations.UDP}} {
		for i, direction := range []string{"ingress", "egress"} {
			count := protocol.pairs[i]
			ch <- prometheus.MustNewConstMetric(p.observedBytes, prometheus.CounterValue,
				float64(count.Bytes), p.ifaceName, protocol.name, direction)
			ch <- prometheus.MustNewConstMetric(p.observedPackets, prometheus.CounterValue,
				float64(count.Packets), p.ifaceName, protocol.name, direction)
		}
	}
	ch <- prometheus.MustNewConstMetric(p.skips, prometheus.CounterValue,
		float64(current.observations.Malformed), p.ifaceName, "malformed")
	ch <- prometheus.MustNewConstMetric(p.skips, prometheus.CounterValue,
		float64(current.observations.Unsupported), p.ifaceName, "unsupported")
	ch <- prometheus.MustNewConstMetric(p.accounting, prometheus.CounterValue,
		float64(current.observations.AccountingFailures), p.ifaceName)
}

func (p *PrometheusExporter) emitTraffic(ch chan<- prometheus.Metric, labels protocolLabels, direction string, value traffic) {
	ch <- prometheus.MustNewConstMetric(p.bytes, prometheus.CounterValue,
		float64(value.bytes), p.ifaceName, labels.protocol, labels.l7, direction)
	ch <- prometheus.MustNewConstMetric(p.packets, prometheus.CounterValue,
		float64(value.packets), p.ifaceName, labels.protocol, labels.l7, direction)
}

// Export adds deltas in each kernel counter. A label change applies to
// subsequent deltas, so historical totals under the old label stay monotonic.
func (p *PrometheusExporter) Export(flows []store.Flow, updateFailures uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.next == nil {
		p.previous = make(map[flowKey]flowCounters, len(flows))
		p.next = make(map[flowKey]flowCounters, len(flows))
	}
	clear(p.next)
	increments := make(map[protocolLabels]totals)
	active := make(map[protocolLabels]uint64)
	for _, flow := range flows {
		key := flowKey{flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, flow.Protocol}
		if _, duplicate := p.next[key]; duplicate {
			continue
		}
		current := flowCounters{
			firstSeen: flow.FirstSeenNs,
			totals: totals{
				ingress: traffic{flow.BytesIngress, flow.PktsIngress},
				egress:  traffic{flow.BytesEgress, flow.PktsEgress},
			},
		}
		p.next[key] = current
		previous := p.previous[key]
		if previous.firstSeen != current.firstSeen {
			previous = flowCounters{}
		}
		inc := diff(current.ingress, previous.ingress)
		out := diff(current.egress, previous.egress)
		if inc == (traffic{}) && out == (traffic{}) {
			continue
		}

		labels := flowLabels(flow)
		increments[labels] = addTotals(increments[labels], totals{inc, out})
		active[labels]++
	}
	p.previous, p.next = p.next, p.previous
	p.publish(increments, active, p.current.Load().observations, updateFailures, len(p.previous))
}

func (p *PrometheusExporter) SetMapCapacity(capacity uint32) { p.cap.Store(capacity) }

// PublishGeneration consumes each sealed generation at most once. The sealed
// counters already describe only that generation, so they need no per-flow
// delta history. Flows must contain one row per tuple.
func (p *PrometheusExporter) PublishGeneration(generation uint64, flows []store.Flow, observations bpf.ObservationTotals, updateFailures uint64) {
	increments := make(map[protocolLabels]totals)
	active := make(map[protocolLabels]uint64)
	for _, flow := range flows {
		labels := flowLabels(flow)
		observed := totals{
			ingress: traffic{flow.BytesIngress, flow.PktsIngress},
			egress:  traffic{flow.BytesEgress, flow.PktsEgress},
		}
		increments[labels] = addTotals(increments[labels], observed)
		active[labels]++
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if generation <= p.lastGeneration {
		return
	}
	p.lastGeneration = generation
	p.publish(increments, active, observations, updateFailures, len(flows))
}

func (p *PrometheusExporter) publish(increments map[protocolLabels]totals, active map[protocolLabels]uint64, observations bpf.ObservationTotals, failures uint64, entries int) {
	previous := p.current.Load()
	all := make(map[protocolLabels]totals, len(previous.totals))
	for labels, total := range previous.totals {
		all[labels] = total
	}
	for labels, inc := range increments {
		all[labels] = addTotals(all[labels], inc)
	}
	p.current.Store(&publishedMetrics{
		totals: all, active: active, observations: observations, failures: failures, entries: entries,
	})
}

func addTotals(a, b totals) totals {
	return totals{
		ingress: traffic{a.ingress.bytes + b.ingress.bytes, a.ingress.packets + b.ingress.packets},
		egress:  traffic{a.egress.bytes + b.egress.bytes, a.egress.packets + b.egress.packets},
	}
}

func flowLabels(flow store.Flow) protocolLabels {
	protocol, l7 := flow.Protocol, flow.L7Protocol
	if protocol != "TCP" && protocol != "UDP" {
		protocol = "unknown"
	}
	switch l7 {
	case "HTTP", "TLS", "DNS", "SSH":
	default:
		l7 = "unknown"
	}
	return protocolLabels{protocol, l7}
}

func diff(current, previous traffic) traffic {
	return traffic{delta(current.bytes, previous.bytes), delta(current.packets, previous.packets)}
}

func delta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func (p *PrometheusExporter) ServeMetrics(ctx context.Context, addr string, registerExtra func(*http.ServeMux)) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	p.log.WithField("addr", ln.Addr()).Info("HTTP server listening")
	return p.serve(ctx, ln, registerExtra)
}

func (p *PrometheusExporter) serve(ctx context.Context, ln net.Listener, registerExtra func(*http.ServeMux)) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	if registerExtra != nil {
		registerExtra(mux)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				http.Error(w, "request body is unexpected", http.StatusBadRequest)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			shutdownErr = errors.Join(shutdownErr, server.Close())
		}
		serveErr := <-done
		if errors.Is(serveErr, http.ErrServerClosed) {
			return shutdownErr
		}
		return errors.Join(shutdownErr, serveErr)
	}
}
