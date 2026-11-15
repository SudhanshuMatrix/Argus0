package exporter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
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
	srcIP, dstIP     string
	srcPort, dstPort uint16
	protocol         string
}

type flowCounters struct {
	firstSeen uint64
	totals
}

type PrometheusExporter struct {
	mu        sync.RWMutex
	ifaceName string
	log       *logrus.Logger
	registry  *prometheus.Registry

	bytes, packets, active, entries, failures *prometheus.Desc

	totals    map[protocolLabels]totals
	activeNow map[protocolLabels]uint64
	previous  map[flowKey]flowCounters
	next      map[flowKey]flowCounters
	failed    uint64
}

// Each agent has its own registry so it can be started and stopped in process.
func NewPrometheusExporter(ifaceName string, log *logrus.Logger) (*PrometheusExporter, error) {
	directions := []string{"interface", "protocol", "l7_protocol", "direction"}
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
			"Cumulative packets the BPF flow map could not account for.", []string{"interface"}, nil),
		totals:   make(map[protocolLabels]totals),
		previous: make(map[flowKey]flowCounters),
		next:     make(map[flowKey]flowCounters),
	}
	exp.registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err := exp.registry.Register(exp); err != nil {
		return nil, err
	}
	return exp, nil
}

func (p *PrometheusExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.bytes
	ch <- p.packets
	ch <- p.active
	ch <- p.entries
	ch <- p.failures
}

func (p *PrometheusExporter) Collect(ch chan<- prometheus.Metric) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for labels, total := range p.totals {
		p.emitTraffic(ch, labels, "ingress", total.ingress)
		p.emitTraffic(ch, labels, "egress", total.egress)
		ch <- prometheus.MustNewConstMetric(p.active, prometheus.GaugeValue,
			float64(p.activeNow[labels]), p.ifaceName, labels.protocol, labels.l7)
	}
	ch <- prometheus.MustNewConstMetric(p.entries, prometheus.GaugeValue, float64(len(p.previous)), p.ifaceName)
	ch <- prometheus.MustNewConstMetric(p.failures, prometheus.CounterValue, float64(p.failed), p.ifaceName)
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

	clear(p.next)
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

		l7 := flow.L7Protocol
		if l7 == "" {
			l7 = "unknown"
		}
		labels := protocolLabels{flow.Protocol, l7}
		total := p.totals[labels]
		total.ingress.bytes += inc.bytes
		total.ingress.packets += inc.packets
		total.egress.bytes += out.bytes
		total.egress.packets += out.packets
		p.totals[labels] = total
		active[labels]++
	}
	p.activeNow = active
	p.previous, p.next = p.next, p.previous
	p.failed = updateFailures
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
	ln, err := net.Listen("tcp", addr)
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

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
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
