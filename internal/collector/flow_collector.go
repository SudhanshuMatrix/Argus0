// Package collector reads flow data from BPF maps, enriches it with process
// and container metadata, and forwards the enriched records to exporters.
package collector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	internalbpf "github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/enricher"
	"github.com/sudhanshu-singh/argus/internal/exporter"
	"github.com/sudhanshu-singh/argus/internal/store"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

// Flow is the fully enriched representation of a network flow that gets
// published to exporters. It combines the raw BPF 5-tuple + counters with
// the process and container metadata added by the enricher.
type Flow struct {
	// --- 5-tuple ---
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   string `json:"protocol"`
	L7Protocol string `json:"l7_protocol,omitempty"`

	// --- Counters ---
	BytesIngress uint64 `json:"bytes_ingress"`
	BytesEgress  uint64 `json:"bytes_egress"`
	PktsIngress  uint32 `json:"pkts_ingress"`
	PktsEgress   uint32 `json:"pkts_egress"`

	// --- Process attribution ---
	PID           uint32 `json:"pid"`
	ProcessName   string `json:"process_name"`
	ContainerID   string `json:"container_id,omitempty"`

	// --- Timing ---
	LastSeenNs    uint64    `json:"last_seen_ns"`
	CollectedAt   time.Time `json:"collected_at"`
	LatencyMs     float64   `json:"latency_ms,omitempty"`
	DurationMs    float64   `json:"duration_ms,omitempty"`
}

// Collector periodically reads the BPF flow_map, enriches each entry, and
// delivers the results to all registered exporters.
type Collector struct {
	bpfObjs   *internalbpf.Objects
	enricher  *enricher.ProcessEnricher
	exporters []exporter.Exporter
	interval  time.Duration
	log       *logrus.Logger
	store     *store.FlowStore
}

// NewCollector constructs a Collector.
//
// Parameters:
//   - bpfObjs:   the loaded eBPF objects (provides map access)
//   - procEnricher: process/container metadata enricher
//   - exporters: list of exporters to send enriched flows to
//   - interval:  how often to read the BPF map
//   - log:       structured logger
//   - store:     in-memory ring buffer store for dashboard UI
func NewCollector(
	bpfObjs *internalbpf.Objects,
	procEnricher *enricher.ProcessEnricher,
	exporters []exporter.Exporter,
	interval time.Duration,
	log *logrus.Logger,
	store *store.FlowStore,
) *Collector {
	return &Collector{
		bpfObjs:   bpfObjs,
		enricher:  procEnricher,
		exporters: exporters,
		interval:  interval,
		log:       log,
		store:     store,
	}
}

// Run starts the collection loop. It blocks until ctx is cancelled.
// On cancellation it performs one final collection pass to flush data, then
// returns. The caller should call bpfObjs.Close() after Run returns.
func (c *Collector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.log.WithField("interval", c.interval).Info("Flow collector started")

	for {
		select {
		case <-ctx.Done():
			c.log.Info("Flow collector shutting down, performing final collection...")
			c.collect()
			return ctx.Err()

		case <-ticker.C:
			c.collect()
		}
	}
}

// collect performs a single pass: iterate the BPF map, enrich each entry,
// and dispatch to all exporters. Errors on individual flows are logged but
// do not abort the whole pass — observability should be best-effort.
func (c *Collector) collect() {
	collectedAt := time.Now()
	flowMap := c.bpfObjs.FlowMap()

	flows, err := c.readFlows(flowMap, collectedAt)
	if err != nil {
		c.log.WithError(err).Error("Failed to read BPF flow map")
		return
	}

	c.log.WithField("count", len(flows)).Debug("Read flows from BPF map")

	// Convert to store.Flow for in-memory caching in the UI store
	storeFlows := make([]store.Flow, len(flows))
	for i, f := range flows {
		storeFlows[i] = store.Flow{
			SrcIP:        f.SrcIP,
			DstIP:        f.DstIP,
			SrcPort:      f.SrcPort,
			DstPort:      f.DstPort,
			Protocol:     f.Protocol,
			L7Protocol:   f.L7Protocol,
			BytesIngress: f.BytesIngress,
			BytesEgress:  f.BytesEgress,
			PktsIngress:  f.PktsIngress,
			PktsEgress:   f.PktsEgress,
			PID:          f.PID,
			ProcessName:  f.ProcessName,
			ContainerID:  f.ContainerID,
			CollectedAt:  f.CollectedAt,
			LatencyMs:    f.LatencyMs,
			DurationMs:   f.DurationMs,
		}
	}
	if c.store != nil {
		c.store.Write(store.Snapshot{
			CollectedAt: collectedAt,
			Flows:       storeFlows,
		})
	}

	// Print to stdout in JSON (Phase 1 requirement).
	c.printFlowsJSON(flows)

	// Forward to all registered exporters.
	for _, exp := range c.exporters {
		exp.Export(storeFlows)
	}
}

// readFlows iterates the BPF hash map using the MapIterator API from
// cilium/ebpf, which internally uses the BPF_MAP_GET_NEXT_KEY syscall.
//
// IMPORTANT: The BPF map can be modified by the kernel while we are
// iterating (packets arriving during the walk). cilium/ebpf's iterator
// handles this gracefully — it may miss entries added after the walk starts
// or see entries twice if they are rehashed, but it never panics or corrupts.
// For observability this is acceptable.
func (c *Collector) readFlows(flowMap *ebpf.Map, collectedAt time.Time) ([]Flow, error) {
	var (
		key   internalbpf.FlowKey
		value internalbpf.FlowMetrics
		flows []Flow
	)

	iter := flowMap.Iterate()
	for iter.Next(&key, &value) {
		flow, err := c.buildFlow(key, value, collectedAt)
		if err != nil {
			c.log.WithError(err).Warn("Failed to build flow entry; skipping")
			continue
		}
		flows = append(flows, flow)
	}

	// iter.Err() is non-nil only on a fatal iteration error (e.g., map closed).
	if err := iter.Err(); err != nil {
		return flows, fmt.Errorf("iterating flow map: %w", err)
	}

	return flows, nil
}

// buildFlow converts a raw BPF key+value pair into a fully enriched Flow.
func (c *Collector) buildFlow(
	key internalbpf.FlowKey,
	metrics internalbpf.FlowMetrics,
	collectedAt time.Time,
) (Flow, error) {
	// Convert raw IP addresses (network byte order u32) to dotted-quad strings.
	srcIP := intToIPv4(key.SrcIp)
	dstIP := intToIPv4(key.DstIp)

	// Port fields are in network byte order in the BPF map; convert to host
	// order for presentation.
	srcPort := networkToHostU16(key.SrcPort)
	dstPort := networkToHostU16(key.DstPort)

	var latencyMs float64
	if metrics.LatencyNs > 0 {
		latencyMs = float64(metrics.LatencyNs) / 1000000.0
	}

	var durationMs float64
	if metrics.LastSeenNs >= metrics.FirstSeenNs && metrics.FirstSeenNs > 0 {
		durationMs = float64(metrics.LastSeenNs - metrics.FirstSeenNs) / 1000000.0
	}

	flow := Flow{
		SrcIP:        srcIP.String(),
		DstIP:        dstIP.String(),
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Protocol:     protocolName(key.Protocol),
		L7Protocol:   l7ProtocolName(metrics.L7Proto),
		BytesIngress: metrics.BytesIngress,
		BytesEgress:  metrics.BytesEgress,
		PktsIngress:  metrics.PktsIngress,
		PktsEgress:   metrics.PktsEgress,
		PID:          metrics.Pid,
		LastSeenNs:   metrics.LastSeenNs,
		CollectedAt:  collectedAt,
		LatencyMs:    latencyMs,
		DurationMs:   durationMs,
	}

	// Enrich with process name and container ID from /proc.
	// Errors here are non-fatal: the process may have exited by now.
	if metrics.Pid > 0 {
		procInfo, err := c.enricher.Enrich(metrics.Pid)
		if err != nil {
			c.log.WithFields(logrus.Fields{
				"pid": metrics.Pid,
			}).Debug("Could not enrich process info (process may have exited)")
		} else {
			flow.ProcessName = procInfo.Name
			flow.ContainerID = procInfo.ContainerID
		}
	}

	return flow, nil
}

// printFlowsJSON marshals flows to JSON and writes them to stdout.
// Each flow is printed on its own line (JSON Lines format) for easy
// piping to tools like jq.
func (c *Collector) printFlowsJSON(flows []Flow) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	for _, f := range flows {
		if err := encoder.Encode(f); err != nil {
			c.log.WithError(err).Warn("Failed to JSON-encode flow")
		}
	}
}

// intToIPv4 converts a 32-bit integer in network byte order to a net.IP.
// The BPF map stores IPv4 addresses as __u32 in network byte order (big-endian
// on all architectures because the kernel maintains them that way).
func intToIPv4(ip uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b)
}

// networkToHostU16 converts a uint16 from network byte order to host byte order.
func networkToHostU16(n uint16) uint16 {
	b := [2]byte{byte(n >> 8), byte(n)}
	return binary.LittleEndian.Uint16(b[:])
}

// protocolName returns the human-readable IANA protocol name for common
// protocol numbers, falling back to the numeric string for unknown ones.
func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

// l7ProtocolName converts the raw eBPF L7 protocol identifier to a string representation.
func l7ProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "HTTP"
	case 2:
		return "TLS"
	case 3:
		return "DNS"
	case 4:
		return "SSH"
	default:
		return ""
	}
}
