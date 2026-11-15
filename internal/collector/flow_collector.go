// Package collector reads BPF flow snapshots and forwards them to the store
// and registered exporters.
package collector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/exporter"
	"github.com/sudhanshu-singh/argus/internal/store"
)

type Collector struct {
	bpfObjs   *bpf.Objects
	exporters []exporter.Exporter
	interval  time.Duration
	log       *logrus.Logger
	store     *store.FlowStore
}

func NewCollector(objects *bpf.Objects, exporters []exporter.Exporter, interval time.Duration, log *logrus.Logger, flowStore *store.FlowStore) *Collector {
	return &Collector{objects, exporters, interval, log, flowStore}
}

// Run performs one final collection on cancellation. The caller releases the
// BPF objects after Run returns.
func (c *Collector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.collect()
			return ctx.Err()
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) collect() {
	collectedAt := time.Now()
	var flows []store.Flow
	var key bpf.FlowKey
	var value bpf.FlowMetrics
	iter := c.bpfObjs.FlowMap().Iterate()
	for iter.Next(&key, &value) {
		flows = append(flows, buildFlow(key, value, collectedAt))
	}
	if err := iter.Err(); err != nil {
		c.log.WithError(err).Error("Failed to read BPF flow map")
		return
	}
	failures, err := c.bpfObjs.FlowUpdateFailures()
	if err != nil {
		c.log.WithError(err).Error("Failed to read BPF flow update failures")
		return
	}

	if c.store != nil {
		c.store.Write(store.Snapshot{CollectedAt: collectedAt, Flows: flows})
	}
	for _, exp := range c.exporters {
		exp.Export(flows, failures)
	}
	c.log.WithFields(logrus.Fields{
		"count": len(flows), "duration_ns": time.Since(collectedAt).Nanoseconds(),
		"flow_update_failures": failures,
	}).Debug("Published BPF flow snapshot")

	// The flow dump is useful for diagnostics, but serializing every flow at
	// every interval can dominate the agent's CPU and disk usage.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		encoder := json.NewEncoder(os.Stdout)
		for _, flow := range flows {
			if err := encoder.Encode(flow); err != nil {
				c.log.WithError(err).Warn("Failed to write flow JSON")
				break
			}
		}
	}
}

func buildFlow(key bpf.FlowKey, metrics bpf.FlowMetrics, collectedAt time.Time) store.Flow {
	var durationMs float64
	if metrics.LastSeenNs >= metrics.FirstSeenNs && metrics.FirstSeenNs > 0 {
		durationMs = float64(metrics.LastSeenNs-metrics.FirstSeenNs) / float64(time.Millisecond)
	}
	return store.Flow{
		SrcIP:        ipv4String(key.SrcIp),
		DstIP:        ipv4String(key.DstIp),
		SrcPort:      networkToHostU16(key.SrcPort),
		DstPort:      networkToHostU16(key.DstPort),
		Protocol:     protocolName(key.Protocol),
		L7Protocol:   l7ProtocolName(metrics.L7Proto),
		BytesIngress: metrics.BytesIngress,
		BytesEgress:  metrics.BytesEgress,
		PktsIngress:  metrics.PktsIngress,
		PktsEgress:   metrics.PktsEgress,
		FirstSeenNs:  metrics.FirstSeenNs,
		CollectedAt:  collectedAt,
		DurationMs:   durationMs,
	}
}

func ipv4String(ip uint32) string {
	var bytes [4]byte
	binary.NativeEndian.PutUint32(bytes[:], ip)
	return netip.AddrFrom4(bytes).String()
}

func networkToHostU16(n uint16) uint16 {
	var bytes [2]byte
	binary.NativeEndian.PutUint16(bytes[:], n)
	return binary.BigEndian.Uint16(bytes[:])
}

func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

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
