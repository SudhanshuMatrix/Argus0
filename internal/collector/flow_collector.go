// Package collector reads sealed BPF flow maps and publishes complete snapshots.
package collector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/exporter"
	"github.com/sudhanshu-singh/argus/internal/store"
	"golang.org/x/sys/unix"
)

type Collector struct {
	bpfObjs    *bpf.Objects
	exporter   *exporter.PrometheusExporter
	capacity   uint32
	interval   time.Duration
	log        *logrus.Logger
	store      *store.FlowStore
	reader     mapReader
	generation uint64
}

func NewCollector(objects *bpf.Objects, exp *exporter.PrometheusExporter, capacity uint32, interval time.Duration, log *logrus.Logger, flowStore *store.FlowStore) *Collector {
	exp.SetMapCapacity(capacity)
	return &Collector{bpfObjs: objects, exporter: exp, capacity: capacity, interval: interval, log: log, store: flowStore}
}

func (c *Collector) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	scheduled := time.Now()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.runCollection(ctx, scheduled, c.interval, false)
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case scheduled := <-ticker.C:
			if ctx.Err() == nil {
				c.runCollection(ctx, scheduled, c.interval, false)
			}
		}
	}

	c.runCollection(context.Background(), time.Now(), min(500*time.Millisecond, c.interval), true)
	return ctx.Err()
}

func (c *Collector) runCollection(parent context.Context, scheduled time.Time, budget time.Duration, final bool) {
	started := time.Now()
	result := exporter.CollectionResult{Lag: started.Sub(scheduled), Final: final}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	flows, err := c.collect(ctx, &result)
	result.Duration = time.Since(started)
	result.Overrun = !final && result.Duration >= c.interval
	if err != nil {
		c.store.MarkCollectionFailed(started)
		c.log.WithFields(logrus.Fields{"stage": result.ErrorStage, "duration": result.Duration}).WithError(err).Warn("Flow collection failed")
	}
	c.exporter.RecordCollection(result)
	if err == nil && !final && c.log.IsLevelEnabled(logrus.TraceLevel) {
		encoder := json.NewEncoder(os.Stdout)
		for _, flow := range flows {
			if ctx.Err() != nil {
				break
			}
			if err := encoder.Encode(flow); err != nil {
				c.log.WithError(err).Warn("Failed to write flow JSON")
				break
			}
		}
	}
}

func (c *Collector) collect(ctx context.Context, result *exporter.CollectionResult) ([]store.Flow, error) {
	result.ErrorStage = "attachment"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.bpfObjs.CheckInterface(); err != nil {
		c.store.SetAttached(false)
		return nil, err
	}

	result.ErrorStage = "rotation"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sealed, err := c.bpfObjs.RotateFlowMap()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := sealed.Close(); err != nil {
			c.log.WithError(err).Warn("Failed to close sealed flow map")
		}
	}()
	c.generation++
	result.Discarded = true

	result.ErrorStage = "read_counters"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clock := flowClock{wall: time.Now(), recent: c.interval}
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return nil, err
	}
	clock.monoNS = uint64(mono.Nano())
	observations, err := c.bpfObjs.ObservationTotals()
	if err != nil {
		return nil, err
	}
	failures, err := c.bpfObjs.FlowUpdateFailures()
	if err != nil {
		return nil, err
	}

	result.ErrorStage = "read_flows"
	walkStarted := time.Now()
	flows, err := c.reader.read(ctx, kernelFlowMap{sealed}, int(c.capacity), clock)
	result.MapRead = time.Since(walkStarted)
	if err != nil {
		return nil, err
	}

	result.ErrorStage = "publication"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.store.Write(store.Snapshot{
		CollectedAt: clock.wall, Flows: flows,
		ObservationTotals: store.Totals{
			BytesIngress: observations.TCP[0].Bytes + observations.UDP[0].Bytes,
			BytesEgress:  observations.TCP[1].Bytes + observations.UDP[1].Bytes,
			PktsIngress:  observations.TCP[0].Packets + observations.UDP[0].Packets,
			PktsEgress:   observations.TCP[1].Packets + observations.UDP[1].Packets,
		},
	})
	c.exporter.PublishGeneration(c.generation, flows, observations, failures)
	c.store.SetAttached(true)
	result.ErrorStage = ""
	result.Published = time.Now()
	result.Discarded = false
	c.log.WithFields(logrus.Fields{
		"count": len(flows), "duration_ns": result.Published.Sub(clock.wall).Nanoseconds(),
		"flow_update_failures": failures,
	}).Debug("Published BPF flow snapshot")
	return flows, nil
}

func buildFlow(key bpf.FlowKey, metrics bpf.FlowMetrics, clock flowClock) store.Flow {
	var durationMs float64
	if metrics.LastSeenNs >= metrics.FirstSeenNs && metrics.FirstSeenNs > 0 {
		durationMs = float64(metrics.LastSeenNs-metrics.FirstSeenNs) / float64(time.Millisecond)
	}
	var lastSeen time.Time
	var recent bool
	if metrics.LastSeenNs > 0 && metrics.LastSeenNs <= clock.monoNS {
		age := time.Duration(clock.monoNS - metrics.LastSeenNs)
		lastSeen = clock.wall.Add(-age)
		recent = age <= clock.recent
	}
	return store.Flow{
		SrcIP:        ipv4Address(key.SrcIp),
		DstIP:        ipv4Address(key.DstIp),
		SrcPort:      networkToHostU16(key.SrcPort),
		DstPort:      networkToHostU16(key.DstPort),
		Protocol:     protocolName(key.Protocol),
		L7Protocol:   l7ProtocolName(metrics.L7Proto),
		BytesIngress: metrics.BytesIngress,
		BytesEgress:  metrics.BytesEgress,
		PktsIngress:  metrics.PktsIngress,
		PktsEgress:   metrics.PktsEgress,
		FirstSeenNs:  metrics.FirstSeenNs,
		LastSeenNs:   metrics.LastSeenNs,
		LastSeen:     lastSeen,
		Recent:       recent,
		CollectedAt:  clock.wall,
		DurationMs:   durationMs,
	}
}

func ipv4Address(ip uint32) store.IPv4 {
	var address store.IPv4
	binary.NativeEndian.PutUint32(address[:], ip)
	return address
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
		return "unknown"
	}
}

func l7ProtocolName(proto uint32) string {
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
