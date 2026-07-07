// network flows. The collector writes here after each BPF map read; the HTTP
// API handlers read from here to serve the dashboard and JSON endpoints.
package store

import (
	"sync"
	"time"
)

type Flow struct {
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	Protocol     string    `json:"protocol"`
	L7Protocol   string    `json:"l7_protocol,omitempty"`
	BytesIngress uint64    `json:"bytes_ingress"`
	BytesEgress  uint64    `json:"bytes_egress"`
	PktsIngress  uint32    `json:"pkts_ingress"`
	PktsEgress   uint32    `json:"pkts_egress"`
	PID          uint32    `json:"pid"`
	ProcessName  string    `json:"process_name"`
	ContainerID  string    `json:"container_id,omitempty"`
	CollectedAt  time.Time `json:"collected_at"`
	LatencyMs    float64   `json:"latency_ms,omitempty"`
	DurationMs   float64   `json:"duration_ms,omitempty"`
}

// Snapshot represents a full collection interval — all flows seen at one tick.
type Snapshot struct {
	CollectedAt time.Time `json:"collected_at"`
	Flows       []Flow    `json:"flows"`
}

// Stats aggregates totals across the most recent snapshot.
type Stats struct {
	CollectedAt   time.Time      `json:"collected_at"`
	TotalFlows    int            `json:"total_flows"`
	TotalBytesIn  uint64         `json:"total_bytes_ingress"`
	TotalBytesOut uint64         `json:"total_bytes_egress"`
	TotalPktsIn   uint64         `json:"total_pkts_ingress"`
	TotalPktsOut  uint64         `json:"total_pkts_egress"`
	ByProtocol    map[string]int `json:"by_protocol"`
	TopProcesses  []ProcessStat  `json:"top_processes"`
	History       []HistoryPoint `json:"history"` // last N intervals
}

// ProcessStat aggregates bytes/packets per process name.
type ProcessStat struct {
	Name         string `json:"name"`
	PID          uint32 `json:"pid"`
	BytesIngress uint64 `json:"bytes_ingress"`
	BytesEgress  uint64 `json:"bytes_egress"`
	FlowCount    int    `json:"flow_count"`
}

// HistoryPoint is one data point in the traffic time-series chart.
type HistoryPoint struct {
	Timestamp time.Time `json:"timestamp"`
	BytesIn   uint64    `json:"bytes_in"`
	BytesOut  uint64    `json:"bytes_out"`
	FlowCount int       `json:"flow_count"`
}

// latest snapshot and the history ring.
type FlowStore struct {
	mu          sync.RWMutex
	latest      *Snapshot
	history     []HistoryPoint
	historySize int // max ring buffer length
}

// NewFlowStore creates a FlowStore that retains up to historySize time-series
// data points (one per collection interval). 60 points ≈ 5 minutes at 5s intervals.
func NewFlowStore(historySize int) *FlowStore {
	return &FlowStore{
		historySize: historySize,
		history:     make([]HistoryPoint, 0, historySize),
	}
}

// Write stores a new snapshot. Called by the collector goroutine.
func (s *FlowStore) Write(snap Snapshot) {
	// Build a history point from the snapshot totals.
	var bytesIn, bytesOut uint64
	for _, f := range snap.Flows {
		bytesIn += f.BytesIngress
		bytesOut += f.BytesEgress
	}
	point := HistoryPoint{
		Timestamp: snap.CollectedAt,
		BytesIn:   bytesIn,
		BytesOut:  bytesOut,
		FlowCount: len(snap.Flows),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.latest = &snap

	// Append and trim to historySize (ring buffer).
	s.history = append(s.history, point)
	if len(s.history) > s.historySize {
		s.history = s.history[len(s.history)-s.historySize:]
	}
}

// LatestFlows returns a copy of the flows from the most recent snapshot.
// Returns nil if no data has been written yet.
func (s *FlowStore) LatestFlows() []Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.latest == nil {
		return nil
	}
	// Return a copy to avoid data races in callers.
	cp := make([]Flow, len(s.latest.Flows))
	copy(cp, s.latest.Flows)
	return cp
}

// ComputeStats builds a Stats summary from the current snapshot + history.
func (s *FlowStore) ComputeStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		CollectedAt: time.Now(),
		ByProtocol:  make(map[string]int),
		History:     make([]HistoryPoint, len(s.history)),
	}
	copy(stats.History, s.history)

	if s.latest == nil {
		return stats
	}
	stats.CollectedAt = s.latest.CollectedAt

	// Per-process aggregation map.
	procMap := make(map[uint32]*ProcessStat)

	for _, f := range s.latest.Flows {
		stats.TotalFlows++
		stats.TotalBytesIn += f.BytesIngress
		stats.TotalBytesOut += f.BytesEgress
		stats.TotalPktsIn += uint64(f.PktsIngress)
		stats.TotalPktsOut += uint64(f.PktsEgress)
		stats.ByProtocol[f.Protocol]++

		// Aggregate per PID.
		if f.PID > 0 {
			ps, ok := procMap[f.PID]
			if !ok {
				ps = &ProcessStat{
					Name: f.ProcessName,
					PID:  f.PID,
				}
				procMap[f.PID] = ps
			}
			ps.BytesIngress += f.BytesIngress
			ps.BytesEgress += f.BytesEgress
			ps.FlowCount++
		}
	}

	// Convert process map to sorted slice (top 10 by total bytes).
	for _, ps := range procMap {
		stats.TopProcesses = append(stats.TopProcesses, *ps)
	}
	sortProcessStats(stats.TopProcesses)
	if len(stats.TopProcesses) > 10 {
		stats.TopProcesses = stats.TopProcesses[:10]
	}

	return stats
}

// sortProcessStats sorts descending by (BytesIngress + BytesEgress).
func sortProcessStats(ps []ProcessStat) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0; j-- {
			totalJ := ps[j].BytesIngress + ps[j].BytesEgress
			totalJ1 := ps[j-1].BytesIngress + ps[j-1].BytesEgress
			if totalJ > totalJ1 {
				ps[j], ps[j-1] = ps[j-1], ps[j]
			} else {
				break
			}
		}
	}
}
