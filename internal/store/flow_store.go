// Package store publishes flow snapshots and a bounded traffic history.
package store

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPv4 [4]byte

func (ip IPv4) String() string { return netip.AddrFrom4(ip).String() }

func (ip IPv4) MarshalText() ([]byte, error) {
	return netip.AddrFrom4(ip).MarshalText()
}

func (ip *IPv4) UnmarshalText(text []byte) error {
	addr, err := netip.ParseAddr(string(text))
	if err != nil || !addr.Is4() {
		return errors.New("expected an IPv4 address")
	}
	*ip = addr.As4()
	return nil
}

type Flow struct {
	SrcIP        IPv4      `json:"src_ip"`
	DstIP        IPv4      `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	Protocol     string    `json:"protocol"`
	L7Protocol   string    `json:"l7_protocol,omitempty"`
	BytesIngress uint64    `json:"bytes_ingress"`
	BytesEgress  uint64    `json:"bytes_egress"`
	PktsIngress  uint64    `json:"pkts_ingress"`
	PktsEgress   uint64    `json:"pkts_egress"`
	PID          uint32    `json:"pid,omitempty"`
	FirstSeenNs  uint64    `json:"-"`
	LastSeenNs   uint64    `json:"-"`
	CollectedAt  time.Time `json:"collected_at"`
	LastSeen     time.Time `json:"last_seen"`
	LatencyMs    float64   `json:"latency_ms,omitempty"`
	DurationMs   float64   `json:"duration_ms,omitempty"`
	Recent       bool      `json:"recent"`
}

// Totals counts all eligible hook observations, independently of retained flow details.
type Totals struct {
	BytesIngress uint64 `json:"total_bytes_ingress"`
	BytesEgress  uint64 `json:"total_bytes_egress"`
	PktsIngress  uint64 `json:"total_pkts_ingress"`
	PktsEgress   uint64 `json:"total_pkts_egress"`
}

type Snapshot struct {
	CollectedAt       time.Time
	Flows             []Flow
	ObservationTotals Totals
}

type Stats struct {
	Totals
	CollectedAt   time.Time      `json:"collected_at"`
	TotalFlows    int            `json:"total_flows"`
	RetainedFlows int            `json:"retained_flows"`
	RecentFlows   int            `json:"recent_flows"`
	ByProtocol    map[string]int `json:"by_protocol"`
	History       []HistoryPoint `json:"history"`
}

type HistoryPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	FlowCount int         `json:"flow_count"`
	Rate      TrafficRate `json:"rate"`
}

type TrafficRate struct {
	BytesInPerSecond  float64 `json:"bytes_in_per_second"`
	BytesOutPerSecond float64 `json:"bytes_out_per_second"`
	valid             bool
}

func (r TrafficRate) MarshalJSON() ([]byte, error) {
	if !r.valid {
		return []byte("null"), nil
	}
	type wire TrafficRate
	return json.Marshal(wire(r))
}

type publication struct {
	Snapshot
	generation uint64
	order      []uint32
}

type FlowStore struct {
	mu           sync.RWMutex
	current      *publication
	previous     *publication
	stats        Stats
	history      []HistoryPoint
	historyNext  int
	historyCount int
	generation   uint64
	rateGap      bool
	attached     bool
}

func NewFlowStore(historySize int) *FlowStore {
	return &FlowStore{
		history:    make([]HistoryPoint, historySize),
		generation: uint64(time.Now().UnixNano()),
	}
}

// Write takes ownership of snap.Flows. Published flows are immutable.
func (s *FlowStore) Write(snap Snapshot) {
	order := make([]uint32, len(snap.Flows))
	stats := Stats{
		Totals:        snap.ObservationTotals,
		CollectedAt:   snap.CollectedAt,
		TotalFlows:    len(snap.Flows),
		RetainedFlows: len(snap.Flows),
		ByProtocol:    make(map[string]int, 2),
	}
	for i := range order {
		order[i] = uint32(i)
		f := &snap.Flows[i]
		stats.ByProtocol[f.Protocol]++
		if f.Recent {
			stats.RecentFlows++
		}
	}
	slices.SortFunc(order, func(i, j uint32) int { return compareFlows(&snap.Flows[i], &snap.Flows[j]) })

	s.mu.Lock()
	defer s.mu.Unlock()

	point := HistoryPoint{Timestamp: snap.CollectedAt, FlowCount: len(snap.Flows)}
	if s.current != nil && !s.rateGap {
		point.Rate = rateBetween(s.current.Snapshot, snap)
	}
	s.generation++
	s.previous, s.current = s.current, &publication{Snapshot: snap, generation: s.generation, order: order}
	s.stats = stats
	s.rateGap = false
	s.appendHistory(point)
}

func compareFlows(a, b *Flow) int {
	if a.SrcIP != b.SrcIP {
		return bytes.Compare(a.SrcIP[:], b.SrcIP[:])
	}
	if a.DstIP != b.DstIP {
		return bytes.Compare(a.DstIP[:], b.DstIP[:])
	}
	if c := cmp.Compare(a.SrcPort, b.SrcPort); c != 0 {
		return c
	}
	if c := cmp.Compare(a.DstPort, b.DstPort); c != 0 {
		return c
	}
	return cmp.Compare(a.Protocol, b.Protocol)
}

func rateBetween(before, after Snapshot) TrafficRate {
	elapsed := after.CollectedAt.Sub(before.CollectedAt).Seconds()
	prev, next := before.ObservationTotals, after.ObservationTotals
	if elapsed <= 0 || next.BytesIngress < prev.BytesIngress || next.BytesEgress < prev.BytesEgress ||
		next.PktsIngress < prev.PktsIngress || next.PktsEgress < prev.PktsEgress {
		return TrafficRate{}
	}
	return TrafficRate{
		BytesInPerSecond:  float64(next.BytesIngress-prev.BytesIngress) / elapsed,
		BytesOutPerSecond: float64(next.BytesEgress-prev.BytesEgress) / elapsed,
		valid:             true,
	}
}

func (s *FlowStore) MarkCollectionFailed(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rateGap = true
	s.appendHistory(HistoryPoint{Timestamp: at, FlowCount: s.stats.RetainedFlows})
}

func (s *FlowStore) appendHistory(point HistoryPoint) {
	if len(s.history) == 0 {
		return
	}
	s.history[s.historyNext] = point
	s.historyNext = (s.historyNext + 1) % len(s.history)
	s.historyCount = min(s.historyCount+1, len(s.history))
}

func (s *FlowStore) SetAttached(attached bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attached = attached
}

func (s *FlowStore) LastCollection() (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats.CollectedAt, s.attached
}

func (s *FlowStore) ComputeStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := s.stats
	stats.ByProtocol = maps.Clone(stats.ByProtocol)
	stats.History = make([]HistoryPoint, s.historyCount)
	if s.historyCount == len(s.history) {
		copied := copy(stats.History, s.history[s.historyNext:])
		copy(stats.History[copied:], s.history[:s.historyNext])
	} else {
		copy(stats.History, s.history[:s.historyCount])
	}
	return stats
}

var (
	ErrExpiredCursor = errors.New("flow snapshot expired")
	ErrInvalidCursor = errors.New("invalid flow cursor")
)

type Cursor struct {
	Generation uint64
	Offset     int
}

type FlowPage struct {
	CollectedAt time.Time
	Flows       []Flow
	Next        Cursor
}

type FlowFilter struct {
	address  IPv4
	port     uint16
	protocol string
	isIP     bool
	isPort   bool
}

func ParseFlowFilter(q string) FlowFilter {
	if ip, err := netip.ParseAddr(q); err == nil && ip.Is4() {
		return FlowFilter{address: ip.As4(), isIP: true}
	}
	if port, err := strconv.ParseUint(q, 10, 16); err == nil {
		return FlowFilter{port: uint16(port), isPort: true}
	}
	return FlowFilter{protocol: strings.ToUpper(q)}
}

func (f FlowFilter) matches(flow *Flow) bool {
	switch {
	case f.isIP:
		return f.address == flow.SrcIP || f.address == flow.DstIP
	case f.isPort:
		return f.port == flow.SrcPort || f.port == flow.DstPort
	default:
		return strings.HasPrefix(flow.Protocol, f.protocol) || strings.HasPrefix(flow.L7Protocol, f.protocol) ||
			(flow.L7Protocol == "" && strings.HasPrefix("UNKNOWN", f.protocol))
	}
}

// Page copies only matching rows. It holds a reference to one immutable generation for the walk.
func (s *FlowStore) Page(ctx context.Context, cursor Cursor, limit int, filter FlowFilter) (FlowPage, error) {
	s.mu.RLock()
	snap, previous := s.current, s.previous
	s.mu.RUnlock()

	if cursor.Generation != 0 && (snap == nil || cursor.Generation != snap.generation) {
		if previous == nil || cursor.Generation != previous.generation {
			return FlowPage{}, ErrExpiredCursor
		}
		snap = previous
	}
	if snap == nil {
		return FlowPage{Flows: []Flow{}}, nil
	}
	if cursor.Offset < 0 || (cursor.Generation != 0 && cursor.Offset >= len(snap.Flows)) {
		return FlowPage{}, ErrInvalidCursor
	}
	page := FlowPage{
		CollectedAt: snap.CollectedAt,
		Flows:       make([]Flow, 0, min(limit, len(snap.Flows)-cursor.Offset)),
	}
	for i := cursor.Offset; i < len(snap.Flows); i++ {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return FlowPage{}, err
			}
		}
		flow := &snap.Flows[snap.order[i]]
		if !filter.matches(flow) {
			continue
		}
		if len(page.Flows) == limit {
			page.Next = Cursor{Generation: snap.generation, Offset: i}
			break
		}
		page.Flows = append(page.Flows, *flow)
	}
	return page, ctx.Err()
}
