package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

var benchmarkStats Stats

func BenchmarkComputeStats(b *testing.B) {
	for _, size := range []int{100, 10000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := NewFlowStore(60)
			sample := Snapshot{CollectedAt: time.Now(), Flows: make([]Flow, size)}
			for i := range sample.Flows {
				sample.Flows[i] = Flow{Protocol: "TCP", BytesEgress: 1024, PktsEgress: 2}
			}
			s.Write(sample)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkStats = s.ComputeStats()
			}
		})
	}
}

func TestHistoryRates(t *testing.T) {
	s := NewFlowStore(4)
	start := time.Unix(100, 0)
	write := func(seconds int, in, out uint64) HistoryPoint {
		t.Helper()
		at := start.Add(time.Duration(seconds) * time.Second)
		s.Write(Snapshot{CollectedAt: at, ObservationTotals: Totals{BytesIngress: in, BytesEgress: out}})
		stats := s.ComputeStats()
		if stats.BytesIngress != in || stats.BytesEgress != out {
			t.Fatalf("aggregate totals must come from observations, even with no retained flows: %+v", stats)
		}
		return stats.History[len(stats.History)-1]
	}
	if p := write(0, 110, 200); p.Rate.valid {
		t.Fatalf("first sample unexpectedly has a rate: %+v", p)
	}
	if p := write(4, 110, 200); !p.Rate.valid || p.Rate.BytesInPerSecond != 0 || p.Rate.BytesOutPerSecond != 0 {
		t.Fatalf("unchanged counters must produce a valid zero rate: %+v", p)
	}
	if p := write(6, 310, 500); !p.Rate.valid || p.Rate.BytesInPerSecond != 100 || p.Rate.BytesOutPerSecond != 150 {
		t.Fatalf("rate must use actual elapsed time: %+v", p)
	}
	s.MarkCollectionFailed(start.Add(8 * time.Second))
	if stats := s.ComputeStats(); stats.History[3].Rate.valid || stats.BytesIngress != 310 {
		t.Fatalf("failed collection must keep published totals and mark a gap: %+v", stats)
	}
	if p := write(10, 500, 1000); p.Rate.valid {
		t.Fatalf("recovery interval must preserve the gap: %+v", p)
	}
	if p := write(12, 2, 3); p.Rate.valid {
		t.Fatalf("counter reset must mark a gap: %+v", p)
	}
	if p := write(14, 10, 15); !p.Rate.valid || p.Rate.BytesInPerSecond != 4 || p.Rate.BytesOutPerSecond != 6 {
		t.Fatalf("expected normal throughput after reset: %+v", p)
	}
	history := s.ComputeStats().History
	if len(history) != 4 || !history[0].Timestamp.Equal(start.Add(8*time.Second)) {
		t.Fatalf("history must stay bounded and chronological: %+v", history)
	}
}

func TestPublishedDataIsIsolated(t *testing.T) {
	s := NewFlowStore(2)
	s.Write(Snapshot{CollectedAt: time.Now(), Flows: []Flow{
		{Protocol: "TCP", SrcIP: IPv4{198, 18, 0, 1}, Recent: true},
		{Protocol: "UDP", SrcIP: IPv4{198, 18, 0, 2}},
	}})

	stats := s.ComputeStats()
	if stats.RetainedFlows != 2 || stats.RecentFlows != 1 {
		t.Fatalf("unexpected flow counts: %+v", stats)
	}
	stats.ByProtocol["UDP"] = 99
	stats.History[0].FlowCount = 99

	page, err := s.Page(context.Background(), Cursor{}, 1, ParseFlowFilter("198.18.0.2"))
	if err != nil || len(page.Flows) != 1 {
		t.Fatalf("wrong filtered result: %+v, %v", page, err)
	}
	page.Flows[0].Protocol = "mutated"

	stats = s.ComputeStats()
	page, err = s.Page(context.Background(), Cursor{}, 1, ParseFlowFilter("udp"))
	if err != nil || len(page.Flows) != 1 || stats.ByProtocol["UDP"] != 1 || stats.History[0].FlowCount != 2 {
		t.Fatalf("caller mutated publication: %+v, %+v, %v", stats, page, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Page(ctx, Cursor{}, 1, ParseFlowFilter("")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func BenchmarkPublish(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := NewFlowStore(60)
			sample := benchmarkFlows(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Write(Snapshot{CollectedAt: time.Now(), Flows: slices.Clone(sample)})
			}
		})
	}
}

func BenchmarkPage(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := NewFlowStore(60)
			s.Write(Snapshot{CollectedAt: time.Now(), Flows: benchmarkFlows(size)})
			ctx := context.Background()
			filter := ParseFlowFilter("")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Page(ctx, Cursor{}, 100, filter); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkFlows(size int) []Flow {
	rows := make([]Flow, size)
	for i := range rows {
		unique := (size - i) * 6553 % (1 << 24)
		rows[i] = Flow{
			SrcIP:        IPv4{10, byte(unique >> 16), byte(unique >> 8), byte(unique)},
			DstIP:        IPv4{198, 18, 0, 1},
			SrcPort:      49152,
			DstPort:      443,
			Protocol:     "TCP",
			BytesIngress: 1024,
			PktsIngress:  2,
		}
	}
	return rows
}
