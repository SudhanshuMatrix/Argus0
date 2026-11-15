package store

import (
	"fmt"
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
