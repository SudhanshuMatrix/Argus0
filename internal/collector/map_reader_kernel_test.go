//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/store"
)

func kernelMapFixture(t testing.TB, rows []mapEntry) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(binary.Size(bpf.FlowKey{})),
		ValueSize: uint32(binary.Size(bpf.FlowMetrics{})), MaxEntries: uint32(len(rows)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	for _, row := range rows {
		if err := m.Put(row.key, row.value); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestKernelBatchMatchesIterator(t *testing.T) {
	if os.Getenv("ARGUS_BPF_TEST") != "1" {
		t.Skip("set ARGUS_BPF_TEST=1 in a privileged Linux test environment")
	}
	rows := mapEntries(batchSize + 7)
	m := kernelMapFixture(t, rows)
	ctx := context.Background()
	clock := flowClock{wall: time.Now(), monoNS: uint64(len(rows) + 5)}
	batch := mapReader{}
	got, err := batch.read(ctx, kernelFlowMap{m}, len(rows), clock)
	if err != nil {
		t.Fatal(err)
	}
	if batch.batchUnsupported {
		t.Fatal("expected kernel batch support on a TCX test kernel")
	}
	iter := mapReader{batchUnsupported: true}
	want, err := iter.read(ctx, kernelFlowMap{m}, len(rows), clock)
	if err != nil {
		t.Fatal(err)
	}
	sortBySourcePort := func(flows []store.Flow) {
		slices.SortFunc(flows, func(a, b store.Flow) int { return int(a.SrcPort) - int(b.SrcPort) })
	}
	sortBySourcePort(got)
	sortBySourcePort(want)
	if len(want) != len(rows) || !reflect.DeepEqual(got, want) {
		t.Fatalf("batch read %d of %d tuples or returned different field values", len(got), len(want))
	}
}

// BenchmarkKernelReadMap compares lookup paths for the same sealed fixture.
func BenchmarkKernelReadMap(b *testing.B) {
	if os.Getenv("ARGUS_BPF_TEST") != "1" {
		b.Skip("set ARGUS_BPF_TEST=1 in a privileged Linux test environment")
	}
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m := kernelMapFixture(b, mapEntries(count))
			for _, mode := range []struct {
				name     string
				iterator bool
			}{{"batch", false}, {"iterator", true}} {
				b.Run(mode.name, func(b *testing.B) {
					r := mapReader{batchUnsupported: mode.iterator}
					ctx := context.Background()
					clock := flowClock{wall: time.Now(), monoNS: uint64(count) + 5, recent: time.Second}
					read := func() {
						rows, err := r.read(ctx, kernelFlowMap{m}, count, clock)
						if err != nil || len(rows) != count || r.batchUnsupported != mode.iterator {
							b.Fatalf("%s returned %d of %d rows: %v", mode.name, len(rows), count, err)
						}
					}
					read()
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						read()
					}
				})
			}
		})
	}
}
