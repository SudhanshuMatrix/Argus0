package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/exporter"
	"github.com/sudhanshu-singh/argus/internal/store"
)

type mapEntry struct {
	key   bpf.FlowKey
	value bpf.FlowMetrics
}

type fakeMap struct {
	rows       []mapEntry
	pos        int
	batchCalls int
	iterCalls  int
	batchError func(int) error
	iterError  error
}

func (m *fakeMap) nextBatch(_ *ebpf.MapBatchCursor, keys []bpf.FlowKey, values []bpf.FlowMetrics) (int, error) {
	m.batchCalls++
	n := min(len(m.rows)-m.pos, len(keys))
	for i := 0; i < n; i++ {
		row := m.rows[m.pos+i]
		keys[i], values[i] = row.key, row.value
	}
	m.pos += n
	if m.batchError != nil {
		if err := m.batchError(m.batchCalls); err != nil {
			return n, err
		}
	}
	if m.pos == len(m.rows) {
		return n, ebpf.ErrKeyNotExist
	}
	return n, nil
}

func (m *fakeMap) iterator() flowIterator {
	m.iterCalls++
	return &fakeIterator{rows: m.rows, err: m.iterError}
}

type fakeIterator struct {
	rows []mapEntry
	err  error
}

func (it *fakeIterator) Next(key, value any) bool {
	if len(it.rows) == 0 {
		return false
	}
	row := it.rows[0]
	it.rows = it.rows[1:]
	*key.(*bpf.FlowKey) = row.key
	*value.(*bpf.FlowMetrics) = row.value
	return true
}

func (it *fakeIterator) Err() error { return it.err }

func mapEntries(count int) []mapEntry {
	rows := make([]mapEntry, count)
	for i := range rows {
		rows[i] = mapEntry{
			key: bpf.FlowKey{
				SrcIp:    binary.NativeEndian.Uint32([]byte{198, 18, 0, byte(1 + i/50000)}),
				DstIp:    binary.NativeEndian.Uint32([]byte{198, 19, 0, 1}),
				SrcPort:  networkToHostU16(uint16(10000 + i%50000)),
				DstPort:  networkToHostU16(443),
				Protocol: 6,
			},
			value: bpf.FlowMetrics{
				BytesEgress: uint64(i+1) * 1024, PktsEgress: uint64(i + 1),
				FirstSeenNs: 1, LastSeenNs: uint64(i + 2), L7Proto: 2,
			},
		}
	}
	return rows
}

func TestBatchAndIteratorEquivalent(t *testing.T) {
	rows := mapEntries(batchSize + 7)
	ctx := context.Background()
	clock := flowClock{wall: time.Now(), monoNS: 2000, recent: time.Second}
	reader := mapReader{}
	batch := fakeMap{rows: rows}
	want, err := reader.read(ctx, &batch, len(rows), clock)
	if err != nil || len(want) != len(rows) || batch.batchCalls != 2 || batch.iterCalls != 0 {
		t.Fatalf("batch returned %d rows after %d batch calls and %d iterator calls (%v)", len(want), batch.batchCalls, batch.iterCalls, err)
	}
	last := want[len(want)-1]
	if last.BytesEgress != rows[len(rows)-1].value.BytesEgress || last.SrcPort != uint16(10000+len(rows)-1) {
		t.Fatalf("missing final partial batch values: %+v", last)
	}

	variant := []struct {
		name      string
		failure   error
		permanent bool
	}{{"unsupported", ebpf.ErrNotSupported, true}, {"oversized bucket", syscall.ENOSPC, false}}
	for _, tt := range variant {
		t.Run(tt.name, func(t *testing.T) {
			reader := mapReader{}
			m := fakeMap{rows: rows, batchError: func(call int) error {
				if call == 2 {
					return tt.failure
				}
				return nil
			}}
			got, err := reader.read(ctx, &m, len(rows), clock)
			if err != nil || !reflect.DeepEqual(got, want) || m.iterCalls != 1 || reader.batchUnsupported != tt.permanent {
				t.Fatalf("fallback returned %d rows after %d iterator calls (%v), persistent=%v", len(got), m.iterCalls, err, reader.batchUnsupported)
			}
			m.pos = 0
			m.batchCalls = 0
			if _, err := reader.read(ctx, &m, len(rows), clock); err != nil {
				t.Fatal(err)
			}
			if (m.batchCalls == 0) != tt.permanent {
				t.Fatalf("%d batch calls with persistent fallback %v", m.batchCalls, tt.permanent)
			}
		})
	}
}

func TestMapWalkRejectsIncompleteResults(t *testing.T) {
	rows := mapEntries(batchSize + 1)
	clock := flowClock{wall: time.Now()}
	fault := errors.New("map read failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		source fakeMap
		want   error
	}{
		{"partial batch error", context.Background(), fakeMap{rows: rows, batchError: func(call int) error {
			if call == 2 {
				return fault
			}
			return nil
		}}, fault},
		{"partial iterator error", context.Background(), fakeMap{rows: rows, batchError: func(int) error { return syscall.EOPNOTSUPP }, iterError: fault}, fault},
		{"duplicate tuple during churn", context.Background(), fakeMap{rows: append(append([]mapEntry{}, rows...), rows[0])}, nil},
		{"cancel during batch", ctx, fakeMap{rows: rows, batchError: func(int) error { cancel(); return nil }}, context.Canceled},
	}
	reader := mapReader{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader.batchUnsupported = false
			got, err := reader.read(tt.ctx, &tt.source, len(rows)+1, clock)
			if got != nil || err == nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("incomplete walk returned %d rows, err %v", len(got), err)
			}
		})
	}
	ok := fakeMap{rows: rows}
	if flows, err := reader.read(context.Background(), &ok, len(rows), clock); err != nil || len(flows) != len(rows) {
		t.Fatalf("successful walk after errors returned %d rows (%v)", len(flows), err)
	}
}

func BenchmarkCollectAndPublish(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			rows := mapEntries(count)
			rand.New(rand.NewSource(42)).Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
			m := fakeMap{rows: rows}
			clock := flowClock{wall: time.Now(), monoNS: uint64(count) + 5, recent: time.Second}
			exp, err := exporter.NewPrometheusExporter("test0", logrus.New())
			if err != nil {
				b.Fatal(err)
			}
			s := store.NewFlowStore(60)
			reader := mapReader{}
			ctx := context.Background()
			if _, err := reader.read(ctx, &m, count, clock); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.pos = 0
				clock.wall = clock.wall.Add(time.Second)
				flows, err := reader.read(ctx, &m, count, clock)
				if err != nil || len(flows) != count {
					b.Fatalf("read %d of %d tuples: %v", len(flows), count, err)
				}
				s.Write(store.Snapshot{CollectedAt: clock.wall, Flows: flows})
				exp.PublishGeneration(uint64(i+1), flows, bpf.ObservationTotals{}, 0)
			}
		})
	}
}
