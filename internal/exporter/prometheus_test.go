package exporter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/store"
)

func newExporter(t testing.TB) *PrometheusExporter {
	t.Helper()
	exp, err := NewPrometheusExporter("test0", logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	return exp
}

type expectation struct {
	name, label, direction string
	value                  float64
}

func verifyMetrics(t *testing.T, exp *PrometheusExporter, expectations ...expectation) {
	t.Helper()
	families, err := exp.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range expectations {
		found := false
		for _, family := range families {
			if family.GetName() != want.name {
				continue
			}
			for _, metric := range family.GetMetric() {
				labels := map[string]string{}
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["l7_protocol"] != want.label || labels["direction"] != want.direction {
					continue
				}
				found = true
				got := metric.GetCounter().GetValue() + metric.GetGauge().GetValue()
				if got != want.value {
					t.Errorf("%s %s %s = %v, want %v", want.name, want.label, want.direction, got, want.value)
				}
			}
		}
		if !found {
			t.Errorf("missing metric %+v", want)
		}
	}
}

func TestCumulativeSnapshotAccounting(t *testing.T) {
	exp := newExporter(t)
	f := store.Flow{Protocol: "TCP", SrcPort: 9000, FirstSeenNs: 10,
		BytesIngress: 100, PktsIngress: 4, BytesEgress: 25, PktsEgress: 1}
	publish := func(f store.Flow) { exp.Export([]store.Flow{f, f}, 7) }
	expect := func(label string, bytes, packets, active float64) {
		t.Helper()
		verifyMetrics(t, exp,
			expectation{"network_bytes_total", label, "ingress", bytes},
			expectation{"network_packets_total", label, "ingress", packets},
			expectation{"network_active_connections", label, "", active})
	}

	publish(f)
	expect("unknown", 100, 4, 1)
	publish(f)
	expect("unknown", 100, 4, 0)
	f.BytesIngress += 25
	f.PktsIngress++
	f.BytesEgress += 50
	f.PktsEgress += 2
	publish(f)
	expect("unknown", 125, 5, 1)
	verifyMetrics(t, exp,
		expectation{"network_bytes_total", "unknown", "egress", 75},
		expectation{"network_packets_total", "unknown", "egress", 3},
		expectation{"network_flow_map_entries", "", "", 1},
		expectation{"network_flow_update_failures_total", "", "", 7})

	f.L7Protocol = "HTTP"
	f.BytesIngress += 40
	f.PktsIngress += 2
	publish(f)
	expect("unknown", 125, 5, 0)
	expect("HTTP", 40, 2, 1)

	// A counter decrease and a recycled key with larger counters both reset.
	f.BytesIngress, f.PktsIngress = 10, 1
	publish(f)
	expect("HTTP", 50, 3, 1)
	f.FirstSeenNs++
	f.BytesIngress, f.PktsIngress = 100, 5
	publish(f)
	expect("HTTP", 150, 8, 1)

	exp.Export(nil, 8)
	expect("HTTP", 150, 8, 0)
	verifyMetrics(t, exp, expectation{"network_flow_map_entries", "", "", 0})
	publish(f)
	expect("HTTP", 250, 13, 1)
}

func TestConcurrentExportAndScrape(t *testing.T) {
	exp := newExporter(t)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for i := uint64(1); i <= 100; i++ {
			exp.Export([]store.Flow{{Protocol: "TCP", BytesEgress: i}}, 0)
		}
	}()
	go func() {
		defer group.Done()
		for range [50]struct{}{} {
			if _, err := exp.registry.Gather(); err != nil {
				t.Error(err)
			}
		}
	}()
	group.Wait()
	verifyMetrics(t, exp, expectation{"network_bytes_total", "unknown", "egress", 100})
}

func TestHTTPServerLifecycle(t *testing.T) {
	exp := newExporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := exp.ServeMetrics(ctx, ln.Addr().String(), nil); err == nil {
		t.Fatal("occupied address did not fail")
	}
	done := make(chan error, 1)
	go func() {
		done <- exp.serve(ctx, ln, func(mux *http.ServeMux) {
			mux.HandleFunc("/extra", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
		})
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	for _, request := range []struct {
		path   string
		status int
	}{{"/healthz", 200}, {"/metrics", 200}, {"/extra", 204}} {
		resp, err := client.Get(fmt.Sprintf("http://%s%s", ln.Addr(), request.path))
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if resp.StatusCode != request.status {
			t.Errorf("%s returned %d, want %d", request.path, resp.StatusCode, request.status)
		}
	}
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("HTTP server did not stop")
	}
}

func BenchmarkExportSnapshots(b *testing.B) {
	for _, size := range []int{100, 10000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			exp := newExporter(b)
			flows := make([]store.Flow, size)
			for i := range flows {
				flows[i] = store.Flow{Protocol: "TCP", SrcPort: uint16(i), FirstSeenNs: 1}
			}
			exp.Export(flows, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := range flows {
					flows[j].BytesEgress += 512
					flows[j].PktsEgress++
				}
				exp.Export(flows, 0)
			}
		})
	}
}
