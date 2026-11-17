package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/store"
)

func TestFlowPagination(t *testing.T) {
	s := store.NewFlowStore(3)
	mux := testMux(s)
	start := time.Now()
	s.Write(store.Snapshot{CollectedAt: start, Flows: testFlows(100000)})

	first := readFlows(t, mux, "/api/flows?q=TCP")
	if first.Count != 100 || first.NextCursor == "" || first.GeneratedAt == nil || !first.GeneratedAt.Equal(start) {
		t.Fatalf("unexpected first page: count=%d cursor=%q time=%v", first.Count, first.NextCursor, first.GeneratedAt)
	}
	maxPage := readFlows(t, mux, "/api/flows?limit=1000")
	if maxPage.Count != 1000 || len(maxPage.Flows) != 1000 {
		t.Fatalf("unexpected max page size: %d", maxPage.Count)
	}
	ip := first.Flows[10].SrcIP.String()
	match := readFlows(t, mux, "/api/flows?q="+ip)
	if match.Count != 1 || match.Flows[0].SrcIP != first.Flows[10].SrcIP {
		t.Fatalf("unexpected IP filter result: %+v", match)
	}
	path := "/api/flows?q=TCP&cursor=" + url.QueryEscape(first.NextCursor)
	s.Write(store.Snapshot{CollectedAt: start.Add(time.Second)})
	second := readFlows(t, mux, path)
	if second.Count != 100 || len(second.Flows) != 100 || second.GeneratedAt == nil || !second.GeneratedAt.Equal(start) ||
		second.Flows[0].SrcIP == first.Flows[0].SrcIP {
		t.Fatalf("cursor did not advance through the original snapshot: %+v", second.GeneratedAt)
	}
	if resp := request(mux, http.MethodGet, "/api/flows?q=UDP&cursor="+url.QueryEscape(first.NextCursor)); resp.Code != http.StatusBadRequest {
		t.Fatalf("cursor accepted a different filter: %d", resp.Code)
	}
	s.Write(store.Snapshot{CollectedAt: start.Add(2 * time.Second)})
	if resp := request(mux, http.MethodGet, path); resp.Code != http.StatusGone {
		t.Fatalf("expired cursor returned %d", resp.Code)
	}
}

func TestFlowRequestValidation(t *testing.T) {
	mux := testMux(store.NewFlowStore(1))
	tests := map[string]int{
		"?limit=0":                        http.StatusBadRequest,
		"?limit=1001":                     http.StatusBadRequest,
		"?limit=-1":                       http.StatusBadRequest,
		"?limit=invalid":                  http.StatusBadRequest,
		"?limit=":                         http.StatusBadRequest,
		"?limit=1&limit=20":               http.StatusBadRequest,
		"?cursor=invalid":                 http.StatusBadRequest,
		"?cursor=":                        http.StatusBadRequest,
		"?unsupported=yes":                http.StatusBadRequest,
		"?q=%zz":                          http.StatusBadRequest,
		"?q=" + strings.Repeat("x", 65):   http.StatusBadRequest,
		"?q=" + strings.Repeat("x", 1025): http.StatusRequestURITooLong,
	}
	for query, want := range tests {
		if resp := request(mux, http.MethodGet, "/api/flows"+query); resp.Code != want {
			t.Errorf("%q returned %d, want %d", query, resp.Code, want)
		}
	}
	if resp := request(mux, http.MethodPost, "/api/flows"); resp.Code != http.StatusMethodNotAllowed || resp.Header().Get("Allow") != "GET" {
		t.Fatalf("invalid method response: %d %v", resp.Code, resp.Header())
	}
	if resp := request(mux, http.MethodGet, "/api/flows"); resp.Code != http.StatusOK ||
		resp.Header().Get("Access-Control-Allow-Origin") != "" ||
		resp.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(resp.Body.String(), `"flows":[]`) {
		t.Fatalf("unexpected flow response: %d %v %s", resp.Code, resp.Header(), resp.Body)
	}
}

func TestReadiness(t *testing.T) {
	s := store.NewFlowStore(4)
	mux := testMux(s)
	check := func(want int, state string) {
		t.Helper()
		resp := request(mux, http.MethodGet, "/readyz")
		var got collectionStatus
		if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil || got.State != state || resp.Code != want {
			t.Fatalf("readiness returned %d (%s), want %d (%s): %v", resp.Code, resp.Body, want, state, err)
		}
	}
	check(http.StatusServiceUnavailable, "detached")
	s.SetAttached(true)
	check(http.StatusServiceUnavailable, "starting")
	now := time.Now()
	s.MarkCollectionFailed(now.Add(-time.Minute))
	check(http.StatusServiceUnavailable, "starting")
	s.Write(store.Snapshot{CollectedAt: now.Add(-30 * time.Second)})
	s.MarkCollectionFailed(now.Add(-5 * time.Second))
	s.MarkCollectionFailed(now.Add(-time.Second))
	check(http.StatusServiceUnavailable, "stale")
	s.Write(store.Snapshot{CollectedAt: now})
	check(http.StatusOK, "ready")
	s.SetAttached(false)
	check(http.StatusServiceUnavailable, "detached")
}

func TestConcurrentFlowAndStatsReaders(t *testing.T) {
	s := store.NewFlowStore(3)
	mux := testMux(s)
	s.Write(store.Snapshot{CollectedAt: time.Now(), Flows: testFlows(100)})
	var clients sync.WaitGroup
	for i := 0; i < 3; i++ {
		clients.Add(1)
		go func() {
			defer clients.Done()
			for j := 0; j < 10; j++ {
				for _, path := range []string{"/api/flows?limit=3", "/api/stats"} {
					resp := request(mux, http.MethodGet, path)
					if resp.Code != http.StatusOK || !json.Valid(resp.Body.Bytes()) {
						t.Errorf("invalid concurrent response for %s: %d %s", path, resp.Code, resp.Body)
					}
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		s.Write(store.Snapshot{CollectedAt: time.Now(), Flows: testFlows(100 + i)})
	}
	clients.Wait()
}

func testFlows(count int) []store.Flow {
	rows := make([]store.Flow, count)
	for i := range rows {
		key := count - i
		rows[i] = store.Flow{
			Protocol: "TCP",
			SrcIP:    store.IPv4{10, byte(key >> 16), byte(key >> 8), byte(key)},
			DstIP:    store.IPv4{198, 18, 0, 10},
			SrcPort:  49153,
			DstPort:  443,
		}
	}
	return rows
}

func testMux(s *store.FlowStore) *http.ServeMux {
	mux := http.NewServeMux()
	NewHandler(s, "eth-test", logrus.New(), 15*time.Second).RegisterRoutes(mux)
	return mux
}

func request(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func readFlows(t *testing.T, mux *http.ServeMux, path string) flowsResponse {
	t.Helper()
	resp := request(mux, http.MethodGet, path)
	if resp.Code != http.StatusOK {
		t.Fatalf("%s returned %d: %s", path, resp.Code, resp.Body)
	}
	var got flowsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode flow response: %v", err)
	}
	return got
}

func BenchmarkServeFlows(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := store.NewFlowStore(1)
			s.Write(store.Snapshot{CollectedAt: time.Now(), Flows: testFlows(size)})
			mux := testMux(s)
			request := httptest.NewRequest(http.MethodGet, "/api/flows", nil)
			durations := make([]time.Duration, b.N)
			var responseBytes int
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				start := time.Now()
				mux.ServeHTTP(w, request)
				durations[i] = time.Since(start)
				if w.Code != http.StatusOK {
					b.Fatalf("unexpected HTTP status %d", w.Code)
				}
				responseBytes = w.Body.Len()
			}
			b.StopTimer()
			slices.Sort(durations)
			b.ReportMetric(float64(responseBytes), "response_B/op")
			b.ReportMetric(float64(durations[(len(durations)-1)/2].Nanoseconds()), "p50_ns")
			b.ReportMetric(float64(durations[(len(durations)*95+99)/100-1].Nanoseconds()), "p95_ns")
		})
	}
}
