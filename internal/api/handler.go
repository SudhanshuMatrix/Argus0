// Package api provides the HTTP JSON API and dashboard server for Argus.
// Routes:
//
//	GET /           → serves the embedded web dashboard (index.html)
//	GET /api/flows  → latest enriched flows as JSON
//	GET /api/stats  → aggregated stats + traffic history as JSON
//	GET /healthz    → liveness probe
//	GET /metrics    → Prometheus metrics (proxied from promhttp)
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/store"
)

type Handler struct {
	flowStore *store.FlowStore
	ifaceName string
	startTime time.Time
	log       *logrus.Logger
}

// NewHandler creates an API handler backed by the given FlowStore.
func NewHandler(flowStore *store.FlowStore, ifaceName string, log *logrus.Logger) *Handler {
	return &Handler{
		flowStore: flowStore,
		ifaceName: ifaceName,
		startTime: time.Now(),
		log:       log,
	}
}

// RegisterRoutes attaches all API routes to the given mux.
// The caller is responsible for also mounting promhttp.Handler() at /metrics.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/flows", h.handleFlows)
	mux.HandleFunc("/api/stats", h.handleStats)
}

// handleFlows returns the latest flow snapshot as a JSON array.
// GET /api/flows
func (h *Handler) handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flows := h.flowStore.LatestFlows()
	if flows == nil {
		flows = []store.Flow{} // Return empty array, not null
	}

	writeJSON(w, map[string]interface{}{
		"flows":        flows,
		"count":        len(flows),
		"interface":    h.ifaceName,
		"generated_at": time.Now(),
	})
}

// handleStats returns aggregated statistics + traffic history.
// GET /api/stats
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.flowStore.ComputeStats()
	writeJSON(w, map[string]interface{}{
		"stats":      stats,
		"interface":  h.ifaceName,
		"uptime_sec": int(time.Since(h.startTime).Seconds()),
	})
}

// handleHealth is a simple liveness probe.
// GET /healthz
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

// writeJSON marshals v to JSON and writes it to w with proper headers.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // CORS for dev
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
