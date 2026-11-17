// Package api serves the dashboard, flow snapshots, and collection status.
package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sudhanshu-singh/argus/internal/store"
)

const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
	maxQueryBytes    = 1024
	maxFilterBytes   = 64
	cursorHeaderSize = 12
)

type Handler struct {
	flowStore  *store.FlowStore
	ifaceName  string
	startTime  time.Time
	staleAfter time.Duration
	log        *logrus.Logger
}

func NewHandler(flowStore *store.FlowStore, ifaceName string, log *logrus.Logger, staleAfter time.Duration) *Handler {
	return &Handler{
		flowStore:  flowStore,
		ifaceName:  ifaceName,
		startTime:  time.Now(),
		staleAfter: staleAfter,
		log:        log,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/flows", getOnly(h.handleFlows))
	mux.HandleFunc("/api/stats", getOnly(h.handleStats))
	mux.HandleFunc("/readyz", getOnly(h.handleReady))
}

func getOnly(handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(r.URL.RawQuery) > maxQueryBytes {
			http.Error(w, "query too large", http.StatusRequestURITooLong)
			return
		}
		handle(w, r)
	}
}

type flowsResponse struct {
	Flows       []store.Flow `json:"flows"`
	Count       int          `json:"count"`
	Interface   string       `json:"interface"`
	GeneratedAt *time.Time   `json:"generated_at"`
	NextCursor  string       `json:"next_cursor,omitempty"`
}

func (h *Handler) handleFlows(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	for name, values := range query {
		if (name != "limit" && name != "cursor" && name != "q") || len(values) != 1 {
			http.Error(w, "invalid query parameter", http.StatusBadRequest)
			return
		}
	}

	limit := defaultPageLimit
	if query.Has("limit") {
		value, err := strconv.ParseUint(query.Get("limit"), 10, 16)
		if err != nil || value == 0 || value > maxPageLimit {
			http.Error(w, "limit must be between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = int(value)
	}
	filter := strings.TrimSpace(query.Get("q"))
	if len(filter) > maxFilterBytes {
		http.Error(w, "filter too large", http.StatusBadRequest)
		return
	}
	var cursor store.Cursor
	if query.Has("cursor") {
		cursor, err = decodeCursor(query.Get("cursor"), filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := h.flowStore.Page(ctx, cursor, limit, store.ParseFlowFilter(filter))
	switch {
	case errors.Is(err, store.ErrExpiredCursor):
		http.Error(w, err.Error(), http.StatusGone)
		return
	case errors.Is(err, store.ErrInvalidCursor):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, context.Canceled):
		return
	case err != nil:
		http.Error(w, "flow page deadline exceeded", http.StatusServiceUnavailable)
		return
	}

	resp := flowsResponse{Flows: page.Flows, Count: len(page.Flows), Interface: h.ifaceName}
	if !page.CollectedAt.IsZero() {
		resp.GeneratedAt = &page.CollectedAt
	}
	if page.Next.Generation != 0 {
		resp.NextCursor = encodeCursor(page.Next, filter)
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func encodeCursor(cursor store.Cursor, filter string) string {
	raw := make([]byte, cursorHeaderSize, cursorHeaderSize+len(filter))
	binary.BigEndian.PutUint64(raw, cursor.Generation)
	binary.BigEndian.PutUint32(raw[8:], uint32(cursor.Offset))
	return base64.RawURLEncoding.EncodeToString(append(raw, filter...))
}

func decodeCursor(encoded, filter string) (store.Cursor, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(cursorHeaderSize+len(filter)) {
		return store.Cursor{}, store.ErrInvalidCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != cursorHeaderSize+len(filter) || string(raw[cursorHeaderSize:]) != filter {
		return store.Cursor{}, store.ErrInvalidCursor
	}
	cursor := store.Cursor{
		Generation: binary.BigEndian.Uint64(raw),
		Offset:     int(binary.BigEndian.Uint32(raw[8:])),
	}
	if cursor.Generation == 0 || cursor.Offset <= 0 {
		return store.Cursor{}, store.ErrInvalidCursor
	}
	return cursor, nil
}

type collectionStatus struct {
	State      string   `json:"state"`
	AgeSeconds *float64 `json:"age_seconds"`
}

func (h *Handler) status(now, last time.Time, attached bool) collectionStatus {
	status := collectionStatus{State: "starting"}
	if !last.IsZero() {
		age := max(0, now.Sub(last).Seconds())
		status.AgeSeconds = &age
		status.State = "ready"
		if now.Sub(last) > h.staleAfter {
			status.State = "stale"
		}
	}
	if !attached {
		status.State = "detached"
	}
	return status
}

func (h *Handler) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := h.flowStore.ComputeStats()
	_, attached := h.flowStore.LastCollection()
	h.writeJSON(w, http.StatusOK, struct {
		Stats      store.Stats      `json:"stats"`
		Interface  string           `json:"interface"`
		UptimeSec  int              `json:"uptime_sec"`
		Collection collectionStatus `json:"collection"`
	}{
		Stats:      stats,
		Interface:  h.ifaceName,
		UptimeSec:  int(time.Since(h.startTime).Seconds()),
		Collection: h.status(time.Now(), stats.CollectedAt, attached),
	})
}

func (h *Handler) handleReady(w http.ResponseWriter, _ *http.Request) {
	last, attached := h.flowStore.LastCollection()
	status := h.status(time.Now(), last, attached)
	code := http.StatusOK
	if status.State != "ready" {
		code = http.StatusServiceUnavailable
	}
	h.writeJSON(w, code, status)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		h.log.WithError(err).Debug("Failed to write HTTP response")
	}
}
