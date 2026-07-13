// Package api serves the embedded dashboard and JSON API.
package api

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML []byte

//go:embed assets/favicon.ico
var faviconBytes []byte

//go:embed assets/logo.png
var logoBytes []byte

// RegisterDashboardRoute mounts the static index.html dashboard onto the root path /.
func (h *Handler) RegisterDashboardRoute(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only serve the dashboard for exactly the root path.
		// Other unmatched paths should return 404.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})

	// Serve favicon.ico directly from statically linked bytes
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(faviconBytes)
	})

	// Serve logo.png
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(logoBytes)
	})
}
