// Package exporter defines the Exporter interface and the Prometheus exporter
// implementation. Additional exporters (ClickHouse, stdout, etc.) implement
// the same interface and can be registered with the collector.
package exporter

// Exporter is the interface that all output sinks must implement.
// The collector calls Export() on each registered exporter every collection
// interval. Implementations must be safe for concurrent use.
type Exporter interface {
	// Export receives the list of enriched flows collected in this interval.
	// Implementations should be non-blocking; heavy operations should be
	// done asynchronously or via channels.
	Export(flows interface{})
}
