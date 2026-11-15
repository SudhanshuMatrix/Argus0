// Package exporter publishes collected flow data.
package exporter

import "github.com/sudhanshu-singh/argus/internal/store"

// Exporter receives complete cumulative flow snapshots and the cumulative
// count of packets the BPF flow map could not account for.
type Exporter interface {
	Export(flows []store.Flow, updateFailures uint64)
}
