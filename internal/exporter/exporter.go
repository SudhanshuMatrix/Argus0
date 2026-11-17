// Package exporter publishes collected flow data.
package exporter

import "time"

// CollectionResult reports one sampling attempt. An empty ErrorStage indicates
// that the collection successfully reached the store.
type CollectionResult struct {
	ErrorStage string
	Duration   time.Duration
	MapRead    time.Duration
	Lag        time.Duration
	Published  time.Time
	Overrun    bool
	Discarded  bool
	Final      bool
}
