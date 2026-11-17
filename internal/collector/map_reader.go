package collector

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sudhanshu-singh/argus/internal/bpf"
	"github.com/sudhanshu-singh/argus/internal/store"
)

const batchSize = 512

type flowIterator interface {
	Next(key, value any) bool
	Err() error
}

type flowMap interface {
	nextBatch(*ebpf.MapBatchCursor, []bpf.FlowKey, []bpf.FlowMetrics) (int, error)
	iterator() flowIterator
}

type kernelFlowMap struct{ *ebpf.Map }

func (m kernelFlowMap) nextBatch(cursor *ebpf.MapBatchCursor, keys []bpf.FlowKey, values []bpf.FlowMetrics) (int, error) {
	return m.BatchLookup(cursor, keys, values, nil)
}

func (m kernelFlowMap) iterator() flowIterator { return m.Iterate() }

type mapReader struct {
	keys             [batchSize]bpf.FlowKey
	values           [batchSize]bpf.FlowMetrics
	seen             map[bpf.FlowKey]struct{}
	batchUnsupported bool
	lastCount        int
}

// read must receive a sealed map. A duplicate or incomplete walk discards the
// entire result, since looking up a tuple twice wouldn't count extra traffic.
func (r *mapReader) read(ctx context.Context, m flowMap, capacity int, clock flowClock) ([]store.Flow, error) {
	if r.seen == nil {
		r.seen = make(map[bpf.FlowKey]struct{})
	}
	clear(r.seen)
	flows := make([]store.Flow, 0, min(r.lastCount, capacity))
	add := func(key bpf.FlowKey, value bpf.FlowMetrics) error {
		if len(flows) >= capacity {
			return errors.New("flow map walk exceeded configured capacity")
		}
		if _, duplicate := r.seen[key]; duplicate {
			return errors.New("flow map walk repeated a tuple")
		}
		r.seen[key] = struct{}{}
		flows = append(flows, buildFlow(key, value, clock))
		return nil
	}

	finish := func() []store.Flow {
		r.lastCount = len(flows)
		if len(flows) < cap(flows)/2 {
			compact := make([]store.Flow, len(flows))
			copy(compact, flows)
			return compact
		}
		return flows
	}

	if !r.batchUnsupported {
		err := r.readBatch(ctx, m, add)
		switch {
		case err == nil:
			return finish(), nil
		case errors.Is(err, ebpf.ErrNotSupported), errors.Is(err, syscall.EOPNOTSUPP):
			r.batchUnsupported = true
		case errors.Is(err, syscall.ENOSPC):
			// A hash bucket can exceed the batch buffer. Retry this map from scratch.
		default:
			return nil, err
		}
		clear(r.seen)
		flows = flows[:0]
	}

	iter := m.iterator()
	var key bpf.FlowKey
	var value bpf.FlowMetrics
	for ctx.Err() == nil && iter.Next(&key, &value) {
		if err := add(key, value); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return finish(), nil
}

func (r *mapReader) readBatch(ctx context.Context, m flowMap, add func(bpf.FlowKey, bpf.FlowMetrics) error) error {
	var cursor ebpf.MapBatchCursor
	for ctx.Err() == nil {
		n, err := m.nextBatch(&cursor, r.keys[:], r.values[:])
		done := errors.Is(err, ebpf.ErrKeyNotExist)
		if err != nil && !done {
			return fmt.Errorf("readBatch: %w", err)
		}
		if n < 0 || n > len(r.keys) || n == 0 && !done {
			return errors.New("invalid count from batch lookup")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if err := add(r.keys[i], r.values[i]); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
	return ctx.Err()
}

type flowClock struct {
	wall   time.Time
	monoNS uint64
	recent time.Duration
}
