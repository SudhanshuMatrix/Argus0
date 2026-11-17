# Portable Go benchmarks

These runs used an Apple M2 host with darwin/arm64. The baseline was
`1a4fd94d38b04b4b45afd4005d3776b6a12c11f4`. The revised runs used the
working tree included in `a22f9a9e228d22493362ef6cc57d3a6403a6201a`.
The host Go executable reported 1.27.2. Raw benchmark output does not
record the effective Go toolchain for each invocation. The revised module
selects 1.27.4 automatically with the standard toolchain settings.

The collector benchmarks use 1,000, 10,000 and 100,000 distinct synthetic
tuples in a deterministic shuffled order. They measure userspace decode
and publication, including the legacy delta exporter or the revised batch
reader and generation exporter. Kernel map syscalls and traffic are
outside the measurement. Each result file contains five runs.

The HTTP benchmark exercised handlers in process with `httptest`. Five
baseline/revised pairs alternated, with 25 requests per size in each run.
The baseline returns every tuple. The revised default page returns 100.
Each run reports the p50 and p95 of its own requests, along with response
bytes and allocation measurements.

## Reproduce

From the revised repository root, prepare a separate baseline checkout
and copy the two benchmark shims as test sources.

```sh
evidence=benchmarks/results/2026-11-17-flow-lifecycle/raw/portable
baseline=$(mktemp -d)
git archive 1a4fd94d38b04b4b45afd4005d3776b6a12c11f4 | tar -x -C "$baseline"
cp "$evidence/legacy_bench_test.go.txt" "$baseline/internal/collector/legacy_bench_test.go"
cp "$evidence/portable_bench_test.go.txt" "$baseline/internal/api/portable_bench_test.go"

go -C "$baseline" test -run '^$' -bench '^BenchmarkLegacyCollectAndPublish$' -benchmem -benchtime=500ms -count=5 ./internal/collector
go test -run '^$' -bench '^BenchmarkCollectAndPublish$' -benchmem -benchtime=500ms -count=5 ./internal/collector

for run in 1 2 3 4 5
do
  go -C "$baseline" test -run '^$' -bench '^BenchmarkServeFlows$' -benchmem -benchtime=25x ./internal/api
  go test -run '^$' -bench '^BenchmarkServeFlows$' -benchmem -benchtime=25x ./internal/api
done

go -C "$baseline" test -run '^$' -bench '^BenchmarkComputeStats$' -benchmem -benchtime=200ms -count=3 ./internal/store
go test -run '^$' -bench '^Benchmark(ComputeStats|Publish|Page)$' -benchmem -benchtime=200ms -count=3 ./internal/store
```

To profile the baseline exporter at 10,000 flows and reproduce the text
profile format:

```sh
go -C "$baseline" test -run '^$' -bench '^BenchmarkExportSnapshots/10000$' \
  -benchtime=2s -cpuprofile="$baseline/exporter.cpu" -o "$baseline/exporter.test" ./internal/exporter
go tool pprof -top "$baseline/exporter.test" "$baseline/exporter.cpu"
```
