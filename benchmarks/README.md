# Argus validation benchmarks

[ARM64 validation report and raw results](results/2026-11-15-637ddfa/report.md)

The primary harness compares Argus detached with Argus attached. It creates a veth pair in two Linux network namespaces that have no external interface or default route. The client namespace has address `198.18.0.1/30`, and the server namespace has address `198.18.0.2/30`. Argus monitors the client side. Each enabled trial starts a new agent and an empty flow map.

## Build and check

Use a Linux test environment with TCX support and permission to create network namespaces, load BPF and attach TCX links. The harness requires Python 3.9+, iproute2, ethtool, curl and **iperf3 3.19.1**. Run the suite only on infrastructure where you have permission to generate traffic. The benchmark needs no external server.

From the repository root:

```sh
make build
go test ./...
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -o bin/bpfprobe ./benchmarks/cmd/bpfprobe
```

Run privileged BPF regression tests inside a test namespace. The example names a disposable namespace and removes it on exit.

```sh
set -eu
mkdir -p bin
CGO_ENABLED=0 go test -c -o bin/bpf-kernel.test ./internal/bpf
test_ns="argus-kernel-test-$$"
ip netns add "$test_ns"
trap 'ip netns del "$test_ns"' EXIT
ip -n "$test_ns" link add probe0 type veth peer name probe1
ip -n "$test_ns" link set probe0 up
ip -n "$test_ns" link set probe1 up
ip netns exec "$test_ns" env ARGUS_BPF_TEST=1 ARGUS_TEST_INTERFACE=probe0 \
  ./bin/bpf-kernel.test -test.v
```

The kernel tests execute the embedded programs on constructed Ethernet frames, force insertion into a full two-entry test map, and query both TCX hooks before load, after attach, and after close.

## Primary measurements

Run with root privileges on the Linux test system. Choose a new output directory and record the revision used to build the binary. Append `-dirty` to the revision if tracked source differed when built.

```sh
benchmarks/run.sh --argus bin/argus --output ./my-run \
  --revision "$(git rev-parse HEAD)" --environment "local Linux VM" \
  --duration 60 --warmup 5 --repetitions 5 --collect-interval 5 \
  --tcp-streams 1 4 --udp-rates 5M 20M --udp-length 1200 --http-parallel 2

python3 benchmarks/summarize.py ./my-run ./my-run/summary.json
```

The harness alternates the order of conditions within successive pairs. TCP runs in both directions. UDP runs from client to server at each offered rate. Start with rates the endpoints can sustain. HTTP sends requests with two persistent connections to a Python server returning a 64-byte response. The harness records workload commands, software versions, configuration, offloads and namespace cleanup. Each trial saves receiver output, guest CPU time and, when enabled, agent CPU ticks, RSS and post-run Argus metrics. The CPU sampling windows include the warm-up period.

The summarizer checks that the run finished and that each condition has all requested repetitions. It reports means, medians, ranges, sample standard deviations and paired differences. Throughput overhead is `100 × (baseline − enabled) / baseline`. Latency overhead is `100 × (enabled − baseline) / baseline`. Both headline figures use the condition medians. A negative result indicates an observed increase in throughput or decrease in latency.

## Flow capacity, recovery and runtime

Run these separately from the primary suite. Runtime statistics use a temporary, guest-wide BPF descriptor that closes at the end of the profiling interval. Use an isolated Linux test VM for this suite.

```sh
python3 benchmarks/validate.py --argus bin/argus --probe bin/bpfprobe \
  --output ./my-validation --profile-seconds 10 --soak-seconds 3600
```

The suite generates unique UDP tuples up to the map limit and compares application receive counts with Argus observations and update failures. It queries live TCX links and map information, verifies detachment, checks shutdown on HTTP bind failure and checks that a restart begins with an empty map. The profile uses the change in BPF run-count and runtime counters for each program. The soak runs bounded UDP traffic, samples process RSS, checks for map accounting failures, and waits for the active-flow gauge to return to zero after traffic stops.

## Go microbenchmarks

Run the allocation benchmarks separately from race testing and network traffic:

```sh
go test -run '^$' -bench '^Benchmark(ExportSnapshots|ComputeStats)$' -benchmem \
  -benchtime=750ms -count=5 ./internal/exporter ./internal/store
```

Both workloads use 100 and 10,000 synthetic flow records. The exporter benchmark publishes cumulative snapshots with advancing counters, including the fixture's in-place counter increments. The store benchmark aggregates the latest snapshot for the stats API. Both measure local userspace work and allocations.
