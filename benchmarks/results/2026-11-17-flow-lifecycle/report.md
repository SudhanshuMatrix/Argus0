# Flow lifecycle and scalability validation

The starting source was `1a4fd94d38b04b4b45afd4005d3776b6a12c11f4`. The tested revised agent was `79a758149098b485cfd4ff6a9aaf8b8044b0129c`. Both Git worktrees were clean when those agent binaries were built.

Portable tests and microbenchmarks ran on an Apple M2 with macOS 15.7.7. Network and privileged tests ran in QEMU 8.2.6 using software emulation, two Cortex-A72 vCPUs, 1 GiB RAM, and Alpine Linux 6.12.117-0-virt on ARM64. The guest had a RAM root, a task-only file share, and zero external NICs. Both traffic endpoints belonged to isolated guest namespaces linked by veth.

The attached-to-attached binaries used Go 1.27.4, Linux arm64, and `CGO_ENABLED=0`. The detached-to-attached comparison here used a baseline binary built with Go 1.27.2 for both conditions. The original checked-in objects were used for both baseline builds. New objects were produced with cilium/ebpf bpf2go v0.22.0, Zig 0.15.2, libbpf 1.5.0 headers, and the flags defined by `make generate`. Build metadata and object digests are in [raw evidence](raw/).

## Paired UDP throughput

The sender offered 5 Mbit/s with 1,200-byte UDP payloads. Each comparison used five alternating pairs with two seconds of warmup and eight seconds of measurement per trial. The collection interval was two seconds, capacity was 100,000, and each attached trial began with a fresh process. Values below are medians across five trials per condition.

| Comparison | Receiver Mbit/s before → after | Lost packets across all trials | Agent CPU, % of one guest vCPU | Agent RSS, KiB |
| --- | ---: | ---: | ---: | ---: |
| A · baseline revision detached → attached | 4.9935 → 4.9965 | 0 | — → 0.59 | — → 32,284 |
| B · baseline attached → revised attached | 4.9984 → 4.9978 | 0 | 0.59 → 2.18 | 34,116 → 23,656 |

The 5 Mbit/s offered load limits this comparison to the tested rate. The process CPU changed by +1.58 percentage points of one vCPU and the median RSS changed by -31%. These runs used a small number of active tuples. The CPU measurement covers the whole process, including rotation. [Condition A summary](raw/primary-a-summary.json) · [Condition B summary](raw/primary-b-summary.json) · [Trial inputs and output](raw/udp-trials.tar.gz)

## Churn and concurrent clients

With capacity set to 1,000 and two-second windows, the sender offered 900 distinct UDP tuples in each of 12 successive windows, then 1,100 in one window. The receiver counted all 11,900 packets. Argus counted 11,900 eligible UDP egress observations, 100 detail admission failures in the full window, and zero observation accounting failures. The following quiet publication held zero tuples. Agent RSS ranged from 14,132 to 22,480 KiB at the loaded samples.

Three concurrent clients requested default flow pages, stats and metrics. The durations are curl transfer times in milliseconds on loopback inside the guest. p95 uses nearest rank.

| Endpoint | Samples | p50 | p95 | Largest body |
| --- | ---: | ---: | ---: | ---: |
| `/api/flows` | 79 | 17.61 ms | 36.13 ms | 27,426 B |
| `/api/stats` | 81 | 14.09 ms | 31.63 ms | 2,427 B |
| `/metrics` | 78 | 20.15 ms | 66.70 ms | 12,351 B |

The logged collector phase from counter sampling through publication was 8.72 ms p50 and 76.92 ms p95 over the 13 loaded windows. This phase excludes the preceding map rotation and attachment check. The full-collection Prometheus histogram across 16 successful attempts bounds p50 at 25 ms and p95 at 250 ms. Loaded sample timestamps were 1.82–2.17 seconds apart. Repeated windows exercised continued admission with a bounded working set while the HTTP clients ran. [Validation evidence](raw/validation/)

## Portable scalability

The collector fixture converted and published distinct, shuffled tuples without kernel calls. The table reports medians across five 500 ms benchmark runs for each size.

| Tuples | Time/op before → after | Allocated bytes/op before → after | Allocations/op before → after |
| ---: | ---: | ---: | ---: |
| 1,000 | 246 µs → 179 µs | 482,447 → 185,872 | 2,014 → 11 |
| 10,000 | 2.78 ms → 2.19 ms | 8,388,465 → 1,803,792 | 20,022 → 11 |
| 100,000 | 36.34 ms → 26.91 ms | 100,119,050 → 18,007,568 | 200,067 → 11 |

At 100,000 retained tuples, the in-process HTTP benchmark measured p50 47.23 ms → 80.46 µs and p95 54.64 ms → 105.88 µs. The default response changed from all rows to a 100-row page, reducing the body from 22,900,774 to 25,222 bytes. Per-request allocations increased from 47 to 222 as the revised handler formats the page's addresses on demand. At 10,000 tuples the stats lookup median dropped from 118.23 µs to 96.55 ns, with three allocations in both cases. These measurements use the `httptest` recorder or direct store calls. [Fixtures and raw samples](raw/portable/)

## Kernel batch and runtime

The Linux kernel benchmark populated real hash maps with distinct keys and measured one read-and-convert pass per operation. Values are medians across three runs of three operations each. These fixtures exercise steady retained cardinalities separately from packet generation and publication.

| Retained tuples | Batch | Iterator |
| ---: | ---: | ---: |
| 1,000 | 4.02 ms | 15.23 ms |
| 10,000 | 17.32 ms | 136.29 ms |
| 100,000 | 159.05 ms | 1,387.99 ms |

At 100,000 configured entries, the active hash reported 14,098,368 → 14,098,368 bytes in BPF fdinfo. The directly observed map totals including counters and the map-of-maps were 14,098,656 → 14,099,472 bytes. These are kernel accounting values from one probe. They exclude any sealed map still open during rotation.

The final standalone agent reached readiness with only `CAP_BPF` and `CAP_NET_ADMIN` in its effective set on Linux 6.12. The earlier candidate needed the full guest capabilities because an inlined classifier reused a spilled pointer slot. Moving the classifier into its own BPF subprogram corrected the kernel verifier failure. The final candidate passed both endian generation checks on macOS and Linux ARM64. It also released the TCX links after an HTTP bind conflict and returned readiness 503 with liveness 200 after the interface disappeared.

The bounded soak delivered 93,750 UDP packets in 180.01 seconds with 0 receiver losses. RSS samples ranged from 23,856 to 26,028 KiB. The final detail update failure counter was zero. The guest took 183.69 seconds including sampling and the final idle check. [Kernel map timings](raw/kernel-map-bench.txt) · [Soak and runtime evidence](raw/validation/)

## Verification and limits

- Baseline and revised Go unit and race tests passed on macOS. The HTTP lifecycle test needs an ephemeral loopback listener. Linux production binaries built on Go 1.25.0 and Go 1.27.4 for amd64 and arm64.
- Explicitly gated Linux ARM64 tests passed for packet classification, exact eligible totals at full detail capacity, malformed and unsupported counters, repeated rotation, concurrent updates and rotation, TCX chaining and detachment, and batch/iterator equivalence.
- The cilium/ebpf update removed the reachable advisory reported by `govulncheck`. The revised Linux/arm64 scan found no reachable vulnerabilities and still listed a dependency advisory outside called paths. [Go advisory](https://pkg.go.dev/vuln/GO-2026-6238)
- Both Kubernetes resources passed strict Kubernetes 1.34 schema validation. A headless Chrome fixture verified pagination and the collection-age display. Container and Kubernetes runtime behavior, a physical NIC, a big-endian kernel, and a 60-minute soak remain unverified.
- The older 1.76-second collection measurement came from a specific emulated environment and was a median. This report's paired workload uses eight-second trials and its churn workload uses 900–1,000 retained tuples. The 100,000-tuple userspace and kernel map fixtures measure separate stages.

Reproduce with the [benchmark commands](../../README.md), including `--baseline-argus` for both-attached comparisons. The [lifecycle design](../../../docs/flow-lifecycle.md) describes the accounting and retention guarantees.
