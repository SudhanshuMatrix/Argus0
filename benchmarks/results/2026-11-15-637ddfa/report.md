# Argus ARM64 validation, 2026-11-15

## Environment and method

The test host was a MacBook Air (Mac14,2) running macOS 15.7.7 on an Apple M2 with eight CPU cores and 16 GiB of RAM. The host process ran as an unprivileged user. Apple Virtualization.framework reported unavailable. A task-local xPack QEMU 8.2.6 process used software emulation (TCG) to boot Alpine 3.22.8 with two Cortex-A72 vCPUs, 1 GiB assigned RAM and Linux 6.12.117-0-virt on aarch64. The guest measured 991,828 KiB of usable RAM. It booted a RAM-backed filesystem, used a task-owned 9p share, and had no virtual NIC connected to the host or public network.

Two Linux network namespaces were connected by a single MTU-1500 veth pair with `198.18.0.1/30` on the client side and `198.18.0.2/30` on the server side. Argus attached to the client endpoint. Full offload settings and routes are included. MTU and offloads were left at the defaults for the new veth interfaces. The TCP and UDP byte rates come from the iperf3 receiver. Argus counts socket buffers observed at the hook. Segmentation, aggregation and iperf3 omit-window accounting affect direct comparisons of those counts.

Each primary case had a two-second warm-up and five measured eight-second repetitions per condition, alternating condition order across pairs. The same configuration and workload applied to both conditions. Enabled trials started with a fresh flow map. The agent used a two-second collection interval and JSON info logging. Short trials allowed the full 70-trial matrix in the desktop session. The standard harness defaults provide longer runs.

The tested application revision was `637ddfa10a5bcf04248e940466463eb34e83b629`, built with Go 1.27.2 for Linux/arm64, `CGO_ENABLED=0`, and `-ldflags "-s -w -X main.version=637ddfa"`. Tracked application sources and embedded objects matched that commit. Go recorded `vcs.modified=true` because the checkout also contained untracked benchmark work. The benchmark harness revision and build details are in the environment evidence. BPF bindings were generated with cilium/ebpf bpf2go v0.14.0 and Zig 0.15.2's Clang driver using `-O2 -g -Wall -Wextra -Werror -nostdinc` and libbpf v1.5.0 headers, producing little- and big-endian object files. The aarch64 guest exercised the little-endian object.

The incoming repository revision failed a native ARM64 Go test build because it shipped x86-only bindings and used Linux-only netlink APIs from unguarded code. No before/after source-version measurements were made. Both primary conditions used the same revised release build.

## Reproduction

Build the application from the tested revision with `make build`. On a privileged Linux test guest with the benchmark checkout and the tools in [the harness instructions](../../README.md), run:

```sh
benchmarks/run.sh --argus /path/to/argus --output ./primary \
  --revision 637ddfa10a5bcf04248e940466463eb34e83b629 \
  --environment "QEMU 8.2.6 TCG aarch64, 2 vCPU, 1 GiB" \
  --duration 8 --warmup 2 --repetitions 5 --collect-interval 2 \
  --tcp-streams 1 4 --udp-rates 5M 20M --udp-length 1200 --http-parallel 2
python3 benchmarks/summarize.py ./primary ./primary/summary.json
```

The guest used QEMU arguments `-M virt,accel=tcg -cpu cortex-a72 -smp 2 -m 1024 -nodefaults -display none -serial stdio -nic none -no-reboot`, the Alpine `linux-virt` kernel, and a task-local initramfs and share. Kernel and initramfs digests are in [guest-image-digests.txt](raw/guest-image-digests.txt). Guest image files were disposable. The harness runs on other Linux systems with BPF, TCX and namespace support.

## Correctness

- Prometheus previously added each full cumulative snapshot again. Flow deltas now use the directional tuple and first-seen timestamp. Regression tests cover unchanged and duplicate snapshots, increments in both directions, decreasing counters, tuple replacement, removal and L7 relabeling.
- The kernel map previously ignored insert errors and could overwrite the winner of a concurrent insert. Inserts use `BPF_NOEXIST` and recheck the key after an insert failure. Outcomes with no available entry increment a per-CPU failure counter. Idle tuples stay resident until restart. A recycled tuple retains its first-seen timestamp and any existing L7 label. The active-flow gauge returns to zero once counters stop increasing.
- The source previously captured the task ID at the TC hook and reported a direction-change interval as RTT. The agent now leaves PID/process ownership unknown and stops publishing that latency value. Its duration field describes the observation span. Application RTT or request latency must come from the endpoints.
- The classifier now checks TCP signatures and verifies a DNS header shape with port 53 context. It bounds reads by declared headers and omits fragmented IPv4 packets. Kernel test runs exercised HTTP, TLS, DNS, SSH, unknown data, misleading ports, empty and malformed DNS payloads and bytes outside the UDP length. The classifier examines one socket buffer and has no TLS decryption or TCP stream reassembly.
- The loader uses TCX links directly, so it leaves legacy qdisc configuration alone. The process waits for HTTP shutdown and returns listener errors. Tests exercised cancellation, concurrent metric gathers, endpoint bind failure, both TCX hooks and detachment.

## TCP and UDP throughput

The table shows the median and [minimum, maximum] of five receiver measurements per condition. TCP retransmissions use the sender's totals. Receiver loss comes from iperf3.

| Case | Baseline Mbit/s | Argus Mbit/s | Throughput overhead | Retransmissions or receiver loss in baseline / enabled |
|---|---:|---:|---:|---|
| TCP 1 stream forward | 7520.35 [6609.95, 7653.94] | 7074.27 [6980.84, 7122.60] | +5.93% | 0 [0, 186] / 0 [0, 0] |
| TCP 1 stream reverse | 7671.11 [7464.78, 8336.80] | 7483.20 [7301.90, 7679.71] | +2.45% | 0 [0, 0] / 0 [0, 0] |
| TCP 4 streams forward | 12579.76 [11438.22, 13337.85] | 12559.80 [11408.47, 12793.17] | +0.16% | 1166 [1061, 1214] / 1127 [1097, 1188] |
| TCP 4 streams reverse | 8823.25 [7792.18, 9068.27] | 8307.64 [8075.85, 8509.36] | +5.84% | 0 [0, 9] / 1 [0, 2] |
| UDP 5 Mbit/s | 5.00 [4.99, 5.00] | 5.00 [5.00, 5.00] | -0.02% | 0.00 [0.00, 0.00] / 0.00 [0.00, 0.00] |
| UDP 20 Mbit/s | 19.99 [19.98, 20.00] | 19.99 [19.97, 19.99] | +0.00% | 0.00 [0.00, 0.00] / 0.00 [0.00, 0.00] |

All 70 primary trials completed. Actual iperf3 measured receiver intervals were 7.994–8.026 s. The sum of the final map-update failure readings across the fresh enabled agents was 0. In the UDP trials the Argus totals include warm-up and control traffic. The separate flow-capacity run compares known sent datagrams, application receives, hook observations and insert failures.

## HTTP request latency and throughput

The load client used two persistent connections. Latency rows show statistics over each trial's percentile, followed by the median and range over trials.

| Measure | Baseline | Argus enabled | Overhead |
|---|---:|---:|---:|
| Requests/s | 41.000 [40.625, 41.500] | 40.750 [40.500, 41.000] | +0.61% |
| p50 ms | 48.127 [47.738, 48.477] | 48.413 [48.208, 48.726] | +0.59% |
| p95 ms | 52.068 [51.482, 52.718] | 52.221 [51.646, 53.000] | +0.29% |
| p99 ms | 55.767 [55.493, 66.795] | 56.848 [53.736, 65.327] | +1.94% |
| HTTP error % | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | — |

TCP trial ranges overlapped in 4 of the four workloads, which limits how confidently the median differences can be assigned to Argus. Headline percentages use condition medians. The machine-readable summary includes paired differences, means and sample standard deviations. The observed differences describe the emulator under its workload and scheduling variability. TCP iperf3 client and server CPU peaks were 106.3% and 105.8% of one guest CPU, respectively. Host scheduling, TCG translation and guest generators can constrain these results.

## Resource usage

| Case | Enabled Argus CPU % of one vCPU | Enabled Argus RSS KiB | Guest system + IRQ + softirq % baseline / enabled |
|---|---:|---:|---:|
| http | 0.21 [0.21, 0.28] | 33932 [31972, 34264] | 4.67 [4.09, 4.91] / 4.49 [4.33, 4.52] |
| tcp-1-forward | 0.20 [0.20, 0.79] | 32164 [32128, 34248] | 80.38 [78.33, 80.77] / 80.12 [78.69, 80.99] |
| tcp-1-reverse | 0.10 [0.10, 0.20] | 32264 [32088, 34172] | 80.69 [76.27, 81.44] / 81.18 [80.01, 81.81] |
| tcp-4-forward | 0.30 [0.20, 0.50] | 34180 [32236, 34348] | 95.37 [94.74, 96.02] / 95.62 [95.43, 96.08] |
| tcp-4-reverse | 0.20 [0.10, 0.30] | 33988 [32040, 34296] | 94.78 [94.51, 94.95] / 95.52 [94.90, 95.86] |
| udp-20M | 0.49 [0.30, 0.59] | 32180 [32024, 34288] | 5.90 [4.92, 6.22] / 6.13 [5.96, 6.58] |
| udp-5M | 0.39 [0.30, 0.59] | 32208 [32084, 34220] | 1.66 [1.35, 1.81] / 1.63 [1.05, 2.28] |

The CPU windows include warm-up. Guest kernel CPU is the whole guest's time in the reported modes across both vCPUs. Guest-reported steal peaked at 0.00%. macOS host overhead and hardware throttling were outside the measured counters.

## Flow capacity and recovery

This was real UDP traffic across the veth. Every trial stage added unique source/destination port tuples. The receiver totals are application observations. Argus collection times include building and publishing the whole snapshot.

| Cumulative sent | UDP receiver packets | BPF map entries | Argus egress observations | Flow update failures | Agent RSS KiB | Median collection ms |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 100 | 100 | 100 | 0 | 32,272 | 6.56 |
| 1,000 | 1,000 | 1,000 | 1,000 | 0 | 34,444 | 54.42 |
| 10,000 | 10,000 | 10,000 | 10,000 | 0 | 51,044 | 236.87 |
| 100,100 | 100,100 | 100,000 | 100,000 | 100 | 195,676 | 1763.66 |

The full-map run exercised directional tuples. The separate synthetic two-entry test confirmed an existing flow still updated after a third tuple failed to insert. The active gauge fell to zero after the generated traffic stopped. The retained entries disappeared on restart. Traffic from a known sender PID produced unknown ownership in the API, as intended.

| BPF map | Capacity | Key / value bytes | Kernel fdinfo memlock bytes |
|---|---:|---:|---:|
| flow_map | 100,000 | 16 / 56 | 14,098,368 |
| flow_update_fai | 1 | 4 / 8 | 288 |

Kernel fdinfo values describe BPF map memory accounting. Agent RSS describes userspace process memory.

## eBPF runtime profile

A separate 10-second UDP run at 5 Mbit/s held a kernel BPF runtime-statistics descriptor open. Runtime and invocation counts below are differences between reads of the same program ID.

| Hook | Invocations | Runtime ns | Mean ns per invocation |
|---|---:|---:|---:|
| ingress | 17 | 516,992 | 30,411.3 |
| egress | 5,229 | 72,194,544 | 13,806.6 |

Closing the descriptor ended profiling and left the guest runtime-statistics sysctl at its initial value of 0. Runtime includes the emulator's execution and measurement overhead. The UDP payload stream crosses the egress hook. The much smaller ingress sample includes return and control traffic.

## Soak and shutdown

The client completed a 600.011-second UDP receiver interval at a 5 Mbit/s target. There were 0 receiver-reported lost datagrams out of 312,502 and 0 Argus flow update failures. There were 60 RSS samples, with a start/end of 34,532/37,536 KiB and observed range of 34,532–37,536 KiB. This was a ten-minute soak.

The occupied HTTP address produced an error exit and both hooks were empty after shutdown. Normal agent stops in the scale, profiling and soak runs were followed by direct TCX queries with zero attached programs. Both namespace pairs were removed and the runtime-statistics setting was verified after profiling.

## Go microbenchmarks

Five repeats per case ran on the macOS arm64 host with the ordinary Go build. These measure userspace operations on synthetic flow records.

| Case | ns/op median [min, max] | B/op median | allocs/op median |
|---|---:|---:|---:|
| BenchmarkExportSnapshots/100-8 | 12,404 [12,334, 12,702] | 400 | 2 |
| BenchmarkExportSnapshots/10000-8 | 1,364,046 [1,328,150, 1,377,987] | 5,549 | 2 |
| BenchmarkComputeStats/100-8 | 1,333 [1,312, 1,348] | 304 | 3 |
| BenchmarkComputeStats/10000-8 | 117,367 [116,790, 118,356] | 304 | 3 |

## Verification and limits

Native Go tests, go vet, native race tests and clean Linux ARM64 and amd64 cross-builds completed. The documented compiler and headers also reproduced the embedded BPF files byte-for-byte. Linux ARM64 ran the collector and exporter test binaries and the privileged BPF tests. Log files and trial data are in [raw](raw/). Early development and setup failures are recorded in [development notes](raw/development-checks.txt).

The evidence covers the version and local emulator described here. Physical network capacity and universal packet visibility remain unverified. Flow-map capacity is a retention limit for directional tuples. Process ownership and application latency need separate instrumentation. These runs provide no source-version speedup comparison or production stability claim.

The raw archive contains all per-trial outputs and the original primary and supplemental run directories. Extract it with `tar -xzf raw/trials.tar.gz -C <new-directory>` to reprocess the JSON.
