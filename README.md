<p align="center">
  <img src="internal/api/assets/logo.png" alt="Argus Logo" width="220px">
</p>

# Argus eBPF Kernel Network Observability & DPI Agent

<p align="center">
  <a href="https://hub.docker.com/r/shudhanshusingh/argus">
    <img src="https://img.shields.io/badge/Docker%20Hub-shudhanshusingh%2Fargus-blue?logo=docker" alt="Docker Hub Badge">
  </a>
  <img src="https://img.shields.io/badge/License-Apache%202.0-green?logo=apache" alt="License Badge">
</p>

Argus monitors directional IPv4 TCP and UDP flows on a Linux network interface. It attaches eBPF programs to TCX ingress and egress, records per-flow counters, and exposes snapshots through Prometheus and a web dashboard.

The classifier recognizes common HTTP, TLS handshake and SSH payload prefixes. DNS classification uses port 53 and checks the structure of the DNS header. Payload matching is limited to bytes available in a single socket buffer. It provides neither stream reassembly nor decryption. See the [kernel classifier](bpf/programs/network_stats.c) for the supported patterns.

The flow map holds up to 100,000 directional tuples for the lifetime of the agent. Idle entries remain in the map and the API snapshot. The Prometheus active-flow gauge counts tuples whose counters advanced since the last successful collection. Once the map fills, existing flows continue to update and observation failures for new tuples increment `network_flow_update_failures_total`.

The API leaves process ownership unset because TCX can run in a different task context from the socket owner. Flow duration is the elapsed time between the first and last observed packets in a directional tuple. It describes the observation span and can include idle periods or tuple reuse.

---

## Visual Diagnostics Dashboard

The dashboard displays flow snapshots, byte counts and L7 protocol labels. These screenshots illustrate an earlier interface that included process and latency fields.

### Overview Console
<p align="center">
  <img src="dashboard_screenshot_1.png" alt="Argus Diagnostics UI - Overview Console" width="100%">
</p>

### Stream Inspection Console
<p align="center">
  <img src="dashboard_screenshot_2.png" alt="Argus Diagnostics UI - Stream Inspection Console" width="100%">
</p>

---

## Prometheus Telemetry Schema

Counters account for changes between successful snapshots. When classification changes, subsequent increments use the new label and prior increments remain under the original label.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `network_bytes_total` | Counter | `interface`, `protocol`, `l7_protocol`, `direction` | Monotonically increasing counter of bytes |
| `network_packets_total` | Counter | `interface`, `protocol`, `l7_protocol`, `direction` | Monotonically increasing counter of packets |
| `network_active_connections` | Gauge | `interface`, `protocol`, `l7_protocol` | Directional tuples with newly observed traffic since the previous collection |
| `network_flow_map_entries` | Gauge | `interface` | Entries in the most recent successful collection |
| `network_flow_update_failures_total` | Counter | `interface` | Packets whose flow update could not be recorded |

Bytes count `skb->len` at the hook. Network offloads and hook placement can change the relationship between socket buffers and packets on a network link.

### PromQL examples
```promql
# Graph Ingress TLS traffic throughput (bytes/sec)
sum(rate(network_bytes_total{direction="ingress", l7_protocol="TLS"}[5m]))

# Group observed TCP byte rates by application protocol
sum by (l7_protocol) (rate(network_bytes_total{protocol="TCP"}[5m]))

# Monitor active DNS connection gauges
network_active_connections{l7_protocol="DNS"}
```

---

## Quick Start & Installation

### Prerequisites

- Linux with BPF and TCX support and permission to load BPF objects and attach TCX programs. TCX was introduced in Linux 6.6.
- Go 1.21 or later. The module suggests Go 1.22.5.
- For BPF source changes, install Clang with the BPF backend and libbpf headers. `make generate` uses the module's pinned bpf2go version.

### 1. Build and Run
```bash
git clone https://github.com/SudhanshuMatrix/Argus0.git
cd Argus0

# Compile the Go agent binary
make build

# Start the agent on your network interface (e.g., enp2s0 or eth0)
sudo ./bin/argus --interface enp2s0
```

### 2. Build and Run with Docker (Recommended)
Docker and Docker Compose can build the agent using the checked-in BPF objects. Host-interface monitoring requires a Linux container host with TCX support and permission to attach to the named interface.

#### Option A: Docker Compose (Easiest)
Make sure you have created your `.env` file from `.env.example` and set your active interface (`ARGUS_INTERFACE=eth0` or `ARGUS_INTERFACE=enp2s0`):

```bash
# Build the image and run the agent in the foreground
sudo docker compose up --build

# Run in the background (detached)
sudo docker compose up -d --build

# Stop the agent
sudo docker compose down
```

#### Option B: Docker CLI
You can pull and run the pre-built image directly from Docker Hub:

```bash
# Run the pre-built eBPF agent container from Docker Hub
sudo docker run -d \
  --name argus \
  --privileged \
  --network host \
  --pid host \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -v $(pwd)/configs:/app/configs:ro \
  -e ARGUS_INTERFACE=eth0 \
  -p 9090:9090 \
  --restart unless-stopped \
  shudhanshusingh/argus:latest
```

Alternatively, you can build and run it locally:
```bash
# Build the image locally
docker build -t argus:latest .

# Run the local image
sudo docker run -d \
  --name argus \
  --privileged \
  --network host \
  --pid host \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -v $(pwd)/configs:/app/configs:ro \
  -e ARGUS_INTERFACE=eth0 \
  -p 9090:9090 \
  --restart unless-stopped \
  argus:latest
```

### 3. Access the Consoles
*   **Web Diagnostics UI:** `http://localhost:9090`
*   **Prometheus Metrics Endpoint:** `http://localhost:9090/metrics`

### 4. Verify L7 Detection

Send a plain HTTP request to a server you control across the monitored interface. After a collection interval, look for the directional tuple and its `HTTP` label in `/api/flows`. Enable trace logging if you need a JSON line for each sampled flow.

---

## Benchmarks

In 70 trials across 35 baseline/enabled pairs on an ARM64 Linux guest under QEMU software emulation, enabling Argus was associated with median TCP receiver throughput reductions of 0.16% to 5.93%. The baseline and enabled ranges overlapped for all four TCP workloads. Median per-trial HTTP p99 was 55.77 ms detached and 56.85 ms attached. See the [full validation report](benchmarks/results/2026-11-15-637ddfa/report.md) and [reproduction instructions](benchmarks/README.md).

---

## Project Structure

```
argus/
├── bpf/
│   ├── include/
│   │   ├── common.h          # Shared structs (flow_key_t, flow_metrics_t)
│   │   └── vmlinux.h         # Relocatable kernel type mapping
│   └── programs/
│       └── network_stats.c   # eBPF C program (Ingress/Egress TC hooks + DPI Engine)
├── cmd/
│   └── network-observer/
│       └── main.go           # Daemon entry point & YAML configuration parser
├── configs/
│   └── default.yaml          # Agent intervals & network server configs
├── deploy/
│   └── kubernetes/
│       └── daemonset.yaml    # Kubernetes DaemonSet deployment spec
├── internal/
│   ├── bpf/
│   │   └── loader.go         # TCX links and BPF map loader
│   ├── collector/
│   │   └── flow_collector.go # Map iterator, L7 name mapper, JSON formatter
│   ├── config/
│   │   └── config.go         # Struct configuration loader
│   ├── enricher/
│   │   └── process.go        # Thread-safe VFS /proc parser & PID cache
│   └── exporter/
│       ├── exporter.go       # Exporter interface
│       └── prometheus.go     # Custom Prometheus Collector HTTP Server
│   └── api/
│       └── dashboard.html    # Interactive Glassmorphism Dashboard UI
├── Makefile
├── go.mod
└── README.md
```

---

## Kubernetes Deployment Guide

To observe network flows cluster-wide, Argus is deployed as a **DaemonSet** so that exactly one monitoring agent pod runs on every Linux node in your cluster.

### 1. Required Privileges & Mounts
Because eBPF interacts directly with host-level sockets, network interfaces, and kernel subsystems, the DaemonSet requires specific security privileges and host directory mounts:
*   **`securityContext.privileged: true`** (or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` capabilities) to load Traffic Control links and access kernel rings.
*   **Host Network (`hostNetwork: true`):** Runs the pod in the node's network namespace to attach hooks directly to host physical interfaces (like `eth0` or `bond0`).
*   **Host `/sys/fs/bpf` Volume:** Mounts the host's BPF virtual filesystem so maps can be inspected or persisted.

### 2. Deploying Argus
Deploy the pre-configured DaemonSet and RBAC authorization resources to your cluster:
```bash
# Create the monitoring namespace
kubectl create namespace monitoring

# Apply the DaemonSet configurations
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

### 3. Verify the Deployment
```bash
# Verify pods are running on every cluster node
kubectl get pods -n monitoring -l app=argus -o wide

# Inspect the logs of an active agent pod
kubectl logs -n monitoring -l app=argus --tail=100 -f
```

---

## eBPF Architecture Notes

The current parser handles unfragmented IPv4 TCP and UDP over Ethernet. In-packet VLAN headers, IPv6 and fragmented packets are outside the accounting scope. The running agent holds TCX links and BPF maps through file descriptors. Closing the descriptors releases its references.

---

## License

Argus is licensed under the Apache 2.0 License.
