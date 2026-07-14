# ==============================================================================
# Multi-Stage Build Dockerfile for Argus (eBPF Observability Agent)
# ==============================================================================

# --- STAGE 1: Builder ---
FROM golang:1.22-bookworm AS builder

# Install build dependencies: Clang, LLVM, libbpf-dev, and Make.
# Clang/LLVM are required to compile the eBPF C programs into BPF bytecode.
# libbpf-dev provides standard helper headers.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory inside the build container
WORKDIR /src

# Copy go.mod and go.sum to cache Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire workspace code
COPY . .

# Pre-install the exact version of bpf2go matching our go.mod (v0.14.0)
# to avoid fetching @latest which requires Go >= 1.24.
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.14.0

# Run the build target from the Makefile.
RUN make build

# --- STAGE 2: Runner ---
# Use a lightweight, clean, slim Debian image for production execution
FROM debian:bookworm-slim

# Install basic network diagnostics tools for convenient debugging inside the container
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set standard workspace directory
WORKDIR /app

# Copy the statically compiled binary from the builder stage
COPY --from=builder /src/bin/argus /app/argus

# Copy the default configurations
COPY --from=builder /src/configs /app/configs

# Expose the default HTTP port for the web dashboard and Prometheus endpoint
EXPOSE 9090

# Set entrypoint to run the Argus binary
ENTRYPOINT ["/app/argus"]
