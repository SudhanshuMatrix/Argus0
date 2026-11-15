# ==============================================================================
# Multi-Stage Build Dockerfile for Argus (eBPF Observability Agent)
# ==============================================================================

# --- STAGE 1: Builder ---
FROM golang:1.22-bookworm AS builder

# Set up working directory inside the build container
WORKDIR /src

# Copy go.mod and go.sum to cache Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire workspace code
COPY . .

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
