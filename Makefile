# =============================================================================
# Argus — eBPF Network Observability Tool
# Makefile
#
# Targets:
#   make generate   — compile C → .o and run bpf2go to generate Go bindings
#   make build      — compile the Go agent binary
#   make vmlinux    — regenerate vmlinux.h from the running kernel's BTF
#   make lint       — run golangci-lint
#   make clean      — remove generated files and binaries
#   make all        — generate + build (default)
#
# Prerequisites (install once):
#   apt install clang llvm libbpf-dev linux-headers-$(uname -r)
#   go install github.com/cilium/ebpf/cmd/bpf2go@latest
#   # Optional: bpftool for vmlinux regeneration
#   apt install linux-tools-$(uname -r)
# =============================================================================

# --------------------------------------------------------------------------- #
# Tunables — override on the command line, e.g.:
#   make build ARCH=arm64 OUTPUT_DIR=./out
# --------------------------------------------------------------------------- #
ARCH        ?= $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
TARGET_ARCH ?= $(shell uname -m)   # Used in clang -target triple
OUTPUT_DIR  ?= ./bin
BPF_SRC_DIR ?= ./bpf/programs
BPF_INC_DIR ?= ./bpf/include
# Where bpf2go writes generated .go files
GEN_DIR     ?= ./internal/bpf

# --------------------------------------------------------------------------- #
# Toolchain
# --------------------------------------------------------------------------- #
CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
GO         ?= go
BPF2GO     ?= $(shell $(GO) env GOPATH)/bin/bpf2go

# --------------------------------------------------------------------------- #
# Binary name
# --------------------------------------------------------------------------- #
BINARY      = $(OUTPUT_DIR)/argus

# --------------------------------------------------------------------------- #
# C compiler flags for eBPF target
#
# -target bpf          : emit BPF bytecode (not native machine code)
# -D__TARGET_ARCH_*    : tells vmlinux.h which architecture's struct layouts
#                        to expose (required for CO-RE field relocations)
# -g                   : emit DWARF debug info (BTF is derived from DWARF by
#                        clang's integrated BPF backend; required for CO-RE)
# -O2                  : required — the verifier is much happier with optimised
#                        code; -O0 often produces programs that fail verification
#                        because of unnecessary stack spills and complex CFGs
# -Wall -Wextra        : catch common C mistakes early
# -Werror              : treat warnings as errors for CI robustness
# -nostdinc            : do NOT use system C headers; use only vmlinux.h
# -isystem             : point clang at libbpf's bpf/ headers (bpf_helpers.h etc.)
# --------------------------------------------------------------------------- #
LIBBPF_HEADERS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include/bpf")

# Determine the clang -D flag for the target architecture (required by vmlinux.h)
ifeq ($(TARGET_ARCH),x86_64)
  ARCH_FLAG := -D__TARGET_ARCH_x86
else ifeq ($(TARGET_ARCH),aarch64)
  ARCH_FLAG := -D__TARGET_ARCH_arm64
else ifeq ($(TARGET_ARCH),arm)
  ARCH_FLAG := -D__TARGET_ARCH_arm
else
  $(warning Unknown TARGET_ARCH=$(TARGET_ARCH); defaulting to x86)
  ARCH_FLAG := -D__TARGET_ARCH_x86
endif

CFLAGS := \
    -target bpf              \
    $(ARCH_FLAG)             \
    -g                       \
    -O2                      \
    -Wall                    \
    -Wextra                  \
    -Werror                  \
    -nostdinc                \
    -I$(BPF_INC_DIR)         \
    -I/usr/include           \
    $(LIBBPF_HEADERS)

# --------------------------------------------------------------------------- #
# bpf2go flags
#
# bpf2go wraps clang and also passes these extra flags when it invokes clang
# internally. We need to point it at our include directory so it can find
# common.h. The generated files land in GEN_DIR.
# --------------------------------------------------------------------------- #
BPF2GO_FLAGS := \
    -cc $(CLANG)             \
    -cflags "$(CFLAGS)"      \
    -target $(ARCH)          \
    -go-package bpf          \
    -no-strip                \
    -output-dir $(GEN_DIR)

# --------------------------------------------------------------------------- #
# Source files
# --------------------------------------------------------------------------- #
BPF_C_SRC := $(BPF_SRC_DIR)/network_stats.c

# All generated files produced by bpf2go. Listing them lets `make` skip
# regeneration when the sources haven't changed.
BPF2GO_GENERATED := \
    $(GEN_DIR)/network_stats_bpfeb.go  \
    $(GEN_DIR)/network_stats_bpfel.go  \
    $(GEN_DIR)/network_stats_bpfeb.o   \
    $(GEN_DIR)/network_stats_bpfel.o

# All Go source files (for dependency tracking on the build target)
GO_SRCS := $(shell find . -name '*.go' -not -path '*/vendor/*' 2>/dev/null)

# =============================================================================
# Phony targets — not real files
# =============================================================================
.PHONY: all generate build vmlinux lint clean help

# Default target
all: generate build

# --------------------------------------------------------------------------- #
# help — print a usage summary
# --------------------------------------------------------------------------- #
help:
	@echo ""
	@echo "  Argus Makefile targets:"
	@echo ""
	@echo "    make all        Generate eBPF bindings and build the binary (default)"
	@echo "    make generate   Compile C → BPF object and run bpf2go"
	@echo "    make build      Compile the Go agent binary to $(BINARY)"
	@echo "    make vmlinux    Regenerate bpf/include/vmlinux.h from running kernel"
	@echo "    make lint       Run golangci-lint"
	@echo "    make clean      Remove generated files and binaries"
	@echo ""

# --------------------------------------------------------------------------- #
# vmlinux.h — generate from the running kernel's BTF blob
#
# This target MUST be run once on the target kernel before anything else.
# The resulting vmlinux.h is checked into the repository so CI doesn't need
# bpftool, but developers should regenerate it when upgrading the kernel.
# --------------------------------------------------------------------------- #
vmlinux:
	@echo "[vmlinux] Regenerating bpf/include/vmlinux.h from kernel BTF..."
	@if ! command -v $(BPFTOOL) >/dev/null 2>&1; then \
	    echo "ERROR: bpftool not found. Install with: apt install linux-tools-\$$(uname -r)"; \
	    exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_INC_DIR)/vmlinux.h
	@echo "[vmlinux] Done: $(BPF_INC_DIR)/vmlinux.h"

# --------------------------------------------------------------------------- #
# generate — compile the C eBPF program and generate Go bindings
#
# bpf2go:
#   1. Invokes clang with the given -cflags to compile network_stats.c into
#      two .o files: one little-endian (bpfel) and one big-endian (bpfeb).
#   2. Reads the BTF from each .o to extract map and program definitions.
#   3. Emits .go files with typed Go structs for every map and program so the
#      agent can load and interact with the BPF objects without reflection.
#
# The generated files use //go:embed directives to embed the .o bytes directly
# into the Go binary — no need to ship separate .o files at runtime.
# --------------------------------------------------------------------------- #
generate: $(GEN_DIR)/network_stats_bpfel.go

$(GEN_DIR)/network_stats_bpfel.go: $(BPF_C_SRC) $(BPF_INC_DIR)/common.h $(BPF_INC_DIR)/vmlinux.h
	@echo "[bpf2go] Generating Go bindings from $(BPF_C_SRC)..."
	@mkdir -p $(GEN_DIR)
	@if [ ! -f "$(BPF2GO)" ]; then \
	    echo "Installing bpf2go..."; \
	    $(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest; \
	fi
	$(BPF2GO) \
	    $(BPF2GO_FLAGS)         \
	    NetworkStats            \
	    $(BPF_C_SRC)
	@echo "[bpf2go] Generated files in $(GEN_DIR)"

# --------------------------------------------------------------------------- #
# build — compile the Go binary
#
# CGO_ENABLED=0 produces a statically linked binary.
# -ldflags "-s -w" strips debug symbols for a smaller production binary.
# Use CGO_ENABLED=1 if you need cgo (e.g., some libbpf wrappers). cilium/ebpf
# is pure Go and does NOT require cgo.
# --------------------------------------------------------------------------- #
build: generate
	@echo "[build] Compiling Go agent..."
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 $(GO) build \
	    -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
	    -o $(BINARY)            \
	    ./cmd/network-observer/...
	@echo "[build] Binary: $(BINARY)"

# --------------------------------------------------------------------------- #
# lint — static analysis
# --------------------------------------------------------------------------- #
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
	    golangci-lint run ./...; \
	else \
	    echo "golangci-lint not found; skipping lint"; \
	fi

# --------------------------------------------------------------------------- #
# clean — remove all generated artefacts
# --------------------------------------------------------------------------- #
clean:
	@echo "[clean] Removing generated files and binaries..."
	rm -f $(BPF2GO_GENERATED)
	rm -rf $(OUTPUT_DIR)
	@echo "[clean] Done"
