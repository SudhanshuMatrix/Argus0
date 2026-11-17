.DEFAULT_GOAL := all
.PHONY: all help generate generate-pinned check-generated build vmlinux fmt lint clean

GO ?= go
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOARCH)
CLANG ?= clang
BPF_EXTRA_CFLAGS ?=
BPF_OUTPUT_DIR ?= internal/bpf
LIBBPF_CFLAGS ?= -I/usr/include $(shell pkg-config --cflags libbpf 2>/dev/null)
OUTPUT_DIR ?= ./bin
BINARY = $(OUTPUT_DIR)/argus

help:
	@printf '%s\n' 'build            Build the Linux agent from checked-in BPF objects' \
		'generate         Regenerate BPF objects with the local compiler' \
		'generate-pinned  Regenerate using the pinned Zig and libbpf releases' \
		'check-generated  Check both generated object and binding pairs' \
		'fmt              Format Go source' 'lint             Run go vet'

all: generate
	$(MAKE) build

# The TC programs use only __sk_buff fields and are architecture-independent
# apart from endianness. Check in both generated bindings and their objects.
generate:
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc "$(CLANG)" -no-strip -target bpfel,bpfeb \
		-cflags "-O2 -g -Wall -Wextra -Werror -nostdinc -mcpu=v3 -fdebug-compilation-dir=. -ffile-prefix-map=$(CURDIR)=. -Ibpf/include $(LIBBPF_CFLAGS) $(BPF_EXTRA_CFLAGS)" \
		-go-package bpf -output-dir "$(BPF_OUTPUT_DIR)" \
		-type flow_key_t -type flow_metrics_t NetworkStats ./bpf/programs/network_stats.c

generate-pinned:
	./scripts/bpf-artifacts.sh update

check-generated:
	./scripts/bpf-artifacts.sh check

fmt:
	$(GO) fmt ./...

build:
	@mkdir -p "$(OUTPUT_DIR)"
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build \
		-ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
		-o "$(BINARY)" ./cmd/network-observer

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h.tmp
	mv bpf/include/vmlinux.h.tmp bpf/include/vmlinux.h

lint:
	$(GO) vet ./...

clean:
	rm -f "$(BINARY)"
