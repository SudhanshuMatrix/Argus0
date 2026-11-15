.PHONY: all generate build vmlinux lint clean

GO ?= go
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOARCH)
CLANG ?= clang
BPF_EXTRA_CFLAGS ?=
LIBBPF_CFLAGS ?= -I/usr/include $(shell pkg-config --cflags libbpf 2>/dev/null)
OUTPUT_DIR ?= ./bin
BINARY = $(OUTPUT_DIR)/argus

all: generate
	$(MAKE) build

# The TC programs use only __sk_buff fields and are architecture-independent
# apart from endianness. Check in both generated bindings and their objects.
generate:
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc "$(CLANG)" -no-strip -target bpfel,bpfeb \
		-cflags "-O2 -g -Wall -Wextra -Werror -nostdinc -fdebug-compilation-dir=. -Ibpf/include $(LIBBPF_CFLAGS) $(BPF_EXTRA_CFLAGS)" \
		-go-package bpf -output-dir internal/bpf NetworkStats ./bpf/programs/network_stats.c

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
