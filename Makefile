SHELL := /bin/bash
GO ?= go
PNPM ?= pnpm
CLANG ?= clang
BPFTOOL ?= bpftool

BIN := bin/ebpfshark
WEB_DIR := web
WEB_DIST := internal/server/webdist
VMLINUX := internal/capture/bpf/vmlinux.h
GENERATED := internal/capture/capture_bpfel.go internal/capture/capture_bpfel.o
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -X ebpfshark/internal/server.Version=$(VERSION)

.PHONY: all build generate web go-build go-build-full dev dev-web run test test-full vet deps clean help

all: build

help:
	@echo "Targets:"
	@echo "  make build      Regenerate eBPF, build the UI, compile the binary"
	@echo "  make generate   Rebuild vmlinux.h + eBPF object (needs clang, bpftool)"
	@echo "  make web        Build the React UI into $(WEB_DIST)"
	@echo "  make go-build   Compile the core Go binary (common protocols only)"
	@echo "  make go-build-full  Compile with all protocol dissectors (-tags full)"
	@echo "  make run        Run the backend on :9999 (UI must be built)"
	@echo "  make dev        Run the backend on :9999 with debug logging"
	@echo "  make dev-web    Run the Vite dev server on :5173 (proxies to :9999)"
	@echo "  make test       Run core + full Go tests and TypeScript checks"
	@echo "  make test-full  Run Go tests with all protocol dissectors"
	@echo "  make deps       Install eBPF build dependencies (Debian/Ubuntu)"
	@echo "  make clean      Remove build artifacts"

build: generate web go-build

generate: $(VMLINUX)
	cd internal/capture && $(GO) generate ./...

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

web:
	cd $(WEB_DIR) && $(PNPM) install --frozen-lockfile
	cd $(WEB_DIR) && $(PNPM) run build
	rm -rf $(WEB_DIST)
	mkdir -p $(WEB_DIST)
	cp -r $(WEB_DIR)/dist/. $(WEB_DIST)/
	touch $(WEB_DIST)/.keep

go-build: $(GENERATED)
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/ebpfshark

go-build-full: $(GENERATED)
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -tags full -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/ebpfshark

$(GENERATED): $(VMLINUX) internal/capture/bpf/capture.c internal/capture/generate.go
	cd internal/capture && $(GO) generate ./...

run: go-build
	./$(BIN) -addr :9999

dev: $(GENERATED)
	$(GO) run ./cmd/ebpfshark -addr :9999 -log-level debug

dev-web:
	cd $(WEB_DIR) && $(PNPM) run dev

test: $(GENERATED)
	$(GO) test ./...
	$(GO) test -tags full ./...
	cd $(WEB_DIR) && $(PNPM) run lint

test-full: $(GENERATED)
	$(GO) test -tags full ./...

vet: $(GENERATED)
	$(GO) vet ./...

deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev bpftool

clean:
	rm -rf bin $(WEB_DIST)/assets $(WEB_DIST)/index.html $(WEB_DIST)/favicon.svg $(WEB_DIR)/dist
	rm -f $(GENERATED) $(VMLINUX)
