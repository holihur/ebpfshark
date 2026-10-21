SHELL := /bin/bash
GO ?= go
PNPM ?= pnpm
CLANG ?= clang
BPFTOOL ?= bpftool

BIN := bin/ebpfshark
WEB_DIR := web
WEB_DIST := internal/server/webdist
VMLINUX := internal/capture/bpf/vmlinux.h
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -X ebpfshark/internal/server.Version=$(VERSION)

.PHONY: all build generate web go-build dev dev-web run test vet deps clean help

all: build

help:
	@echo "Targets:"
	@echo "  make build      Regenerate eBPF, build the UI, compile the binary"
	@echo "  make generate   Rebuild vmlinux.h + eBPF object (needs clang, bpftool)"
	@echo "  make web        Build the React UI into $(WEB_DIST)"
	@echo "  make go-build   Compile the Go binary only"
	@echo "  make run        Run the backend on :9999 (UI must be built)"
	@echo "  make dev        Run the backend on :9999 with debug logging"
	@echo "  make dev-web    Run the Vite dev server on :5173 (proxies to :9999)"
	@echo "  make test       Run Go tests + TypeScript checks"
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

go-build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/ebpfshark

run: go-build
	./$(BIN) -addr :9999

dev:
	$(GO) run ./cmd/ebpfshark -addr :9999 -log-level debug

dev-web:
	cd $(WEB_DIR) && $(PNPM) run dev

test:
	$(GO) test ./...
	cd $(WEB_DIR) && $(PNPM) run lint

vet:
	$(GO) vet ./...

deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev bpftool

clean:
	rm -rf bin $(WEB_DIST)/assets $(WEB_DIST)/index.html $(WEB_DIST)/favicon.svg $(WEB_DIR)/dist
