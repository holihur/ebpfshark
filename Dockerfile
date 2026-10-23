# syntax=docker/dockerfile:1

# ebpfshark is a Linux/eBPF application. The build stage needs clang, bpftool
# and host BTF to generate the CO-RE eBPF object; the runtime stage needs a
# Linux kernel >= 6.6 and the capabilities documented in docs/DOCKER.md.
ARG GO_VERSION=1.26
ARG NODE_VERSION=24

FROM node:${NODE_VERSION}-bookworm-slim AS web-builder
WORKDIR /src/web
RUN npm install -g pnpm@12.4.1
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM golang:${GO_VERSION}-bookworm AS go-builder
ARG VERSION=dev
ARG BUILD_TARGET=go-build-full
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev linux-tools-common linux-tools-generic \
      make git ca-certificates \
 && BPFTOOL="$(find /usr/lib/linux-tools -name bpftool | sort | tail -1)" \
 && test -n "$BPFTOOL" \
 && ln -sf "$(readlink -f "$BPFTOOL")" /usr/local/bin/bpftool \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/web/dist ./web/dist
RUN make generate \
 && mkdir -p internal/server/webdist \
 && cp -r web/dist/. internal/server/webdist/ \
 && touch internal/server/webdist/.keep \
 && make "${BUILD_TARGET}" VERSION="${VERSION}"

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /src/bin/ebpfshark /usr/local/bin/ebpfshark
# Container must run as root (or be given effective BPF/NET_ADMIN caps).
ENV EBPFSHARK_ADDR=:9999 \
    EBPFSHARK_AUTO_UPDATE=false
EXPOSE 9999
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/ebpfshark"]
