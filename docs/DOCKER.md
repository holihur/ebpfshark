# Docker

ebpfshark runs in Docker, but it is **not** a normal isolated web app. It needs
host networking and eBPF capabilities, so treat the container as a host-level
network analyser.

## Requirements

| Item | Requirement |
| --- | --- |
| Host kernel | Linux >= 6.6 with BTF (`/sys/kernel/btf/vmlinux`) |
| Docker | Linux containers; a Docker Engine with `bpf` syscall permitted |
| Architectures | Same architecture as the runtime host; the image is not a cross-arch build |
| Build host | Linux with access to BTF while `make generate` runs |
| Runtime kernel | The container shares the host kernel; Docker Desktop's VM is not the host |

The default image is a **static full build** (`-tags full`) and does not support
dynamic `.so` plugins. Build with `BUILD_TARGET=go-build-dynamic` if plugin
loading is required.

## Build

```bash
docker build \
  --build-arg VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
  -t ebpfshark:local .
```

The build stage installs clang/llvm/bpftool, generates the eBPF object, builds
the React UI and embeds it into the Go binary. The first build needs network
access for Go modules, npm packages and Debian packages.

Dynamic-plugin capable image:

```bash
docker build \
  --build-arg BUILD_TARGET=go-build-dynamic \
  --build-arg VERSION=local-dynamic \
  -t ebpfshark:dynamic .
```

The plugin and the image must be built with the same Go toolchain/module graph;
see [PLUGINS.md](PLUGINS.md).

## Run

```bash
docker run --rm -it \
  --name ebpfshark \
  --network host \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=PERFMON \
  --cap-add=SYS_RESOURCE \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -e EBPFSHARK_AUTH_PASS='change-this-password' \
  ebpfshark:local \
  -addr 127.0.0.1:9999 -capture eth0
```

Open `http://127.0.0.1:9999`.

Why each option is needed:

| Option | Purpose |
| --- | --- |
| `--network host` | Capture the host interface; bridge networking only sees the container netns |
| `--cap-add=BPF` | Load eBPF programs |
| `--cap-add=NET_ADMIN` | Attach TCX programs and manage interfaces |
| `--cap-add=PERFMON` | Not strict for TCX, but included for perf-related BPF paths/tooling |
| `--cap-add=SYS_RESOURCE` | Raise memlock for maps and the ring buffer |
| `seccomp=unconfined` | Many Docker profiles block `bpf()` even with capabilities |
| `apparmor=unconfined` | Some hosts block BPF loading through AppArmor |
| `memlock=-1` | eBPF maps/ring buffer need locked memory |
| BTF mount | Runtime CO-RE/BTF lookup |

`CAP_PERFMON` alone does not replace `CAP_BPF`/`CAP_NET_ADMIN`. The real TCX
minimum is `CAP_BPF + CAP_NET_ADMIN`.

### Authentication and exposure

- The image defaults to `EBPFSHARK_AUTO_UPDATE=false`; update by rebuilding the
  image instead of self-updating inside a container.
- If `EBPFSHARK_AUTH_PASS` is unset, a random password is printed to the
  container log (`docker logs ebpfshark`).
- Bind to `127.0.0.1` when possible. For remote access, put a TLS reverse proxy
  in front and use `-secure-cookie`; do not expose `:9999` directly to the
  Internet.
- The MCP endpoint is independent from the web login and uses its own bearer
  token (`-mcp-token` / `EBPFSHARK_MCP_TOKEN`). Protect it with the same care.

## Docker Compose

```yaml
services:
  ebpfshark:
    build:
      context: .
      args:
        VERSION: local
    image: ebpfshark:local
    container_name: ebpfshark
    network_mode: host
    cap_add:
      - BPF
      - NET_ADMIN
      - PERFMON
      - SYS_RESOURCE
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro
      # Optional dynamic plugins, only for go-build-dynamic images:
      # - ./plugins:/plugins:ro
    environment:
      EBPFSHARK_AUTH_PASS: change-this-password
      EBPFSHARK_AUTO_UPDATE: "false"
    command:
      - -addr
      - 127.0.0.1:9999
      - -capture
      - eth0
```

Change `eth0` to the host interface you want. If you use dynamic plugins, add:

```yaml
    command:
      - -addr
      - 127.0.0.1:9999
      - -capture
      - eth0
      - -plugins
      - /plugins/example.so
```

## Risks

Docker does **not** make this configuration safe by itself:

1. **Host network access.** `--network host` lets the process see host traffic;
   captured packets may contain credentials, tokens, personal data or internal
   service traffic.
2. **Powerful capabilities.** `CAP_BPF` + `CAP_NET_ADMIN` can load BPF programs
   and modify/attach network hooks. `seccomp=unconfined` and
   `apparmor=unconfined` remove additional isolation layers.
3. **Root in the container.** The default container user is root because
   capabilities and eBPF loading are simplest that way. A container escape or
   malicious plugin becomes a host compromise.
4. **Dynamic plugins are native code.** A `.so` plugin runs with the capture
   process's full privileges. Only load plugins you built or reviewed. Never
   mount an untrusted plugin directory.
5. **Exposed API.** The HTTP API can read/export captured traffic and control
   capture. Keep authentication enabled, bind to localhost, and use TLS in
   front of any remote access.
6. **No Docker socket.** Do not mount `/var/run/docker.sock`; it gives the
   container host-level control and is not needed by ebpfshark.
7. **Kernel compatibility.** A different kernel/toolchain can change BTF/CO-RE
   behavior. Rebuild the image for the target fleet when needed.
8. **Docker Desktop is not host capture.** On macOS/Windows, the Linux VM is
   the container host; `eth0` is the VM interface, not the physical host NIC.

`--privileged` works as a fallback but gives away essentially all isolation and
is not recommended. Prefer the explicit capability list above.

## Troubleshooting

| Error | Fix |
| --- | --- |
| `operation not permitted` while loading BPF | Add `CAP_BPF`; check `seccomp=unconfined` and AppArmor |
| `bpf: BPF not allowed` | Docker default seccomp is blocking `bpf()`; use a custom profile or `seccomp=unconfined` |
| `failed to load BTF` | Mount `/sys/kernel/btf/vmlinux:ro`; enable kernel BTF |
| `cannot allocate memory` / map creation fails | Add `--cap-add=SYS_RESOURCE` and `--ulimit memlock=-1:-1` |
| Interface not found | Use `--network host`; verify the interface name on the host |
| Captures start but no packets | Confirm interface direction, TCX support (kernel >= 6.6), and that traffic is in the host netns |
| Docker build fails at `make generate` | Build on Linux with `/sys/kernel/btf/vmlinux`; install clang/llvm/bpftool |
| Plugin load fails | The image must be `go-build-dynamic`, and the `.so` must match its Go toolchain/ABI |

For the non-Docker security model and capability details, see
[INSTALL.md](INSTALL.md) and the README.
