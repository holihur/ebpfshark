# sisyphus

> 基于 **eBPF** 的 Linux 网络、进程与函数分析器。

ebpfshark 通过 TCX 在 Linux 网卡 ingress/egress 抓包，浏览器中提供实时报文列表、Wireshark 风格协议树和十六进制视图；同时提供 HTTP/SSE API、MCP 和 pcap 导入导出。

![sisyphus screenshot](docs/screenshot.png)

## 核心功能

- **实时抓包**：多网卡、ingress + egress、snaplen、采样率；支持 pcap/pcapng 导入导出。
- **浏览器分析**：报文列表、可展开协议树、hex/ASCII、字段高亮、虚拟滚动、自定义显示列（显示/隐藏/排序）。
- **显示过滤器**：字段比较、CIDR、端口范围、布尔表达式、`contains`，以及可视化构造器。
- **混合过滤**：安全可下推的 L2–L4 条件编译进 eBPF，应用层字段和复杂表达式继续在用户态精确匹配。
- **TCP 流分析**：乱序/重传/重叠处理、Follow Stream、双向会话统计。
- **AI / HTTPS 解析**：Anthropic Messages、OpenAI Chat Completions、OpenAI Responses，支持 JSON/SSE；支持 TLS keylog，以及可选的本地 HTTPS MITM 代理（页面设置、CA 下载）。
- **范围抓包**：左侧进程列表直接按 cgroup 过滤；也支持 cgroup v2 路径、Pod/容器片段。
- **函数调用追踪（实验）**：CLI、Web 页面和 MCP 均可对显式 `binary:symbol` 挂 uprobe/uretprobe；Web 支持进程 PID 提示和函数符号列表。
- **本地 IPC / Unix 域套接字**：枚举 `/proc/net/unix` 的套接字、属主与 cgroup，并可用 eBPF 追踪 AF_UNIX 双向负载（按 PID/cgroup 过滤）。
- **服务化访问**：登录认证、SSE 实时推送、HTTP API、MCP；支持单二进制、Docker 和动态插件。

## 界面预览

| 实时抓包与协议分析 | 显示过滤器与可视化构造器 |
| --- | --- |
| ![实时抓包、协议树和十六进制视图](docs/screenshot.png) | ![过滤器构造器](docs/filter-builder.png) |
| 报文列表、方向、协议树、hex/ASCII 与字段联动。 | 手写表达式（语法高亮、历史记录、协议搜索）或可视化组合条件。 |

| Follow Stream | 更多操作：导入/导出 |
| --- | --- |
| ![TCP Follow Stream](docs/follow-stream.png) | ![更多菜单](docs/header-menu.png) |
| 双向 TCP 会话、乱序/重传处理和流内搜索。 | pcap/pcapng 导入、全量或当前过滤结果导出。 |

## 快速开始

### Docker

```bash
docker build -t ebpfshark:local .

docker run --rm -it \
  --network host \
  --cap-add=BPF --cap-add=NET_ADMIN --cap-add=PERFMON --cap-add=SYS_RESOURCE \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -e EBPFSHARK_AUTH_PASS='change-this-password' \
  ebpfshark:local -addr 127.0.0.1:9999 -capture eth0
```

Docker 需要 host network、eBPF capability、放宽 seccomp/AppArmor 和 BTF。风险和排障见 **[docs/DOCKER.md](docs/DOCKER.md)**。

### 一键安装（systemd）

```bash
curl -fsSL https://raw.githubusercontent.com/holihur/ebpfshark/main/install.sh | sudo bash
```

默认安装 **full** 版本，启用 systemd 和自动更新；每 **10 分钟**检查 GitHub Release 的更新 manifest。安装时还会生成并信任本地 MITM CA、写入 `HTTPS_PROXY` 登录 profile，使新启动的应用可直接看到 HTTPS 明文。安装完成后会打印登录密码和 MCP Token。

不需要系统级 HTTPS 明文时使用：

```bash
curl -fsSL https://raw.githubusercontent.com/holihur/ebpfshark/main/install.sh | sudo bash -s -- --no-mitm-system
```

也可以从本地仓库安装：

```bash
sudo ./install.sh
```

安装、更新 manifest、卸载和回滚见 **[docs/INSTALL.md](docs/INSTALL.md)**。

### 源码构建

```bash
make build
sudo ./bin/ebpfshark -addr :9999 -capture eth0
```

首次打开 `http://localhost:9999`，使用启动时打印的 `admin` 凭据登录。

### HTTPS 明文（MITM）

默认在 `127.0.0.1:18080` 启动本地 HTTPS 解密代理（端口占用时自动换一个回环端口）。进入 **More → HTTPS decryption proxy**：

1. 安装脚本默认已经把 CA 加入系统信任，并写入登录 profile；重新登录或重启应用一次
2. 如果禁用系统模式，则在页面下载 CA 并设置 `HTTPS_PROXY=http://<页面显示的地址>`
3. 代理解密后的请求/响应会作为 `mitm` 虚拟报文进入报文列表，可直接用 `http`、`https`、`ai` 等过滤器查看

不使用代理时，HTTPS 仍只能看到 TLS 元数据。证书 pinning、强制代理外的直连和部分非 HTTP 协议无法通过 MITM 解密。

## 函数调用追踪

CLI：

```bash
# 检查符号 / build-id / debuginfo
sudo ./bin/ebpfshark trace -pid 1234 -inspect

# 追踪显式函数
sudo ./bin/ebpfshark trace \
  -pid 1234 \
  -func /usr/local/bin/app:main.handler \
  -duration 10s

# 目标即 PID 的 exe 时可以省略 binary
sudo ./bin/ebpfshark trace -pid 1234 -func :main.handler

# 共享库或已知偏移
sudo ./bin/ebpfshark trace -pid 1234 -func /usr/lib/libfoo.so:foo
sudo ./bin/ebpfshark trace -pid 1234 -func /usr/local/bin/app:@0x1234
```

Web 侧栏 **Trace** 标签和 MCP 的 `start_function_trace` / `query_function_trace` 提供同样的能力。`inspect` 可显示 build-id、符号数、debuginfo、容器/Pod cgroup；事件旁边的 `↔` 可查找同一 cgroup、同一时间窗口内的网络包。需要显式符号、带符号 ELF 和 `CAP_BPF`/`CAP_PERFMON`；stripped 二进制会提示安装 debuginfo 或改用地址。

## 本地 IPC / Unix 域套接字

侧栏 **Local IPC** 或 API `GET /api/ipc/sockets` 会列出 `/proc/net/unix` 中的 Unix
域套接字，并尽力从 `/proc/<pid>/fd` 解析属主 PID、命令、可执行文件和 cgroup。套接字
清单不需要 BPF 权限。

启动负载追踪后，eBPF 通过 fentry/fexit 在 AF_UNIX 的发送与接收路径复制负载，覆盖
stream、dgram、seqpacket；每个 iovec 段最多复制 4 KiB，最多记录 8 段，超出部分标记
截断。事件按 socket inode 聚合为双向流，可按 PID 或 cgroup 过滤，适合排查
Docker/containerd、systemd、D-Bus、X11/Wayland、本地 RPC、数据库 socket 等流量。

```bash
curl -s -b /tmp/ebpfshark.cookie 'localhost:9999/api/ipc/sockets?type=stream&q=postgres' | jq
curl -s -b /tmp/ebpfshark.cookie -X POST localhost:9999/api/ipc/start \
  -H 'Content-Type: application/json' -d '{"pid":1234,"maxPayload":4096}'
curl -s -b /tmp/ebpfshark.cookie 'localhost:9999/api/ipc/events?limit=100' | jq
curl -s -b /tmp/ebpfshark.cookie 'localhost:9999/api/ipc/streams' | jq
curl -sN -b /tmp/ebpfshark.cookie 'localhost:9999/api/ipc/stream?after=0'
curl -s -b /tmp/ebpfshark.cookie 'localhost:9999/api/ipc/export?format=jsonl' -o ipc.jsonl
curl -s -b /tmp/ebpfshark.cookie -X POST localhost:9999/api/ipc/stop
```

负载追踪需要 root / `CAP_BPF` + `CAP_PERFMON`、内核 BTF 和 fentry/fexit 支持（本项目的
内核下限 6.6 已满足）。事件/流分别有上限（默认 20,000 条事件、4,096 条流），不会无限
增长；Web UI 使用 SSE 实时接收，也可导出 JSONL。需要落盘时设置
`-ipc-log /var/log/ebpfshark-ipc.jsonl`（或 `EBPFSHARK_IPC_LOG`），每个事件按行追加。

## 常用参数

```text
-capture eth0,lo         启动即抓包的网卡列表
-cgroup pid:1234         只抓指定 cgroup / PID / Pod / 容器
-addr :9999              监听地址
-auth-pass ""            登录密码；留空则随机生成
-max-packets 100000      内存中保留的报文数
-ipc-log ""             本地 IPC 事件的 JSONL 追加日志（可选持久化）
-snaplen 2048            每包捕获字节数（2K/4K/16K/64K/256K）
-sample-rate 1           每 N 个包抓 1 个
-capture-filter ""       可选显示过滤器；其 L2–L4 子集会在 eBPF 中预过滤
-tls-keylog ""           NSS SSLKEYLOGFILE，用于 TLS 解密
-tls-keylog-auto true    自动发现进程的 SSLKEYLOGFILE / --tls-keylog
-mitm 127.0.0.1:18080   本地 HTTPS MITM 代理；留空关闭
-mitm-ca-dir DIR        MITM CA 证书/私钥目录
-wifi-psk ""             WPA2-PSK，解密 CCMP/GCMP 无线数据帧
-plugins ""              动态 Go .so 协议插件
```

## 协议支持

默认 **core** 构建包含链路/网络/传输层和常用协议（DNS、DHCP、HTTP/1.x、TLS 等）。使用 `-tags full` 构建完整协议集，包括 HTTP/2、QUIC、MQTT、Redis、PostgreSQL、BGP、SSH、RTP/RTSP、CoAP、Modbus、AMQP、BACnet、OPC UA 等。

完整支持程度、限制和 RFC 参考见 **[docs/PROTOCOLS.md](docs/PROTOCOLS.md)**。

## 已知限制

- 需要 Linux ≥ 6.6、BTF 和 root / `CAP_BPF` + `CAP_NET_ADMIN`。
- 显示过滤器采用混合过滤：L2–L4 安全子集在 eBPF 预过滤，应用层/复杂表达式仍在用户态执行；无法下推的过滤器不会减少内核复制。
- 协议覆盖和深度不及 Wireshark；长期存储/检索不及 Arkime。
- cgroup 抓包要求 cgroup v2；按 PID 实际是解析该 PID 当前 cgroup。
- 函数调用追踪是实验功能，只支持显式符号；已支持基础事件列表、build-id/容器检查和 cgroup 时间窗关联，尚无参数/返回值/USDT。
- 本地 IPC 负载追踪每个 iovec 段最多复制 4 KiB（最多 8 段），超出部分标记截断；环形缓冲满时会丢事件。
- Docker 部署会降低隔离；不要暴露 API 到公网，也不要加载不可信插件。

## 文档

| 文档 | 内容 |
| --- | --- |
| [INSTALL](docs/INSTALL.md) | systemd、自动更新、卸载 |
| [DOCKER](docs/DOCKER.md) | Docker/Compose、安全边界和排障 |
| [PROTOCOLS](docs/PROTOCOLS.md) | 协议支持矩阵、RFC、限制 |
| [FILTERS](docs/FILTERS.md) | 过滤语法、字段、构造器 |
| [API](docs/API.md) | HTTP API |
| [MCP](docs/MCP.md) | MCP 工具和客户端配置 |
| [PLUGINS](docs/PLUGINS.md) | 动态 Go 插件 |
| [COMPARISON](docs/COMPARISON.md) | 与 Wireshark / tcpdump 对比 |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | 目录、插件和构建架构 |
| [OPERATIONS](docs/OPERATIONS.md) | 性能、限制和 Roadmap |
| [RELEASE](docs/RELEASE.md) | GoReleaser 和发布 |

## License

MIT
