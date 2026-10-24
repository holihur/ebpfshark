# HTTP API

除登录相关接口外，以下 API 均**需要登录会话**。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/auth/session` | 当前会话状态（公开） |
| POST | `/api/auth/login` | 登录，设置会话 Cookie（公开） |
| POST | `/api/auth/logout` | 退出登录 |
| GET | `/api/health` | 健康检查（公开） |
| GET | `/api/status` | 抓包状态、统计、网卡列表 |
| GET | `/api/interfaces` | 网卡列表 |
| POST | `/api/capture/start` | `{interfaces, snaplen, sampleRate, clear, cgroup, filter}` |
| POST | `/api/capture/stop` | 停止抓包 |
| POST | `/api/capture/clear` | 清空缓冲区 |
| POST | `/api/capture/filter` | `{filter}` 更新 eBPF 预过滤（安全 L2–L4 子集） |
| POST | `/api/capture/cgroup` | `{cgroup}` 运行中动态更新 cgroup 过滤（空字符串清除） |
| GET | `/api/processes?q=&limit=` | 进程列表及 cgroup ID/路径，用于按进程过滤 |
| GET | `/api/decrypt` | TLS keylog / Wi-Fi PSK 配置状态（不返回密钥） |
| GET | `/api/mitm` | 本地 HTTPS MITM 代理状态 |
| POST | `/api/mitm` | `{enabled, addr}` 启停/重启 MITM 代理 |
| GET | `/api/mitm/ca` | 下载本地 MITM CA 证书 |
| POST | `/api/decrypt/tls-keylog` | `{keylog}` 加载 SSLKEYLOGFILE 内容；空字符串清除 |
| POST | `/api/decrypt/tls-keylog-auto` | `{enabled}` 开启/关闭自动发现进程 keylog |
| POST | `/api/decrypt/wifi-psk` | `{psk}` 加载/清除 WPA2-PSK |
| GET | `/api/ipc`、`/api/ipc/status` | 本地 IPC 负载追踪状态与计数器 |
| GET | `/api/ipc/sockets?q=&type=&pid=` | `/proc/net/unix` 套接字、属主与 cgroup |
| POST | `/api/ipc/start` | `{pid, cgroup, cgroupID, maxPayload, ringSize}` 启动 AF_UNIX 负载追踪 |
| POST | `/api/ipc/stop` | 停止本地 IPC 负载追踪 |
| POST | `/api/ipc/clear` | 清空已保留的 IPC 事件和流 |
| GET | `/api/ipc/events?limit=&after=&inode=&pid=&direction=&q=` | 最近 IPC 负载事件（payload 为 base64） |
| GET | `/api/ipc/stream?after=&inode=&pid=&direction=&q=` | SSE：`ready` / `ipc` 事件（IPC 负载批量推送） |
| GET | `/api/ipc/export?format=jsonl&after=&inode=&pid=&direction=&q=` | 导出 IPC 事件为 JSONL/JSON（不导出 pcap） |
| GET | `/api/ipc/streams?limit=&inode=&pid=&type=&q=` | 按 inode 聚合的双向 IPC 流 |
| GET | `/api/packets?filter=&limit=` | 最近 N 条匹配报文 |
| GET | `/api/packets/{id}` | 协议树 + base64 原始字节 |
| GET | `/api/packets/{id}/stream` | 该 TCP 报文所属会话的双向重组负载 |
| GET | `/api/stream?filter=` | SSE：`packets` / `ready` 事件 |
| GET | `/api/stats` | 计数器、协议分布、60 秒速率 |
| GET | `/api/conversations?limit=` | 双向会话 |
| POST | `/api/filter/validate` | `{filter}` → `{valid, error}` |
| GET | `/api/filter/fields` | 可过滤字段（用于补全） |
| GET | `/api/filter/schema` | 过滤器构造器字段目录（类型/运算符/枚举值） |
| GET | `/api/update` | 自动更新状态 |
| GET | `/api/trace?limit=&after=` | 函数调用追踪状态和事件 |
| GET | `/api/trace/inspect?pid=&binary=` | 检查 build-id、符号、debuginfo 和建议 |
| GET | `/api/trace/symbols?pid=&binary=&q=&limit=` | 列出可挂 uprobe 的函数符号 |
| GET | `/api/trace/context?cgroup=&at=&window=` | 查找同 cgroup、同一时间窗口内的网络包 |
| POST | `/api/trace/start` | `{pid, functions}` 启动 uprobe 追踪 |
| POST | `/api/trace/stop` | 停止函数调用追踪 |
| GET | `/api/export/pcap?filter=&format=&from=&to=` | 导出 pcap/pcapng；`format=pcapng`，时间支持 RFC3339 或 Unix 秒 |
| POST | `/api/import` | multipart `file` 导入 pcap/pcapng |

示例：

```bash
# 先登录拿到 Cookie（见上一节），然后：
curl -s -b /tmp/ebpfshark.cookie localhost:9999/api/status | jq
curl -s -b /tmp/ebpfshark.cookie -X POST localhost:9999/api/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"interfaces":["eth0"],"snaplen":2048,"clear":true}'
curl -s -b /tmp/ebpfshark.cookie \
  'localhost:9999/api/packets?filter=tcp%20port%20443&limit=5' | jq
curl -sN -b /tmp/ebpfshark.cookie 'localhost:9999/api/stream?filter=http' | head
curl -s -b /tmp/ebpfshark.cookie \
  'localhost:9999/api/export/pcap?filter=dns' -o dns.pcap

# pcapng + 最近 10 分钟
curl -s -b /tmp/ebpfshark.cookie \
  "localhost:9999/api/export/pcap?format=pcapng&from=$(date -d '10 minutes ago' +%s)" \
  -o recent.pcapng
```
