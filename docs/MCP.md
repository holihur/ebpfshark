# ebpfshark MCP 使用说明

ebpfshark 内置 **Model Context Protocol (MCP) Server**，让 Claude Code、Claude Desktop、Cursor
以及其他 MCP 客户端可以直接：

- 查询网卡和抓包状态
- 启动 / 停止 / 清空抓包
- 按 Wireshark 风格过滤器查询报文
- 读取单条报文的协议树
- 对 TCP 会话做流重组（Follow Stream）
- 等待实时流量、查看会话和统计
- 启动/停止应用函数 uprobe 追踪，查询调用耗时

本文档覆盖启用方式、客户端配置、全部工具参数、示例和安全注意事项。

> 版本：ebpfshark 0.1.0-dev / MCP SDK v1.8.0 / 协议版本 `2025-06-18`

---

## 1. 传输方式与鉴权

| 传输 | 地址 / 命令 | 鉴权 |
| --- | --- | --- |
| Streamable HTTP | `POST http://<host>:9999/mcp` | `Authorization: Bearer <token>` |
| stdio | `ebpfshark mcp` | 进程权限（本地） |

- HTTP MCP 使用**无状态** Streamable HTTP（Stateless），不需要维护 `Mcp-Session-Id`。
- HTTP MCP 与 Web 登录会话相互独立：Web 端登录 Cookie 不能访问 `/mcp`，MCP 的 Bearer
  Token 也不能访问 Web API。
- HTTP `/mcp` 不受 `-no-auth` 影响，始终要求 Bearer Token。
- stdio 模式没有网络鉴权，安全性取决于启动进程的本地用户权限。

---

## 2. 启用 HTTP MCP

### 2.1 配置 Token

优先级：命令行 `-mcp-token` > 环境变量 `EBPFSHARK_MCP_TOKEN` > 启动时随机生成。

```bash
cd /root/ebpf

# 推荐：固定 Token（写入本地 env 文件，勿提交到仓库）
export EBPFSHARK_MCP_TOKEN='replace-with-a-long-random-token'

# 启动服务
sudo -E ./bin/ebpfshark -addr :9999
```

也可以直接传参：

```bash
sudo ./bin/ebpfshark -addr :9999 -mcp-token 'replace-with-a-long-random-token'
```

如果两者都为空，服务启动时会生成随机 Token 并打印到日志和 stderr：

```text
MCP HTTP endpoint enabled at /mcp
  Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxx
Set EBPFSHARK_MCP_TOKEN to use a stable token.
```

关闭 MCP：

```bash
sudo ./bin/ebpfshark -addr :9999 -no-mcp
```

### 2.2 验证端点

```bash
TOKEN='replace-with-a-long-random-token'

# 未带 Token：401
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:9999/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{}'

# 初始化：200，响应为 SSE（data: {...}）
curl -s -X POST http://127.0.0.1:9999/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {},
      "clientInfo": {"name": "curl", "version": "1"}
    }
  }'
```

---

## 3. 客户端配置

### 3.1 HTTP（推荐）

通用 JSON 配置（不同客户端字段名可能略有差异）：

```json
{
  "mcpServers": {
    "ebpfshark": {
      "type": "http",
      "url": "http://127.0.0.1:9999/mcp",
      "headers": {
        "Authorization": "Bearer replace-with-a-long-random-token"
      }
    }
  }
}
```

Claude Code CLI 示例：

```bash
claude mcp add --transport http ebpfshark http://127.0.0.1:9999/mcp \
  --header "Authorization: Bearer replace-with-a-long-random-token"
```

如果服务不在本机，把 `127.0.0.1` 换成实际地址，并确保网络可达；公网部署务必使用
HTTPS 反向代理（见第 7 节）。

### 3.2 stdio（本地客户端）

```bash
sudo ./bin/ebpfshark mcp
```

- stdout 只输出 newline-delimited JSON-RPC，**日志全部写入 stderr**。
- 需要抓包时进程必须具备 root 或 `CAP_BPF` / `CAP_NET_ADMIN`；否则 `start_capture`
  会返回权限错误。
- 支持参数：

```text
-max-packets 100000    内存中保留的报文数
-stream-budget 64      TCP 重组内存预算（MiB）
-log-level warn        debug / info / warn / error
-exclude-port 0        要排除的 TCP/UDP 端口（0 = 不排除）
```

Claude Desktop 配置示例：

```json
{
  "mcpServers": {
    "ebpfshark": {
      "command": "sudo",
      "args": ["-n", "/root/ebpf/bin/ebpfshark", "mcp"]
    }
  }
}
```

`sudo -n` 要求配置免密 sudo。最小化 sudoers 示例：

```sudoers
# /etc/sudoers.d/ebpfshark
youruser ALL=(root) NOPASSWD: /root/ebpf/bin/ebpfshark mcp
```

> 直接以 root 运行 MCP 客户端也能工作，但不推荐。建议为 MCP 创建专用用户并仅授予
> 该命令的 sudo 权限。

---

## 4. 工具参考

所有工具参数通过 `tools/call` 的 `params.arguments` 传入；返回内容为文本形式的 JSON
（`content[0].text`）。

### 4.1 状态与网卡

#### `get_status`

获取服务版本、抓包状态、缓冲区统计、流重组统计和网卡列表。

```json
{"name": "get_status", "arguments": {}}
```

主要返回字段：

```json
{
  "version": "0.1.0-dev",
  "capture": {
    "running": true,
    "interfaces": ["eth0"],
    "snaplen": 2048,
    "kernelPackets": 1234,
    "kernelFiltered": 12,
    "excludePort": 9999
  },
  "store": {
    "stored": 1234,
    "capacity": 100000,
    "protocols": {"TCP": 900, "DNS": 20},
    "streams": {"flows": 8, "bytes": 524288, "evicted": 0, "budgetBytes": 67108864}
  },
  "interfaces": [ ... ],
  "serverTime": 1790000000000000000
}
```

#### `list_interfaces`

```json
{"name": "list_interfaces", "arguments": {}}
```

返回网卡名称、索引、地址、MTU、Up 状态、是否默认路由、类型等。

### 4.2 抓包控制

#### `start_capture`

启动新的抓包会话；会先停止当前会话。

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `interfaces` | string[] | 必填 | 网卡名，例如 `["eth0", "lo"]` |
| `snaplen` | number | 2048 | 每包捕获字节数，最大 2048 |
| `sampleRate` | number | 1 | 每 N 个包抓 1 个 |
| `ringSize` | number | 32 MiB | eBPF ringbuffer 字节数 |
| `cgroup` | string | 空 | 只抓指定 cgroup：ID、路径、`pid:N`、`pod:NAME`、`container:ID` |
| `filter` | string | 空 | 可选显示过滤器；其安全 L2–L4 子集在 eBPF 预过滤 |
| `clear` | boolean | false | 启动前清空报文缓冲 |

```json
{
  "name": "start_capture",
  "arguments": {
    "interfaces": ["eth0", "lo"],
    "snaplen": 2048,
    "clear": true
  }
}
```

> HTTP MCP 启动抓包时会自动排除服务自身的 API 端口，避免 UI 轮询/SSE 混入结果。

#### `stop_capture`

停止抓包，已缓冲的数据保留。

```json
{"name": "stop_capture", "arguments": {}}
```

#### `clear_capture`

清空报文、统计、会话和重组流；抓包继续运行。

```json
{"name": "clear_capture", "arguments": {}}
```

### 4.3 数据查询

#### `query_packets`

返回**最近** N 条匹配的报文，按时间从旧到新排列。

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `filter` | string | 空 | Wireshark 风格显示过滤器 |
| `limit` | number | 100 | 最大 1000 |

```json
{
  "name": "query_packets",
  "arguments": {
    "filter": "tcp port 443 and not arp",
    "limit": 20
  }
}
```

返回：

```json
{
  "count": 2,
  "stored": 1234,
  "packets": [
    {
      "id": 1201,
      "time": 1790000000123456789,
      "iface": "eth0",
      "direction": "egress",
      "len": 1514,
      "capLen": 1514,
      "protocol": "TLS",
      "layers": ["eth", "ip", "tcp", "tls"],
      "src": "10.0.0.5:54321",
      "dst": "93.184.216.34:443",
      "srcPort": 54321,
      "dstPort": 443,
      "info": "Application Data (1400 bytes)"
    }
  ]
}
```

常用过滤器：

```text
tcp / udp / icmp / arp / dns / http / tls
tcp port 443
ip.addr == 10.0.0.5
http.request.method == "GET"
dns.qry.name contains example
tls.handshake.extensions_server_name contains github
frame contains "password"
```

完整语法见项目 `README.md` 的“显示过滤器”章节。

#### `get_packet`

返回单条报文的完整协议树。

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `id` | number | 必填 | `query_packets` 返回的报文编号 |
| `includeRaw` | boolean | false | 是否附带原始帧 base64 |

```json
{"name": "get_packet", "arguments": {"id": 1201, "includeRaw": false}}
```

### 4.4 TCP 流重组

#### `follow_stream`

对报文所属 TCP 会话做双向重组。报文只需属于该会话，不要求一定是首个数据包。

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `packetId` | number | 必填 | 会话内任意 TCP 报文编号 |
| `maxBytes` | number | 65536 | 每个方向返回的最大字节数，上限 1 MiB |
| `includeBase64` | boolean | false | 是否附带原始字节 base64 |

```json
{
  "name": "follow_stream",
  "arguments": {
    "packetId": 1201,
    "maxBytes": 8192,
    "includeBase64": false
  }
}
```

返回：

```json
{
  "key": "tcp|10.0.0.5|54321|93.184.216.34|443",
  "a": {"ip": "10.0.0.5", "port": 54321},
  "b": {"ip": "93.184.216.34", "port": 443},
  "aToB": {
    "from": {"ip": "10.0.0.5", "port": 54321},
    "to": {"ip": "93.184.216.34", "port": 443},
    "capturedBytes": 182,
    "returnedBytes": 182,
    "truncated": false,
    "gaps": 0,
    "text": "GET / HTTP/1.1\r\nHost: example.com\r\n..."
  },
  "bToA": {
    "capturedBytes": 1256,
    "returnedBytes": 1256,
    "truncated": false,
    "gaps": 0,
    "text": "HTTP/1.1 200 OK\r\n..."
  }
}
```

文本中的不可打印字节会显示为 `.`。二进制协议建议请求 `includeBase64: true`。

### 4.5 会话与统计

#### `list_conversations`

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `limit` | number | 100 | 最大 1000 |

返回按字节数降序的双向会话，包含字节数、包数、TCP 状态和方向统计。

#### `get_stats`

```json
{"name": "get_stats", "arguments": {}}
```

返回缓冲计数、协议分布、60 秒速率和流重组内存统计。

### 4.6 过滤器与实时等待

#### `validate_filter`

```json
{"name": "validate_filter", "arguments": {"filter": "tcp.flags.syn == 1"}}
```

无效时返回：

```json
{"valid": false, "error": "unknown field \"tcp.flagz.syn\""}
```

#### `wait_for_packets`

等待实时报文，适合“启动抓包后观察一段时间”的场景。

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `filter` | string | 空 | 匹配所有 |
| `limit` | number | 50 | 最大 1000 |
| `timeoutSeconds` | number | 5 | 最大 60 |

```json
{
  "name": "wait_for_packets",
  "arguments": {
    "filter": "dns",
    "limit": 20,
    "timeoutSeconds": 10
  }
}
```

返回：

```json
{
  "timedOut": false,
  "count": 3,
  "packets": [ ... ]
}
```

到达数量上限或超时后返回；`timedOut=true` 表示是超时返回。

---

#### `inspect_function_target`

检查目标 ELF 的 build-id、是否 stripped、符号数量和 debuginfo，再决定如何启动追踪。

```json
{"name":"inspect_function_target","arguments":{"pid":1234}}
```

#### `start_function_trace`

启动实验性 uprobe/uretprobe 函数追踪。需要 root/CAP_BPF/CAP_PERFMON，并且目标 ELF 有可用符号。

```json
{"name":"start_function_trace","arguments":{
  "pid": 1234,
  "functions": "/usr/local/bin/app:main.handler,/usr/local/bin/app:main.dbQuery"
}}
```

#### `stop_function_trace`

```json
{"name":"stop_function_trace","arguments":{}}
```

#### `query_function_trace`

```json
{"name":"query_function_trace","arguments":{"limit":200,"after":0}}
```

返回 `status` 和已完成的函数调用事件：`time`、`durationNs`、`pid`、`tid`、`function`、`comm`。

> 当前只支持显式符号，不做任意函数全量采集，也不解析参数/返回值。函数追踪和网络抓包是独立会话。

## 5. 典型工作流

### 5.1 抓取并分析 HTTP 请求

```text
1. get_status                         # 确认服务运行、选择网卡
2. start_capture {"interfaces":["eth0"],"snaplen":2048,"clear":true}
3. wait_for_packets {"filter":"http","limit":10,"timeoutSeconds":15}
4. query_packets {"filter":"http.request.method == \"GET\"","limit":5}
5. follow_stream {"packetId":<id>, "maxBytes":65536}
6. stop_capture
```

### 5.2 排查 DNS / TLS 问题

```text
1. start_capture {"interfaces":["eth0"],"snaplen":2048}
2. wait_for_packets {"filter":"dns","limit":50,"timeoutSeconds":20}
3. query_packets {"filter":"dns.flags.response == 1 and dns.qry.name contains example"}
4. query_packets {"filter":"tls.handshake.type == 1","limit":20}
5. get_packet {"id":<id>}
```

### 5.3 分析 TCP 异常

```text
1. list_conversations {"limit":50}
2. query_packets {"filter":"tcp.flags.rst == 1","limit":20}
3. query_packets {"filter":"tcp.port == 443","limit":50}
4. follow_stream {"packetId":<id>}
5. get_stats
```

---

## 6. 协议请求示例

### 6.1 列出工具

```bash
curl -s -X POST http://127.0.0.1:9999/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

### 6.2 调用工具

```bash
curl -s -X POST http://127.0.0.1:9999/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "query_packets",
      "arguments": {"filter": "dns", "limit": 5}
    }
  }'
```

无状态 HTTP 模式下每个 POST 都是独立请求；响应可能是 `application/json`，也可能是
`text/event-stream`，按 SSE 格式取 `data:` 后面的 JSON 即可。

---

## 7. 安全建议

1. **Token 等同管理员权限**：可启动/停止抓包、读取全部报文内容。不要写进代码仓库、
   截图或公开日志。
2. 生产环境使用 HTTPS 反向代理（Nginx / Caddy）并在代理层追加鉴权/访问控制。
   服务本身不终止 TLS。
3. 默认监听 `:9999` 时对网络可达用户开放登录页；建议绑定 `127.0.0.1` 或通过防火墙
   限制来源。
4. MCP Token 与 Web 登录密码应分别设置、分别轮换；修改 `.env.local` 后重启服务生效。
5. stdio 模式建议使用专用用户 + 精确 sudoers 规则，避免整个客户端以 root 运行。
6. 抓包数据可能包含明文凭据、Cookie、Token，转发给 AI Agent 前请确认合规要求。

---

## 8. 故障排查

| 现象 | 排查 |
| --- | --- |
| `/mcp` 返回 401 | 检查 `Authorization: Bearer` 是否与 `EBPFSHARK_MCP_TOKEN` 一致 |
| `/mcp` 返回 404 | 启动参数是否带了 `-no-mcp` |
| `start_capture` 返回 permission denied | 进程需要 root 或 `CAP_BPF` + `CAP_NET_ADMIN` |
| `start_capture` 返回 kernel 6.6+ 错误 | 内核过旧或未启用 BTF / TCX |
| `query_packets` 为空 | 是否启动了抓包；过滤器是否写错；试 `validate_filter` |
| `follow_stream` 返回 no stream | 报文无 payload、snaplen 太小、流已被淘汰或不是 TCP |
| Follow Stream 有 gaps | snaplen 截断、GSO/TSO 超级包、内核丢包；尝试抓 ingress 或关闭 GRO/TSO |
| 客户端连不上 HTTP MCP | 确认使用 Streamable HTTP（不是旧 SSE 端点），地址是 `/mcp`，代理未缓冲 POST |
| stdio 无响应 | 检查 stdout 是否被其他日志污染；`ebpfshark mcp` 只应输出 JSON-RPC |

查看服务日志：

```bash
tail -f /tmp/ebpfshark-9999.log
# 或 systemd
journalctl -u ebpfshark -f
```

---

## 9. 当前限制

- MCP 工具不提供 pcap 导入/导出；需要文件操作时使用 Web UI 或 REST API
  （`/api/export/pcap`、`/api/import`）。
- 仅支持单 Bearer Token，没有按工具/按用户的细粒度权限。
- HTTP MCP 为无状态模式，不提供服务端主动推送的实时事件流；实时数据请使用
  `wait_for_packets` 轮询。
- `query_packets` 只查询当前内存缓冲（`-max-packets`），不读取历史 pcap 文件。
- 流重组受 snaplen 和 `-stream-budget` 限制，不保证 100% 完整。

---

## 10. 相关文档

- 项目主文档：[../README.md](../README.md)
- 显示过滤器语法：README.md 的“显示过滤器”章节
- 认证与 Web 登录：README.md 的“登录认证”章节
- MCP 规范：<https://modelcontextprotocol.io/>
