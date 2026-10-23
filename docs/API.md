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
| POST | `/api/capture/start` | `{interfaces, snaplen, sampleRate, clear, cgroup}` |
| POST | `/api/capture/stop` | 停止抓包 |
| POST | `/api/capture/clear` | 清空缓冲区 |
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
