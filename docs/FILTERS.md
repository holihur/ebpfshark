# 过滤器

## 过滤器构造器

![filter builder](filter-builder.png)

- 入口：过滤器输入框右侧的 **过滤器构造器 / Filter builder** 按钮。
- 可选择一个可选的协议前缀（`tcp`、`http`、`dns` …），再添加多个字段条件。
- 每行支持字段、运算符、值，以及 `!` 取反；行与行之间可切换 **AND / OR**。
- 协议前缀 + OR 条件会自动加括号，例如：
  `tcp and (ip.addr == 10.0.0.1 or ip.addr == 10.0.0.2)`。
- 实时预览表达式，并调用 `/api/filter/validate` 做语法校验；无效时禁止应用。
- 字段目录由后端 `GET /api/filter/schema` 提供，包含类型、可用运算符、枚举值和输入建议。

## 混合过滤

过滤器采用两层执行：

1. **eBPF 预过滤**：只下推保守的 L2–L4 条件，例如 `tcp`、`udp`、`port 443`、IPv4 `host`/`net`（含 CIDR）、`vlan.id`。
2. **用户态精确匹配**：应用层字段、`contains`、OR/NOT 等继续由 Go AST 匹配。

只有 AND 组合中的安全条件会被下推。例如：

```text
tcp port 443                 -> proto=tcp, port=443 下推
tcp and (port 80 or 443)     -> 只下推 tcp
http.host contains example   -> 完全用户态
```

API：

```text
POST /api/capture/start   {filter}
POST /api/capture/filter  {filter}
```

下推过滤器不会改变显示结果；它只减少进入 ring buffer 的无关报文。IPv6 扩展头、IPv4 非首分片等无法安全判断的包会被保留并交给用户态。若过滤器无法安全下推，系统自动回退到纯用户态过滤。

## 显示过滤器

支持 `and` / `or` / `not`（也可写 `&&` / `||` / `!`）与括号；比较运算支持
`==` `!=` `<` `<=` `>` `>=`（或 `eq` `ne` `lt` `le` `gt` `ge`）以及字符串的 `contains`。

### 协议 / 快捷谓词

| 表达式 | 含义 |
| --- | --- |
| `tcp` `udp` `icmp` `icmpv6` `arp` `ip` `ipv6` | 按协议层匹配 |
| `dns` `http` `tls` `dhcp` `vlan` `eth` | 按应用层 / 链路层匹配 |
| `host 10.0.0.5` | 源或目的 IP |
| `src host 10.0.0.5` / `dst host 10.0.0.5` | 指定方向 |
| `net 10.0.0.0/8` / `net 10.0.0.0 8` | 网段（IPv4/IPv6） |
| `port 443` / `src port 53` / `dst port 53` | 端口 |
| `portrange 8000-8100` | 端口范围 |
| `tcp port 443` | 协议限定的端口（tcpdump 风格） |
| `len > 1000` | 等同 `frame.len > 1000` |

### 字段

| 字段 | 说明 |
| --- | --- |
| `frame.len` `frame.cap_len` `frame.number` `frame.protocols` | 帧长度、捕获长度、序号、协议链 |
| `eth.src` `eth.dst` `eth.type` `vlan.id` | 链路层 |
| `ip.src` `ip.dst` `ip.addr` `ip.proto` `ip.ttl` `ip.len` | IPv4 |
| `ipv6.src` `ipv6.dst` `ipv6.addr` `ipv6.hlim` | IPv6 |
| `tcp.srcport` `tcp.dstport` `tcp.port` `tcp.seq` `tcp.ack` `tcp.window` `tcp.len` | TCP |
| `tcp.flags.syn` `tcp.flags.ack` `tcp.flags.fin` `tcp.flags.rst` `tcp.flags.psh` | TCP 标志位 |
| `udp.srcport` `udp.dstport` `udp.port` `udp.length` | UDP |
| `icmp.type` `icmp.code` `icmpv6.type` | ICMP |
| `arp.opcode` `arp.src.proto_ipv4` `arp.dst.proto_ipv4` | ARP |
| `dns.qry.name` `dns.id` `dns.flags.response` | DNS |
| `http.request.method` `http.request.uri` `http.host` `http.response.code` | HTTP |
| `tls.handshake.type` `tls.handshake.extensions_server_name` | TLS / SNI |

### 示例

```text
tcp port 443 and not arp
http.request.method == "GET" and http.host contains example
dns.qry.name contains github
tls.handshake.extensions_server_name == api.example.com
ip.addr == 10.0.0.0/8 and tcp.flags.syn == 1
(icmp or arp) and frame.len > 64
frame contains "password"
tcp contains "GET /admin"
```

> 过滤器在用户态执行。被过滤掉的包仍然会从内核复制到用户态，因此不会降低抓包开销；
> 高流量场景请使用 snaplen / 采样率控制。
