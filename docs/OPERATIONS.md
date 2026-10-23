# 性能、限制与 Roadmap

## 性能与资源

基准与 profiling 方法见 **[PERF.md](PERF.md)**。

- ringbuffer 默认 32 MiB；报文缓冲默认 100,000 条（`-max-packets`）；TCP 重组默认
  64 MiB 预算（`-stream-budget`）。按 snaplen 2048 B 估算，总内存约 150–250 MB。
- 每条报文在 Go 侧做一次协议解析，SSE 每 50 ms 批量推送（最多 512 条/批）。
- 前端列表使用虚拟滚动，最多保留 20,000 条；更早的报文仍可在后端导出。
- 订阅者消费过慢时会丢弃并计入 `dropped`，不会阻塞抓包线程。
- 协议层判断使用 `LayerMask` 位图，避免每个包反复扫描 `[]string`。
- 入包使用 `DecodeSummary`：只生成 Summary/Meta，不构建详情字段树；详情页按需 `Decode`。
- 有 keylog 时 TLS/QUIC 应用数据解密也延迟到详情页，列表路径不做无效解密。
- 详情字段树使用对象池，减少反复点击详情的 GC 压力。
- 十六进制预览改为查表输出，避免逐字节 `fmt.Fprintf`。
- 相同过滤表达式的多个 SSE 订阅者只计算一次过滤结果。
- flow 统计使用结构体 key，不再每包拼接 IP/端口字符串；flow 锁与 ring buffer 锁分离。
- 详情字段树有 256 条 / 32 MiB LRU 缓存，避免重复点击重复解码。
- SSE 批量 JSON 复用 buffer，减少 map/临时分配。
- TCP 重组改为 owned chunk 列表，避免大流反复扩容拷贝。
- X.509 证书按 DER SHA-256 缓存，重复证书不重复解析。
- TLS/HTTP2 per-flow 状态有上限；流量表/重组表超限时批量淘汰，避免每包 O(n) 扫描。

## 已知限制

- TCP 流重组只处理已捕获的字节：snaplen 截断、GSO/TSO 超级包、内核丢包都会表现为缺口；
  重组不做应用层协议解析（HTTP body 分块、gzip/br 解压等仍需后续处理）。
- 未提供 keylog 时不解密 TLS/QUIC 应用数据；只能看到握手/记录层字段。
- snaplen ≤ 2048 B；超出部分标记为 truncated（列表中的 ✂）。
- 过滤器在用户态执行，不具备内核级过滤的性能优势。
- TCX 需要内核 ≥ 6.6 且启用 BTF；旧内核暂不支持。
- 隧道网卡（wg/tun）上没有二层头，解析器会自动识别裸 IP。
- 无线 monitor 接口按 `ARPHRD_IEEE80211` / `ARPHRD_IEEE80211_RADIOTAP` 选择链路类型；VLAN 子接口会作为普通接口列出，可直接选择抓包。
- 动态插件依赖 Go plugin ABI：需 cgo、Linux/macOS/FreeBSD，且插件与主程序必须用同一 Go 工具链和依赖构建；仅加载可信 `.so`。
- 无线支持 WPA2-PSK 的 CCMP/GCMP 解密：需要 `-wifi-psk`、SSID Beacon/Probe Response、
  完整 4-way 握手。缺少握手或 WPA3 时可使用 `-wifi-keys` 直接导入 PMK/PTK：
  `{"sessions":[{"ap":"...","sta":"...","ssid":"...","pmk":"hex","ptk":"hex"}]}`。
  TKIP、SAE 密钥推导、802.11 分片重组仍未实现。
- cgroup 抓包要求 cgroup v2；按 PID 过滤实际是解析该 PID 当前 cgroup，不是逐 PID 精确匹配；转发/无 socket 流量无法归属 cgroup。
- 同时在 ingress/egress 抓同一个包会在 loopback 上看到重复记录（两个钩子各一次）。
- 只有单用户认证，没有角色/多用户权限；会话存于内存，服务重启后失效。
- 不内置 TLS；公网访问请使用 HTTPS 反向代理并启用 `-secure-cookie`。
- 登录限流按 TCP 源 IP 统计；在反向代理后请确保代理正确传递客户端地址，否则所有
  用户会共享同一个限流计数。

### 协议解析已知问题

- **MQTT**：v4/v5 的 Properties 主要依据报文内“非空属性长度 + 已知属性 ID”启发式识别，
  未按连接持久化协议版本；v5 空 Properties 不会自动识别，会作为载荷显示。
- **PostgreSQL**：`'D'`（DataRow/Describe）、`'E'`（ErrorResponse/Execute）、
  `'S'`（ParameterStatus/Sync）在前端与后端含义不同，当前按报文结构启发式区分；
  SASL 认证只展开消息类型，不解析 SASL 机制载荷。
- **BGP**：AS_PATH 的 2/4 字节 ASN 依据属性长度推断；未根据 Add-Path capability
  自动启用 Path ID；MP_REACH 只展开基础 next-hop/NLRI，未做完整 VPN/EVPN 解析。
- **SNMP v3**：只解析明文 Scoped PDU；加密 PDU 仅显示密文；USM 认证/加密参数
  只展示，不校验认证码，也不解密 privacy。
- **SIP**：一个 TCP 段按一条 SIP 消息解析，未做多消息边界/流水线重组；SDP 只展开
  常用字段，不解析完整 SDP 协商；multipart body 未展开。
- **SSH**：密钥交换后的包为加密载荷，只能显示长度与密文；`31/32/33/34` 在不同
  KEX 方法中含义重叠，按载荷结构启发式区分。
- **Redis**：RESP3 的 chunked string（`;`）与 attribute（`|`）只做有限展开；
  顶层 reply 与命令的区分依赖已知命令表。
- **DNS/DHCP**：DNS 未覆盖全部 RR 类型；DHCP 未实现全部 255 个 option。
- **TLS 解密**：需要启动时通过 `-tls-keylog` / `SSLKEYLOGFILE` 提供密钥；TLS 1.3
  支持 AES-128/256-GCM 与 ChaCha20-Poly1305，TLS 1.2 支持 AES-GCM、AES-CBC 与
  ChaCha20-Poly1305；CCM 套件暂不解密。
  若抓包从握手中间开始，缺少 ClientHello/ServerHello/序列号状态时只能显示密文。
- **TLS 证书**：只做 X.509 解析，不做证书链信任校验；证书消息必须完整捕获，
  snaplen 截断时只能显示部分 DER。
- **HTTP/2 HPACK**：动态表按 TCP 流保存在有上限的 flow store 中；HEADERS 与
  CONTINUATION 支持跨 TCP 段合并；从连接中间开始抓包时仍可能缺少动态表上下文。
- **QUIC**：Initial 使用 RFC 9001 v1/v2 固定盐解密；Handshake/1-RTT 需要 keylog 且
  必须先捕获 ClientHello。Short Header 默认按 8 字节 DCID 解析。HTTP/3 帧与 QPACK
  静态/动态表已支持；动态表依赖先捕获 Encoder stream，跨连接迁移或抓包不完整时
  动态索引可能显示为占位符。
- **SSH**：仍只解析明文消息；加密后的 KEX/用户认证/通道数据无法解密，未实现
  SSH 私钥导入。

## Roadmap

> 按当前实现更新：已完成项移到“已完成”，未完成项保留优先级，不承诺具体日期。

### 已完成

- [x] core/full 构建拆分 + 编译期协议插件注册
- [x] 运行时 Go `.so` 动态插件加载层
- [x] Dockerfile、Compose、Docker CI 和风险文档
- [x] HTTP/2 HPACK、QUIC Initial/keylog、HTTP/3 + QPACK 静态/动态表
- [x] TLS 1.2/1.3 keylog 解密、WPA2-PSK CCMP/GCMP、SSH 可选会话密钥
- [x] RTP H.264/H.265/VP8/VP9/AV1/AAC/Opus、RTSP、MPEG-TS、HLS
- [x] CoAP、MQTT-SN、Modbus TCP、AMQP、BACnet/IP、OPC UA、LoRaWAN
- [x] TLS 1.2 CCM、gRPC/protobuf、NetFlow v9/IPFIX 模板展开、DASH manifest、RTMP
- [x] pcapng 导出、按时间范围导出
- [x] 按进程 / cgroup / Pod 范围抓包
- [x] 显式函数 uprobe/uretprobe 调用耗时（CLI 实验）
- [x] 协议支持程度矩阵、RFC 参考、与 Wireshark/tcpdump 对比

### P0：协议覆盖

- [ ] 音视频补齐：完整 SDP 编解码映射
- [ ] 函数调用追踪 Web 时间线、参数/返回值、USDT/运行时符号
- [ ] 物联网补齐：CoAP over TCP/DTLS、MQTT-SN 完整 QoS、Modbus RTU
- [ ] LDAP/Kerberos
- [ ] SCTP 分片重组
- [ ] IPv4/IPv6 分片重组、802.11 分片重组
- [ ] WPA3/SAE、WPA-TKIP 无线解密

### P1：抓包与性能

- [ ] 内核态预过滤（把常用显示过滤器编译成 cBPF/eBPF）
- [ ] 抓包文件分片
- [ ] 高包速率下的 ring buffer/解码/SSE 压测与背压策略
- [ ] Prometheus metrics / OpenTelemetry 导出

### P2：界面与运维

- [ ] 报文着色规则、自定义列、列宽持久化
- [ ] 多用户 / 角色权限 / 审计日志
- [ ] 内置 TLS、OIDC / LDAP 登录
- [ ] 更完整的过滤器字段目录和协议内字段过滤
