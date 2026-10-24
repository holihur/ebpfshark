# 协议支持

> 默认 **core** 构建只包含常用协议（DNS、DHCP、HTTP/1.x、TLS、IGMP/MPLS/GRE 及链路/网络/传输层）。完整协议集使用 `-tags full` 或 `make go-build-full`。

## 支持程度定义

| 标记 | 含义 |
| --- | --- |
| **完整** | 主要消息类型、头部和常用字段均已解析；未发现影响使用的明显缺口。 |
| **常用** | 常用消息/字段完整，部分少见扩展、边界情况或状态化关联仍有限制。 |
| **基础** | 只解析头部、消息类型或关键字段；深层载荷/完整状态机尚未实现。 |
| **需密钥** | 明文元数据可解析，加密载荷必须提供 keylog、会话密钥或 PMK/PTK。 |
| **不支持** | 当前没有对应 dissector，不会出现在协议层列表和协议过滤器中。 |

## 协议支持矩阵

> `core` 为默认构建即包含；`full` 需要 `-tags full` / `make go-build-full`。RFC/标准列是主要参考，**不代表完整 conformance**；实际支持范围以“程度”和限制列所示为准。

| 层次 | 协议 | 构建 | 程度 | 已解析内容 / 主要限制 | 标准 / RFC |
| --- | --- | --- | --- | --- | --- |
| 链路层 | Ethernet II | core | **完整** | MAC、EtherType | IEEE 802.3 |
| 链路层 | 802.1Q / QinQ VLAN | core | **完整** | 最多 4 层 VLAN 标签 | IEEE 802.1Q / 802.1ad |
| 链路层 | ARP / RARP | core | **完整** | 请求/响应、发送方/目标地址 | RFC 826 / RFC 903 |
| 链路层 | MPLS | core | **常用** | 标签栈、TTL，递归解析内层 IPv4/IPv6；不做 pseudowire 完整展开 | RFC 3032 |
| 链路层 | Radiotap / IEEE 802.11 | core | **常用** | 标准 Radiotap 字段、管理/控制/数据帧、常用 IE、RSN/WPA、EAPOL；WPA2-PSK CCMP/GCMP 可解密；WPA3/TKIP、分片重组未实现 | Radiotap spec / IEEE 802.11 / 802.11i / 802.1X |
| 链路层 | Linux SLL / SLL2 | core | **完整** | pcap/pcapng 导入的 cooked capture | libpcap LINKTYPE_LINUX_SLL/SLL2 |
| 链路层 | Raw IP | core | **完整** | wg/tun 等无二层头接口自动识别 | libpcap LINKTYPE_RAW |
| 网络层 | IPv4 | core | **常用** | 选项、分片标志、TTL、校验和；不做 IPv4 分片重组 | RFC 791 |
| 网络层 | IPv6 | core | **常用** | 常见扩展头、Hop Limit；不做 IPv6 分片重组 | RFC 8200 |
| 网络层 | ICMP / ICMPv6 | core | **常用** | Echo、不可达、超时等常用类型；未覆盖全部 ICMPv6 类型 | RFC 792 / RFC 4443 |
| 网络层 | IGMP | core | **完整** | v1/v2/v3，Query/Report/Leave，完整源列表 | RFC 1112 / 2236 / 3376 |
| 网络层 | GRE | core | **常用** | Checksum/Key/Sequence，递归解析 IPv4/IPv6/ARP/以太网 | RFC 2784 / 2890 |
| 网络层 | IP-in-IP | core | **完整** | IPv4/IPv6 隧道递归解析 | RFC 2003 / 2473 |
| 隧道 | VXLAN | full | **完整** | VNI + 内层以太网完整解析 | RFC 7348 |
| 传输层 | TCP | core | **完整** | 端口、序列号、标志位、窗口、常用选项、校验和；流重组受捕获完整性限制 | RFC 9293 |
| 传输层 | UDP | core | **完整** | 端口、长度、校验和 | RFC 768 |
| 传输层 | SCTP | core | **基础** | 端口、Verification Tag、DATA/INIT/SACK/HEARTBEAT 等 chunk；不做分片重组 | RFC 9260 |
| 传输层 | TLS | core | **常用 / 需密钥** | 记录层、ClientHello/ServerHello、SNI/ALPN、X.509、Alert；keylog 解密 TLS 1.3 AES-GCM、TLS 1.2 AES-GCM/CBC/ChaCha20/CCM | RFC 5246 / 8446；NSS key log |
| 传输层 | QUIC | full | **常用 / 需密钥** | Long/Short Header、Initial 解密、帧、CRYPTO/TLS SNI、HTTP/3 帧、QPACK 静态/动态表；Handshake/1-RTT 需 keylog | RFC 9000 / 9001 / 9369；HTTP/3 RFC 9114；QPACK RFC 9204 |
| 应用层 | DNS | core | **常用** | A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV/CAA/NAPTR/TLSA/SVCB/HTTPS；EDNS0/DNSSEC 标志；mDNS/LLMNR；未覆盖全部 RR 类型 | RFC 1035 等；EDNS0 RFC 6891；DNSSEC RFC 4034；SVCB/HTTPS RFC 9460 |
| 应用层 | HTTP/1.x | core | **常用** | 请求行/状态行、Header、Body 预览；不做 chunked/gzip 解压或跨段 HTTP 消息重组 | RFC 9112 |
| 应用层 | HLS manifest | core | **基础** | `#EXTM3U`、VERSION/TARGETDURATION/MEDIA-SEQUENCE/EXTINF/STREAM-INF、Segment 列表；不解析媒体分片 | RFC 8216 |
| 应用层 | DASH manifest | core | **基础** | MPD 属性、Period/AdaptationSet/Representation 常用字段、BaseURL；不解析媒体分片 | ISO/IEC 23009-1 |
| 应用层 | Anthropic / OpenAI / Responses API | core | **常用** | HTTP/1.1 与 HTTP/2 请求/响应、跨 TCP 段 body、chunked、gzip/deflate/zlib/brotli、SSE、公开字段 + 通用 JSON 树；过滤器层：`ai`、`anthropic`、`openai`（Chat Completions）、`openai-responses`；不做 token 计费、完整 schema 校验 | Anthropic Messages API / OpenAI Chat Completions / Responses API |
| 应用层 | gRPC / protobuf | full | **基础** | gRPC length-prefixed message、压缩标记、protobuf wire 字段（varint/fixed/bytes/nested）；不依赖 `.proto` schema | gRPC HTTP/2 spec / protobuf encoding |
| 应用层 | HTTP/2 | full | **常用** | 帧、HPACK 静态/动态表/Huffman、HEADERS+CONTINUATION、DATA 预览；从连接中间抓包时动态表可能缺失 | RFC 9113；HPACK RFC 7541 |
| 应用层 | DHCP | core | **常用** | 完整 DHCPv4 消息类型、常用 option、Option Overload、Relay Agent、Classless Routes；未实现全部 255 个 option | RFC 2131 / 2132 |
| 应用层 | NTP | full | **完整** | 版本、模式、Stratum、时间戳、扩展字段/MAC | RFC 5905 |
| 应用层 | SNMP v1/v2c/v3 | full | **常用** | 全部 PDU、v1 Trap、v2c Bulk、v3 USM 头/Scoped PDU、BER/OID；v3 加密 PDU 不解密、不校验认证码 | RFC 1157 / 3412 / 3414 / 3416 |
| 应用层 | Syslog | full | **完整** | RFC5424 与 BSD 格式，facility/severity | RFC 5424 / 3164 |
| 应用层 | STUN | full | **常用** | Binding/Allocate 等方法、ERROR-CODE、XOR-PEER/RELAYED、ICE、Integrity；未覆盖全部属性 | RFC 8489 |
| 应用层 | MySQL | full | **基础** | Handshake、OK/ERR、COM_QUERY/INIT_DB/STMT_PREPARE/EXECUTE；未覆盖全部命令/认证插件 | MySQL Client/Server Protocol（无 RFC） |
| 应用层 | RADIUS | full | **基础** | Access/Accounting 报文、常用属性、EAP/Message-Authenticator | RFC 2865 / 2866 |
| 应用层 | NetFlow / IPFIX | full | **常用** | v5 流记录、v9/IPFIX Template/Data Set 展开、常用字段值、模板缓存 | NetFlow v5（Cisco）；v9 RFC 3954；IPFIX RFC 7011 |
| 应用层 | RTP / RTCP | full | **常用** | RTP 头、CSRC/扩展、RTCP SR/RR/SDES/BYE/APP；H.264/H.265/VP8/VP9/AV1/AAC/Opus 载荷按启发式解析；完整 SDP 编解码映射未实现 | RFC 3550；H.264 RFC 6184；H.265 RFC 7798；VP8 RFC 7741；AAC RFC 3640；Opus RFC 7587 |
| 应用层 | RTSP | full | **常用** | OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN、Header、CSeq/Session、SDP body；不做 RTSP 消息分片重组 | RFC 2326 / RFC 7826 |
| 应用层 | RTMP | full | **基础** | Handshake、Chunk Header、常用消息类型、AMF0 首个字符串；不做完整 AMF 对象模型 | Adobe RTMP Specification 1.0 |
| 封装 | MPEG-TS | full | **基础** | 188 字节 TS、PID/PUSI/CC、PAT/PMT、PES/PTS/DTS、PCR；不解析完整 ES 和加密 TS | ISO/IEC 13818-1 |
| 应用层 | CoAP | full | **常用** | CON/NON/ACK/RST、GET/POST/PUT/DELETE、Token、Option/Uri-Path/Observe/Block、Payload；DTLS 未解密 | RFC 7252 |
| 应用层 | MQTT-SN | full | **基础** | ADVERTISE/CONNECT/PUBLISH/SUBSCRIBE/PING/DISCONNECT 等消息类型、Flags/Topic ID/Message ID；QoS 状态机未实现 | OASIS MQTT-SN 1.2 |
| 应用层 | Modbus TCP | full | **基础** | MBAP、功能码 1/2/3/4/5/6/15/16/23/43、常用请求/响应字段、异常码；不做串行 RTU 和时间序列 | Modbus Application Protocol V1.1b3 / Modbus TCP Implementation Guide |
| 应用层 | AMQP 0-9-1 | full | **基础** | Protocol Header、Frame、Method、Content Header/Body、Heartbeat；常用 connection/channel/queue/basic 方法 | AMQP 0-9-1 Specification |
| 应用层 | BACnet/IP | full | **基础** | BVLC、NPDU、APDU 类型、Confirmed/Unconfirmed Request、常用服务码 | ASHRAE 135 |
| 应用层 | OPC UA Binary | full | **基础** | HEL/ACK/ERR/OPN/MSG/CLO、Message Size、Buffer/Chunk、Secure Channel 基础字段 | IEC 62541 |
| 应用层 | LoRaWAN Packet Forwarder | full | **基础** | PUSH/PULL/TX_ACK、Gateway EUI、rxpk/stat JSON 字段；不解析加密 LoRaWAN MAC 载荷 | LoRaWAN 1.0.x / Packet Forwarder Protocol |
| 应用层 | WebSocket | full | **基础** | Text/Binary/Ping/Pong/Close 帧、掩码、长度；不做分片消息重组 | RFC 6455 |
| 应用层 | MQTT | full | **常用** | 14 种报文、CONNECT/Will/用户名密码、QoS、SUBSCRIBE 选项、v5 Properties；v5 属性仍为启发式识别 | MQTT 3.1.1 / 5.0（OASIS） |
| 应用层 | Redis | full | **常用** | RESP2/RESP3 数组、Map、Set、Push、Double、Bool、BigNum、Verbatim、Blob Error；内联命令；chunked string/attribute 仅有限展开 | RESP2 / RESP3（Redis 规范） |
| 应用层 | PostgreSQL | full | **常用** | Startup/SSL/Cancel、Auth、Query/Parse/Bind、RowDescription/DataRow、Error/Notice、Notify、Copy；SASL 机制载荷未展开 | PostgreSQL Frontend/Backend Protocol |
| 应用层 | BGP-4 | full | **常用** | OPEN capabilities、UPDATE withdrawn/Path Attributes/NLRI、MP_REACH/UNREACH、Notification/Route-Refresh；Add-Path/EVPN 未完整支持 | RFC 4271 / 4760 / 6793 / 7911 / 2918 |
| 应用层 | SSH | full | **基础 / 需密钥** | 版本标识、KEXINIT、KEX、用户认证、Global/Channel 明文消息；加密内容需 `-ssh-keys`（仅 AES-CTR 会话密钥），不支持私钥导入 | RFC 4250–4254（部分扩展） |
| 应用层 | SSDP | full | **常用** | M-SEARCH/NOTIFY/响应与常用 Header | UPnP Device Architecture |
| 应用层 | SIP | full | **常用** | 请求/响应、Header、Compact Header、Call-ID/CSeq/From/To、SDP 媒体与属性；一个 TCP 段按一条 SIP 消息解析 | RFC 3261；SDP RFC 4566 |
| 应用层 | WireGuard | full | **基础 / 需密钥** | 握手 Initiation/Response/Cookie 字段、Transport 头部；载荷加密，不解密 | WireGuard Protocol（wireguard.com/protocol） |
| 应用层 | EAPOL | core | **完整** | EAPOL-Key 4-way handshake 字段、RSN/WPA IE；不替代完整 WPA 解密配置 | IEEE 802.1X；RSN IEEE 802.11i |

## 明确未支持

以下协议/能力当前没有完整 dissector，不会出现在协议层列表、协议过滤器或过滤器构造器中。参考标准一并列出，便于后续实现时对齐：

| 类别 | 协议 / 能力 | 参考标准 |
| --- | --- | --- |
| 物联网 | CoAP over TCP / DTLS | RFC 8323 / DTLS RFC 6347 |
| 物联网 | MQTT-SN 完整 QoS | OASIS MQTT-SN 1.2 |
| 物联网 | Modbus RTU | Modbus over Serial Line Specification |
| 安全 | WPA3/SAE、WPA-TKIP | IEEE 802.11i / WPA3 Specification |
| 安全 | 802.11 分片重组 | IEEE 802.11 |
| 安全 / 其他 | LDAP / Kerberos | RFC 4511 / RFC 4120 |
| 传输 | SCTP 分片重组 | RFC 9260 |
| 网络 | IPv4/IPv6 分片重组 | RFC 791 / RFC 8200 |

> 这些条目是当前发布版的真实边界；不要按“已支持”理解。新增协议时应同时更新本矩阵、过滤器 schema 和测试。


**过滤器**：新增协议同样支持协议谓词，例如 `mqtt`、`mqttsn`、`redis`、`vxlan`、`bgp`、
`ssh`、`quic`、`http2`、`postgresql`、`mysql`、`radius`、`netflow`、`rtp`、`rtcp`、`coap`、`modbus`、
`rtsp`、`mpegts`、`hls`、`h264`、`h265`、`vp8`、`vp9`、`av1`、`aac`、`opus`、`dash`、`amqp`、`bacnet`、`opcua`、`lorawan`、`grpc`、`protobuf`、`websocket`、`sctp`、`wifi`、`radiotap`、`igmp`、`wireguard`。

**未支持项**以本页“明确未支持”矩阵为准；过滤器只会识别已注册的协议层。
