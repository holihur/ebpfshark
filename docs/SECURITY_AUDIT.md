# Protocol security audit

## Scope and threat model

The protocol dissectors process bytes supplied by an untrusted network or by
an imported pcap. The security goals are:

- a malformed frame must never panic the process;
- parser work must be linear or explicitly bounded by the captured length;
- no protocol parser may execute shell commands or write files;
- TLS/Wi-Fi/SSH secrets are only held in memory and never serialized by the
  status APIs;
- dynamic `.so` plugins and the MITM CA are explicitly privileged features.

This is an engineering audit, not a formal proof. Fuzzing and tests provide
evidence, not a guarantee.

## Automated gates

- `go test -race ./...` and `go test -race -tags full ./...`
- `FuzzDecode` for framing and link-layer paths
- `FuzzProtocolPayloads` across all common protocol ports
- `go vet`, `govulncheck`
- privileged TCX filter integration test
- static review for `unsafe`, `panic`, unbounded allocations and unbounded
  loops in `internal/decode`

## Protocol inventory

| Layer | Protocols | Main attack surface | Controls |
| --- | --- | --- | --- |
| Link / tunnel | Ethernet, VLAN, MPLS, VXLAN, GRE, Wi-Fi, radiotap, EAPOL | nested headers, TLV lengths, recursion | bounded tunnel depth; length checks; fuzz framing |
| Network | IPv4, IPv6, ICMP, ICMPv6, IGMP, ARP | extension headers, fragments, option lengths | fragment/extension handling; fuzz decode |
| Transport | TCP, UDP, SCTP | header length, options, payload boundaries | bounded payload access; no reassembly explosion |
| Discovery / infra | DNS, DHCP, NTP, SNMP, SSDP, syslog, STUN | TLV/record counts, compression, recursive compression | count/depth bounds; fuzz payload ports |
| Web / TLS | HTTP/1.1, HTTP/2, TLS, QUIC, WebSocket, gRPC, protobuf | chunking, HPACK/QPACK, record lengths, decompression | bounded body/decompression; keylog only when configured |
| Remote access | SSH, SIP, RADIUS | length fields, authentication blobs | bounded parsing; SSH decryption requires explicit keys |
| Data / messaging | Redis, PostgreSQL, MySQL, MQTT, MQTT-SN, CoAP, AMQP, BGP, NetFlow | RESP/frame lengths, template expansion, SQL messages | length checks; template/field caps |
| Industrial / IoT | Modbus, BACnet, OPC UA, LoRaWAN | binary lengths, object IDs | bounded fields; no decryption of encrypted payloads |
| Media | RTP, RTCP, RTSP, MPEG-TS, HLS, DASH, RTMP, H.264, H.265, VP8, VP9, AV1, AAC, Opus | codec headers, segment/playlist sizes | bounded NAL/frame parsing; no decoder execution |
| AI | Anthropic Messages, OpenAI Chat Completions, OpenAI Responses | JSON/SSE nesting, compressed bodies, reassembly | field caps; JSON depth cap; gzip/brotli limits; no API keys serialized |

## Findings and residual risks

- No `unsafe`, explicit `panic`, shell execution or filesystem write was found
  in protocol dissectors during this pass.
- Fuzzing all common protocol ports completed without a crash in the audit
  run; this does not prove absence of bugs.
- HTTP/AI/SSE body buffering and compressed payload handling are the highest
  memory-pressure areas. Keep `max-packets`, stream budget and ring buffer
  bounded.
- TLS decryption depends on operator-provided keylog material; a compromised
  keylog exposes traffic by design.
- SSH support is limited to opt-in session keys; private keys cannot recover
  modern SSH sessions.
- Dynamic Go plugins run in-process with full privileges. Treat them as code.
- MITM mode requires trusting the generated CA and can be defeated by
  certificate pinning. It must not be exposed as an open proxy.
- The privileged capture filter integration test validates TCX behavior, but
  kernel-version-specific differences remain possible.

## Recommended next steps

1. Add per-protocol corpus generators for complex parsers: QUIC, TLS, HTTP/2,
   NetFlow templates, OPC UA, BACnet, AMQP.
2. Run long-duration fuzzing in CI (nightly) with memory limits.
3. Add allocation budgets per dissector and reject pathological field counts.
4. Add sanitizer builds for cgo/dynamic plugin paths.
5. Treat protocol parsing as a security boundary in release notes.
