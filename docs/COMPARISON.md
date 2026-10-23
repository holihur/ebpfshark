# ebpfshark vs Wireshark vs tcpdump

ebpfshark is not a drop-in replacement for Wireshark or tcpdump. It targets a
different deployment model: a Linux host capture agent with a browser UI,
HTTP/SSE API and MCP access. Wireshark and tcpdump remain the reference tools
for deep desktop analysis and low-level packet capture.

## At a glance

| | ebpfshark | Wireshark | tcpdump |
| --- | --- | --- | --- |
| Form factor | Web UI + HTTP API + MCP | Desktop GUI + `tshark` CLI | Command-line |
| Live capture | eBPF TCX on Linux | libpcap/dumpcap | libpcap |
| Host OS | Linux >= 6.6 with BTF | Windows, macOS, Linux, BSD | Linux, macOS, BSD |
| Protocol depth | 50+ protocols, selected deep dissectors | Thousands of dissectors | Mostly link/network/transport; limited application detail |
| Display filters | Wireshark/tcpdump-like subset | Full Wireshark display-filter language | BPF capture filter only |
| Kernel capture filter | Not yet (user-space matching; only self-port drop in eBPF) | BPF capture filter via dumpcap | Native BPF |
| TCP stream view | Follow Stream in UI | Follow TCP/UDP/TLS streams | No built-in stream UI |
| Decryption | TLS/QUIC keylog, WPA2-PSK CCMP/GCMP, optional SSH session keys | Broad TLS/QUIC/WPA and protocol-specific key support (version dependent) | None |
| Statistics | Packet/flow/protocol stats, conversations | Extensive statistics and graphs | Basic packet counts via shell/BPF |
| Remote use | Browser/API/MCP; capture agent runs on target host | Remote capture via extcap/sshdump, `tshark` | SSH + remote `tcpdump -w` |
| File I/O | Import pcap/pcapng, export pcap/pcapng + time range | pcap/pcapng, many formats | Read/write pcap |
| Automation | REST API, SSE, MCP, single binary/Docker | `tshark`, Lua, extcap | Shell pipelines and `-w` files |
| Extensibility | Compile-time plugins + optional Go `.so` plugins | C/Lua dissectors, plugins, extcap | libpcap/BPF expressions |
| Deployment | Linux server/container | Desktop install | Package/single binary |
| Relative overhead | eBPF ring buffer + Go decode; user-space filtering | Full dissection is comparatively heavy | Usually the lowest-overhead capture path |

## Where each tool is strongest

### tcpdump

Use tcpdump when you need:

- The smallest possible capture footprint on a router/server
- Native BPF filtering before packets reach user space
- A quick remote `ssh host tcpdump -w capture.pcap`
- Stable shell automation and pcap handoff
- Minimal dependencies and predictable behavior

tcpdump is not the best choice for deep application protocol trees or
interactive stream analysis.

### Wireshark / tshark

Use Wireshark when you need:

- The broadest protocol coverage and field-level detail
- The full display-filter language, coloring rules and custom columns
- Expert analysis, graphs, conversations and protocol statistics
- TLS/QUIC/WPA and other decryption workflows
- Cross-platform desktop/CLI use
- Lua/extcap/plugin extensibility

Wireshark is the reference for deep, interactive packet forensics. Its GUI and
full dissection are also heavier than a headless capture path.

### ebpfshark

Use ebpfshark when you need:

- A browser-based live view on a Linux host without installing a desktop app
- A long-running capture agent with login, SSE and an HTTP API
- MCP/AI-agent access to packets, flows, filters and capture control
- A single Go binary/container with an embedded UI
- Integrated flow stats, follow-stream and pcap import/export
- A small, auditable protocol set for common operational traffic

Do not choose ebpfshark when you need Wireshark's full dissector catalog,
kernel-level capture filtering at high packet rates, or Windows/macOS host
capture.

## Filtering differences

```text
tcpdump "host 10.0.0.5 and port 443"   -> BPF, applied in the kernel
Wireshark "ip.addr == 10.0.0.5"        -> display filter, applied after capture
ebpfshark "ip.addr == 10.0.0.5"        -> display filter, currently after capture
```

ebpfshark's filters run in user space. They do not reduce kernel-to-user copy
cost; use snaplen, sampling or tcpdump when traffic volume is the problem.

## Interoperability

The tools compose well:

```bash
# Capture on a remote host with tcpdump, inspect with Wireshark
ssh root@host 'tcpdump -i eth0 -s 0 -w - not port 22' > remote.pcap
wireshark remote.pcap

# Capture with ebpfshark, then open the export in Wireshark
# UI: Export -> pcap
wireshark ebpfshark-export.pcap

# Import a Wireshark/tcpdump capture into ebpfshark
# UI: Import -> capture.pcapng
```

ebpfshark exports standard pcap and imports pcap/pcapng, so the tools can be
mixed without conversion pipelines.

## Performance notes

- tcpdump/BPF is generally the lowest-overhead way to capture at high rates,
  especially when a restrictive capture filter is applied in the kernel.
- ebpfshark captures with eBPF and performs protocol decoding/filtering in Go;
  its cost depends on packet rate, snaplen, protocol mix, stream reassembly and
  SSE subscribers.
- Wireshark's dissection is extremely capable but comparatively expensive for
  continuous high-rate capture; `dumpcap`/`tshark` are better for headless
  long-running captures.
- None of these numbers should be treated as universal: benchmark on the
  target kernel, NIC, traffic shape and filter set.

## Security comparison

All three can expose sensitive traffic. The difference is the attack surface:

- Wireshark/tcpdump are local processes; their privilege is usually limited to
  capture.
- ebpfshark adds a network service (UI/API/MCP), authentication and optional
  Docker deployment. Keep it on localhost or behind TLS, and never expose the
  API without authentication.
- eBPF/TCX plus `CAP_BPF`/`CAP_NET_ADMIN` is a powerful host capability. Docker
  deployments require host networking and relaxed seccomp/AppArmor; see
  [DOCKER.md](DOCKER.md).

## Bottom line

| Need | Recommended |
| --- | --- |
| Deepest protocol analysis, GUI, broad decryption | Wireshark |
| Fast remote/low-overhead capture, BPF filtering | tcpdump |
| Browser-based live capture, HTTP/MCP automation on Linux | ebpfshark |
| Long-term full-fidelity packet archive | tcpdump/dumpcap to pcap, analyze later |

Wireshark and tcpdump are mature reference implementations. ebpfshark's value
is operational accessibility and integration, not feature parity.
