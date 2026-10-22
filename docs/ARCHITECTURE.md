# Architecture

## Decode pipeline

```
capture -> store -> decode.DecodeSummary -> packet list
                               |
                               +-> decode.Decode (detail, on demand)
```

The default build is **core** (DNS/DHCP/HTTP/TLS). `-tags full` adds every
protocol plugin. Link-layer, IP, transport and tunnel decoders are always
present because they define packet metadata and filtering.

## Application plugins

Application dissectors do not live in one switch/chain file. Each protocol
module registers a `pluginSpec` in `init()`:

```go
func init() {
    RegisterPlugin(pluginSpec{
        Name:      "example",
        Priority:  100,
        Transport: TransportTCP | TransportUDP,
        Match:     func(c *ctx, sport, dport uint16, b []byte) bool { ... },
        Dissect:   func(c *ctx, b []byte, base int) bool { ... },
        Display:   "Example", // optional summary name
    })
}
```

`plugin.go` collects registrations, sorts by priority, and exposes immutable
chains per transport. `dispatch.go` is the only transport-to-plugin entry
point. `Match` must be cheap and must not mutate the context; `Dissect`
returns `true` only when it claims the payload.

Rules:

- Keep protocol-specific code and helpers in `proto_<name>.go`.
- Put `//go:build full` on non-default plugins.
- Use priorities to preserve protocol precedence, not registration order.
- Register both transport directions in one spec where possible.
- Decrypted TLS/QUIC/SSH payload dispatch uses `Decrypted: true`; such
  plugins run without ports.
- The registry is init-time only. Do not register after decoding starts.

## Core vs full

| Build | Selected by | Plugin files |
| --- | --- | --- |
| core | default | `proto_dns.go`, `proto_http.go`, `proto_tls.go`, `app_dhcp.go` |
| full | `-tags full` | all `proto_*.go` with the `full` tag |

`go test ./...` exercises core; `go test -tags full ./...` exercises all
plugins. CI does both, plus race, fuzz and benchmark smoke.

## Package layout

```
cmd/ebpfshark        flags, startup, doc
internal/capture     eBPF/pcap capture
internal/decode      link/IP/transport + application plugins
internal/filter      filter language, schema
internal/packet      Meta/Summary/LayerMask/Field-independent packet types
internal/store       bounded packet/flow stores
internal/server      HTTP/SSE API
internal/mcpserver   MCP tools over the same store
web/                 React UI
```

## Adding a protocol

1. Add `internal/decode/proto_example.go` with `//go:build full`.
2. Implement `dissectExample`.
3. Register matcher + dissector in `init()`.
4. Add the layer name to `internal/packet/packet.go`.
5. Add core/full filter schema names in `internal/filter/schema_layers_*.go`
   and a predicate in `internal/filter/filter.go` if it is a layer.
6. Add a focused decode test and update `plugin_full_test.go` expectations.
7. Update README protocol coverage and known limitations.
