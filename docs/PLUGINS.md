# Dynamic dissector plugins

ebpfshark can load application dissectors from Go shared objects at startup.

```bash
./ebpfshark -plugins ./plugins/demo.so -capture eth0
./ebpfshark -plugin-dir ./plugins
```

A normal release/static build (`CGO_ENABLED=0`) cannot load `.so` plugins. Build
a dynamic-capable binary with:

```bash
make go-build-dynamic
```

Environment equivalents:

```bash
EBPFSHARK_PLUGINS=./plugins/demo.so
EBPFSHARK_PLUGIN_DIR=./plugins
```

`-plugin-dir` loads `*.so` files sorted by name. Explicit `-plugins` entries
are loaded first. A failed plugin is logged; the rest of the application keeps
running.

## Platform and ABI

Dynamic loading uses Go's `plugin` package:

- Linux, macOS/FreeBSD with cgo enabled
- not available on Windows or in `CGO_ENABLED=0` builds
- plugin and main binary must use the **same Go toolchain**, module graph,
  build tags and cgo settings
- ABI mismatch fails at `plugin.Open`; rebuild the plugin against the same
  ebpfshark release
- plugins are trusted native code and run with the full privileges of the
  capture process; never load untrusted `.so` files
- plugins cannot be unloaded or hot-reloaded in a running process

Because Go plugin ABI is intentionally unstable, the safe distribution model is
to build plugins in the same CI job/release as the ebpfshark binary.

## Writing a plugin

Use `ebpfshark/pkg/pluginapi`. A plugin exports either:

```go
var Plugin pluginapi.Plugin = myDissector{}
```

or:

```go
func New() pluginapi.Plugin { return myDissector{} }
```

Minimal example:

```go
package main

import (
    "fmt"
    "ebpfshark/pkg/pluginapi"
)

type demo struct{}

func (demo) Name() string                    { return "demo" }
func (demo) Priority() int                   { return 500 }
func (demo) Transport() pluginapi.Transport  { return pluginapi.UDP }
func (demo) Match(r pluginapi.Request) bool {
    return r.Meta.SrcPort == 9999 || r.Meta.DstPort == 9999
}
func (demo) Dissect(r pluginapi.Request) (pluginapi.Result, bool) {
    if len(r.Data) == 0 { return pluginapi.Result{}, false }
    return pluginapi.Result{
        Layers: []string{"demo"},
        Proto:  "demo",
        Info:   fmt.Sprintf("demo %d bytes", len(r.Data)),
        Fields: []pluginapi.Field{{
            Label: "Payload", Value: string(r.Data),
            Offset: r.Base, Length: len(r.Data),
        }},
    }, true
}

var Plugin pluginapi.Plugin = demo{}
```

Build:

```bash
go build -buildmode=plugin -o plugins/demo.so ./examples/plugins/demo
```

`examples/plugins/demo` is a complete example.

## Contract

- `Match` must be cheap and side-effect free.
- `Data` is read-only and valid only during the call.
- `Request.Base` is the payload's offset in the captured frame. Return field
  offsets as absolute frame offsets so the hex view highlights correctly.
- `Layers` are added to the packet layer list; `Proto` feeds filtering/summary;
  `Info` becomes the packet-list description.
- Return `false` from `Dissect` to let the next plugin try. Returning `true`
  claims the payload even if the result has no fields.
- Use `Priority` below built-in plugins only if you intentionally want to
  override detection. Built-ins generally use 10–170.
- Implement `pluginapi.DecryptedPlugin` if the plugin should also inspect
  decrypted TLS/QUIC/SSH application bytes.

## Testing

```bash
go build -buildmode=plugin -o /tmp/demo.so ./examples/plugins/demo
EBPFSHARK_TEST_PLUGIN=/tmp/demo.so go test -run TestLoadDynamicPlugin ./internal/decode
```
