// Package pluginapi defines the stable ABI between ebpfshark and dynamically
// loaded application dissectors.
//
// Plugins are built as Go shared objects (buildmode=plugin) with the same Go
// toolchain, module dependencies and cgo settings as the main binary. They are
// trusted native code: loading a plugin grants it the same privileges as the
// capture process.
package pluginapi

// Transport is a bit mask of transports a plugin handles.
type Transport uint8

const (
	UDP Transport = 1 << iota
	TCP
)

// Metadata describes the packet state visible to a dissector. It is a copy;
// plugins must not retain it after Dissect returns.
type Metadata struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Layers  []string
}

// Request is one application payload. Data is read-only and only valid for
// the duration of the call. Base is the offset of Data in the captured frame,
// so field offsets returned by a plugin should be absolute frame offsets.
type Request struct {
	Data []byte
	Base int
	Meta Metadata
}

// Field is a node in the protocol detail tree. Offsets and lengths refer to
// the captured frame, not to Data.
type Field struct {
	Label    string
	Value    string
	Severity string
	Offset   int
	Length   int
	Children []Field
}

// Result is the protocol tree returned by a plugin. Layers are added to the
// packet layer list. Proto is used for filtering/summary; Info becomes the
// packet-list description.
type Result struct {
	Layers []string
	Proto  string
	Info   string
	Fields []Field
}

// Plugin is the interface implemented by a dynamic dissector.
type Plugin interface {
	Name() string
	Priority() int
	Transport() Transport
	Match(req Request) bool
	Dissect(req Request) (Result, bool)
}

// DecryptedPlugin may be implemented by plugins that also want to inspect
// decrypted TLS/QUIC/SSH application bytes, where ports are not meaningful.
type DecryptedPlugin interface {
	Plugin
	Decrypted() bool
}
