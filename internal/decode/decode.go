// Package decode turns raw link-layer frames into a Wireshark-style protocol
// tree plus a compact summary and filter metadata.
package decode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"ebpfshark/internal/packet"
)

// Field is a node in the protocol detail tree. Offset/Length refer to byte
// ranges in the captured frame so the UI can highlight them in the hex view.
type Field struct {
	Label    string   `json:"label"`
	Value    string   `json:"value,omitempty"`
	Offset   int      `json:"offset"`
	Length   int      `json:"length"`
	Severity string   `json:"severity,omitempty"` // "", "note", "warn", "error"
	Children []*Field `json:"children,omitempty"`
}

// Result is the output of dissecting one frame.
type Result struct {
	Fields  []*Field
	Summary packet.Summary
	Meta    packet.Meta
}

type ctx struct {
	data     []byte
	wireLen  int
	linkType packet.LinkType
	depth    int

	m      packet.Meta
	roots  []*Field
	layers []string

	proto   string // highest-level application protocol (HTTP, DNS, ...)
	appInfo string // info string provided by the highest-level dissector
}

// Decode dissects data. linkType selects the outermost decoder and wireLen is
// the original on-wire length (which may exceed len(data) when truncated).
func Decode(data []byte, linkType packet.LinkType, wireLen int) Result {
	return decode(data, linkType, wireLen, 0)
}

const maxTunnelDepth = 4

func decode(data []byte, linkType packet.LinkType, wireLen, depth int) Result {
	c := &ctx{data: data, wireLen: wireLen, linkType: linkType, depth: depth}
	c.m.ID = 0
	c.m.FrameLen = wireLen
	c.m.CapLen = len(data)
	c.m.LinkType = linkType
	c.m.Raw = data

	switch linkType {
	case packet.LinkRaw:
		c.dissectRawIP()
	case packet.LinkLinuxSLL:
		c.dissectSLL(false)
	case packet.LinkLinuxSLL2:
		c.dissectSLL(true)
	default:
		c.dissectEthernet()
	}

	if len(c.roots) == 0 {
		c.roots = append(c.roots, &Field{
			Label:    fmt.Sprintf("Frame (%d bytes)", len(data)),
			Value:    hexPreview(data, 32),
			Offset:   0,
			Length:   len(data),
			Severity: "note",
			Children: []*Field{
				newField("Captured Length", fmt.Sprintf("%d bytes", len(data)), 0, 0),
				newField("Frame Length", fmt.Sprintf("%d bytes", c.m.FrameLen), 0, 0),
			},
		})
	}

	c.m.Layers = c.layers
	c.m.App = c.proto
	if c.m.Payload == nil {
		c.m.Payload = data
	}

	sum := packet.Summary{
		Layers:  c.layers,
		SrcIP:   ipString(c.m.SrcIP),
		DstIP:   ipString(c.m.DstIP),
		SrcPort: c.m.SrcPort,
		DstPort: c.m.DstPort,
		Info:    c.appInfo,
		Src:     endpoint(c.m.SrcIP, c.m.SrcPort),
		Dst:     endpoint(c.m.DstIP, c.m.DstPort),
	}
	if sum.Src == "" {
		sum.Src = c.m.EthSrc
	}
	if sum.Dst == "" {
		sum.Dst = c.m.EthDst
	}
	if sum.Src == "" {
		sum.Src = "?"
	}
	if sum.Dst == "" {
		sum.Dst = "?"
	}

	sum.Protocol = c.topProtocol()
	if sum.Info == "" {
		sum.Info = c.fallbackInfo()
	}

	return Result{Fields: c.roots, Summary: sum, Meta: c.m}
}

func (c *ctx) topProtocol() string {
	switch c.proto {
	case "http2":
		return "HTTP/2"
	case "postgresql":
		return "PostgreSQL"
	case "wireguard":
		return "WireGuard"
	case "syslog":
		return "Syslog"
	case "redis":
		return "Redis"
	}
	if c.proto != "" {
		return strings.ToUpper(c.proto)
	}
	if c.m.HasLayer("icmpv6") {
		return "ICMPv6"
	}
	if c.m.HasLayer("icmp") {
		return "ICMP"
	}
	if c.m.HasLayer("tcp") {
		return "TCP"
	}
	if c.m.HasLayer("udp") {
		return "UDP"
	}
	if c.m.HasLayer("arp") {
		return "ARP"
	}
	if c.m.HasLayer("ipv6") {
		return "IPv6"
	}
	if c.m.HasLayer("ip") {
		return "IPv4"
	}
	if c.m.HasLayer("eth") {
		return "Ethernet"
	}
	if c.m.HasLayer("mpls") {
		return "MPLS"
	}
	if c.m.HasLayer("gre") {
		return "GRE"
	}
	if c.m.HasLayer("igmp") {
		return "IGMP"
	}
	return "Frame"
}

func (c *ctx) fallbackInfo() string {
	switch {
	case c.m.HasLayer("vxlan"):
		return "VXLAN"
	case c.m.HasLayer("mpls"):
		return "MPLS"
	case c.m.HasLayer("gre"):
		return "GRE"
	case c.m.HasLayer("igmp"):
		return "IGMP"
	case c.m.HasLayer("arp"):
		return "ARP"
	case c.m.HasLayer("tcp"):
		return fmt.Sprintf("%d → %d Len=%d", c.m.SrcPort, c.m.DstPort, c.m.TCPPayLen)
	case c.m.HasLayer("udp"):
		return fmt.Sprintf("%d → %d Len=%d", c.m.SrcPort, c.m.DstPort, c.m.UDPLen)
	case c.m.HasLayer("ip"), c.m.HasLayer("ipv6"):
		return fmt.Sprintf("IPv%d %s → %s", c.m.IPVersion, ipString(c.m.SrcIP), ipString(c.m.DstIP))
	case c.m.HasLayer("eth"):
		return fmt.Sprintf("%s → %s", c.m.EthSrc, c.m.EthDst)
	}
	return fmt.Sprintf("%d bytes", len(c.data))
}

func (c *ctx) addLayer(name string) {
	c.layers = append(c.layers, name)
	c.m.LayerMask |= packet.LayerBit(name)
}

func (c *ctx) addRoot(f *Field) {
	if f != nil {
		c.roots = append(c.roots, f)
	}
}

var fieldPool = sync.Pool{New: func() any { return &Field{} }}

func allocField(label, value string, off, length int) *Field {
	f := fieldPool.Get().(*Field)
	f.Label, f.Value, f.Offset, f.Length, f.Severity, f.Children = label, value, off, length, "", nil
	return f
}

func newField(label, value string, off, length int) *Field {
	return allocField(label, value, off, length)
}

func newNode(label string, off, length int) *Field {
	return allocField(label, "", off, length)
}

// ReleaseFields returns a protocol tree to the decoder's pool. Callers that
// only need Summary/Meta (the ingest path) use this to cut GC pressure.
func ReleaseFields(fields []*Field) {
	for _, f := range fields {
		if f == nil {
			continue
		}
		if len(f.Children) > 0 {
			ReleaseFields(f.Children)
		}
		f.Label, f.Value = "", ""
		f.Offset, f.Length, f.Severity = 0, 0, ""
		f.Children = nil
		fieldPool.Put(f)
	}
}

func (f *Field) add(children ...*Field) *Field {
	f.Children = append(f.Children, children...)
	return f
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

func ip4String(v uint32) string {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func endpoint(a netip.Addr, port uint16) string {
	if !a.IsValid() {
		return ""
	}
	s := a.String()
	if port != 0 {
		s += fmt.Sprintf(":%d", port)
	}
	return s
}

func macString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func hexPreview(b []byte, max int) string {
	truncated := len(b) > max
	if truncated {
		b = b[:max]
	}
	const digits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b)*3 + 2)
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(digits[x>>4])
		sb.WriteByte(digits[x&0x0f])
	}
	if truncated {
		sb.WriteString(" …")
	}
	return sb.String()
}

// Bytes returns the first n bytes as a hex string.
// shiftFields offsets a protocol tree by base so nested dissectors can reuse
// the same frame-relative highlighting.
func shiftFields(fields []*Field, base int) []*Field {
	for _, f := range fields {
		if f.Offset >= 0 {
			f.Offset += base
		}
		if len(f.Children) > 0 {
			f.Children = shiftFields(f.Children, base)
		}
	}
	return fields
}

func hexBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	const digits = "0123456789abcdef"
	var sb strings.Builder
	if len(b) > 1 {
		sb.Grow(len(b)*3 - 1)
	}
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(digits[x>>4])
		sb.WriteByte(digits[x&0x0f])
	}
	return sb.String()
}
