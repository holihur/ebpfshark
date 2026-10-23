//go:build full

package decode

import (
	"encoding/binary"
	"fmt"
)

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func looksLikeOPCUA(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	switch string(b[:3]) {
	case "HEL", "ACK", "ERR", "OPN", "MSG", "CLO":
		return int(le32(b[4:8])) >= 8
	}
	return false
}

func opcuaString(b []byte, off int) (string, int, bool) {
	if off+4 > len(b) {
		return "", off, false
	}
	n := int(le32(b[off : off+4]))
	off += 4
	if n < 0 || off+n > len(b) {
		return "", off, false
	}
	return string(b[off : off+n]), off + n, true
}

func (c *ctx) dissectOPCUA(b []byte, base int) bool {
	if !looksLikeOPCUA(b) {
		return false
	}
	typ := string(b[:3])
	size := int(le32(b[4:8]))
	if size < 8 || size > len(b) {
		size = len(b)
	}
	c.addLayer("opcua")
	c.proto = "opcua"
	root := newNode("OPC UA Binary "+typ, base, size)
	root.add(c.newField("Message Type: "+typ, "", base, 3),
		c.newField(fmt.Sprintf("Chunk: %c", b[3]), "", base+3, 1),
		c.newField(fmt.Sprintf("Message Size: %d", le32(b[4:8])), "", base+4, 4))
	info := "OPC UA " + typ
	switch typ {
	case "HEL", "ACK":
		if len(b) >= 28 {
			root.add(c.newField(fmt.Sprintf("Protocol Version: %d", le32(b[8:12])), "", base+8, 4),
				c.newField(fmt.Sprintf("Receive Buffer: %d", le32(b[12:16])), "", base+12, 4),
				c.newField(fmt.Sprintf("Send Buffer: %d", le32(b[16:20])), "", base+16, 4),
				c.newField(fmt.Sprintf("Max Message Size: %d", le32(b[20:24])), "", base+20, 4),
				c.newField(fmt.Sprintf("Max Chunk Count: %d", le32(b[24:28])), "", base+24, 4))
		}
	case "ERR":
		if len(b) >= 16 {
			root.add(c.newField(fmt.Sprintf("Error Code: 0x%08x", le32(b[8:12])), "", base+8, 4))
			if s, _, ok := opcuaString(b, 12); ok {
				root.add(c.newField("Reason: "+s, "", base+12, len(s)))
			}
		}
	case "OPN", "MSG":
		if len(b) >= 12 {
			root.add(c.newField(fmt.Sprintf("Secure Channel ID: %d", le32(b[8:12])), "", base+8, 4))
			if s, next, ok := opcuaString(b, 12); ok {
				root.add(c.newField("Security Policy: "+s, "", base+12, len(s)))
				if len(b) >= next+4 {
					certLen := int(le32(b[next : next+4]))
					root.add(c.newField(fmt.Sprintf("Sender Certificate: %d bytes", certLen), "", base+next, 4))
				}
			}
		}
	}
	c.addRoot(root)
	c.appInfo = info
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "opcua", Priority: 115, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 4840 || dport == 4840) && looksLikeOPCUA(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectOPCUA(b, base) }, Display: "OPC UA"})
}
