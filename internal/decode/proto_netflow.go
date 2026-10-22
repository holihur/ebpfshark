//go:build full

package decode

import (
	"fmt"
	"net/netip"
)

// -------------------------------------------------------------- NetFlow

func (c *ctx) dissectNetFlow(b []byte, base int) bool {
	if len(b) < 8 {
		return false
	}
	v := be16(b[0:2])
	if v != 5 && v != 9 && v != 10 {
		return false
	}
	c.addLayer("netflow")
	c.proto = "netflow"
	root := newNode(fmt.Sprintf("NetFlow v%d", v), base, len(b))
	info := fmt.Sprintf("NetFlow v%d", v)
	switch v {
	case 5:
		if len(b) < 24 {
			return false
		}
		count := be16(b[2:4])
		root.add(newField(fmt.Sprintf("Count: %d", count), "", base+2, 2), newField(fmt.Sprintf("Uptime: %d ms", be32(b[4:8])), "", base+4, 4), newField(fmt.Sprintf("Unix Seconds: %d", be32(b[8:12])), "", base+8, 4), newField(fmt.Sprintf("Flow Sequence: %d", be32(b[16:20])), "", base+16, 4))
		p := 24
		for i := 0; i < int(count) && p+48 <= len(b); i++ {
			src := netip.AddrFrom4([4]byte{b[p], b[p+1], b[p+2], b[p+3]})
			dst := netip.AddrFrom4([4]byte{b[p+4], b[p+5], b[p+6], b[p+7]})
			f := newField(fmt.Sprintf("Flow %d: %s -> %s", i+1, src, dst), "", base+p, 48)
			f.add(newField(fmt.Sprintf("Src Port: %d, Dst Port: %d", be16(b[p+32:p+34]), be16(b[p+34:p+36])), "", base+p+32, 4), newField(fmt.Sprintf("Packets: %d, Bytes: %d", be32(b[p+16:p+20]), be32(b[p+20:p+24])), "", base+p+16, 8), newField(fmt.Sprintf("Protocol: %d", b[p+38]), "", base+p+38, 1))
			root.add(f)
			p += 48
		}
		info += fmt.Sprintf(" flows=%d", count)
	case 9:
		root.add(newField(fmt.Sprintf("Count: %d", be16(b[2:4])), "", base+2, 2), newField(fmt.Sprintf("SysUptime: %d", be32(b[4:8])), "", base+4, 4), newField(fmt.Sprintf("Unix Seconds: %d", be32(b[8:12])), "", base+8, 4), newField(fmt.Sprintf("Sequence: %d", be32(b[12:16])), "", base+12, 4))
		p := 20
		for p+4 <= len(b) {
			id, l := be16(b[p:p+2]), int(be16(b[p+2:p+4]))
			if l < 4 || p+l > len(b) {
				break
			}
			root.add(newField(fmt.Sprintf("FlowSet %d (%d bytes)", id, l), "", base+p, l))
			p += l
		}
	case 10:
		if len(b) < 16 {
			return false
		}
		total := int(be16(b[2:4]))
		root.add(newField(fmt.Sprintf("Length: %d", total), "", base+2, 2), newField(fmt.Sprintf("Export Time: %d", be32(b[4:8])), "", base+4, 4), newField(fmt.Sprintf("Sequence: %d", be32(b[8:12])), "", base+8, 4), newField(fmt.Sprintf("Observation Domain: %d", be32(b[12:16])), "", base+12, 4))
		p := 16
		for p+4 <= len(b) {
			id, l := be16(b[p:p+2]), int(be16(b[p+2:p+4]))
			if l < 4 || p+l > len(b) {
				break
			}
			root.add(newField(fmt.Sprintf("Set %d (%d bytes)", id, l), "", base+p, l))
			p += l
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "netflow", Priority: 120, Transport: TransportUDP | TransportTCP,
		Match: portMatch(map[uint16]bool{2055: true, 2056: true, 4739: true, 9995: true, 6343: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectNetFlow(b, base) }})
}
