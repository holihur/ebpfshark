//go:build full

package decode

import (
	"bytes"
	"fmt"

	"ebpfshark/internal/packet"
)

// ------------------------------------------------------------------ VXLAN

func (c *ctx) dissectVXLAN(b []byte, base int) bool {
	if len(b) < 8 || b[0]&0x08 == 0 {
		return false
	}
	vni := be32(b[4:8]) >> 8
	c.addLayer("vxlan")
	c.proto = "vxlan"
	root := c.newNode(fmt.Sprintf("Virtual eXtensible LAN, VNI: %d", vni), base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Flags: 0x%02x", b[0]), "", base, 1),
		c.newField(fmt.Sprintf("VXLAN Network Identifier: %d", vni), "", base+4, 4),
	)
	inner := b[8:]
	info := fmt.Sprintf("VXLAN VNI %d", vni)
	if len(inner) > 0 && c.depth < maxTunnelDepth {
		res := decode(inner, packet.LinkEthernet, len(inner), c.depth+1, c.noFields)
		if len(res.Fields) > 0 {
			group := c.newNode("Inner frame", base+8, len(inner))
			group.Children = shiftFields(res.Fields, base+8)
			innerRes := res
			root.add(group)
			info += fmt.Sprintf(", inner %s", innerRes.Summary.Protocol)
			if innerRes.Meta.SrcIP.IsValid() {
				info += fmt.Sprintf(" %s → %s", innerRes.Meta.SrcIP, innerRes.Meta.DstIP)
			}
		}
	} else if len(inner) > 0 {
		root.add(c.newField("Inner frame (tunnel depth limit)", "", base+8, len(inner)))
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func looksLikeSSHBanner(b []byte) bool {
	return bytes.HasPrefix(b, []byte("SSH-"))
}

func looksLikeHTTP2(b []byte) bool {
	return bytes.HasPrefix(b, http2Preface)
}

func looksLikeQUIC(b []byte) bool {
	if len(b) < 7 {
		return false
	}
	if b[0]&0x80 != 0 {
		return be32(b[1:5]) != 0
	}
	return len(b) >= 20 && b[0]&0x40 != 0
}

func init() {
	RegisterPlugin(pluginSpec{Name: "vxlan", Priority: 70, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{4789: true, 8472: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectVXLAN(b, base) }})
}
