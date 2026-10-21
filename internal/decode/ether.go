package decode

import (
	"fmt"
	"net/netip"

	"ebpfshark/internal/packet"
)

// looksLikeRawIP detects L3 frames seen on tunnel interfaces (tun, wireguard)
// that are captured without a link-layer header.
func looksLikeRawIP(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	et := be16(b[12:14])
	switch et {
	case etherTypeIPv4, etherTypeIPv6, etherTypeARP, etherTypeRARP, 0x8100, 0x88a8:
		return false
	}
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(be16(b[2:4]))
		return ihl >= 20 && ihl <= 60 && total >= ihl && total <= len(b)+128
	case 6:
		payload := int(be16(b[4:6]))
		return payload <= len(b)+128 && b[7] != 0
	}
	return false
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeARP  = 0x0806
	etherTypeRARP = 0x8035
)

func etherTypeName(t uint16) string {
	switch t {
	case etherTypeIPv4:
		return "IPv4"
	case etherTypeIPv6:
		return "IPv6"
	case etherTypeARP:
		return "ARP"
	case etherTypeRARP:
		return "RARP"
	case 0x8100:
		return "802.1Q Virtual LAN"
	case 0x88cc:
		return "LLDP"
	case 0x8847:
		return "MPLS"
	case 0x8863:
		return "PPPoE Discovery"
	case 0x8864:
		return "PPPoE Session"
	}
	return "Unknown"
}

func (c *ctx) dissectEthernet() {
	if looksLikeRawIP(c.data) {
		c.m.LinkType = packet.LinkRaw
		c.addLayer("raw")
		c.dissectRawIP()
		return
	}
	if len(c.data) < 14 {
		c.addRoot(newNode(fmt.Sprintf("Ethernet II (truncated, %d bytes)", len(c.data)), 0, len(c.data)))
		return
	}
	dst := macString(c.data[0:6])
	src := macString(c.data[6:12])
	et := be16(c.data[12:14])

	root := newNode(fmt.Sprintf("Ethernet II, Src: %s, Dst: %s", src, dst), 0, 14)
	root.add(
		newField("Destination: "+dst, "", 0, 6),
		newField("Source: "+src, "", 6, 6),
		newField(fmt.Sprintf("Type: %s (0x%04x)", etherTypeName(et), et), "", 12, 2),
	)
	c.m.EthSrc, c.m.EthDst = src, dst
	c.addLayer("eth")

	off := 14
	for et == 0x8100 || et == 0x88a8 || et == 0x9100 {
		if len(c.data) < off+4 {
			root.add(newField("VLAN (truncated)", "", off, len(c.data)-off))
			c.m.EthType = et
			c.addRoot(root)
			return
		}
		tci := be16(c.data[off : off+2])
		vid := tci & 0x0fff
		c.m.VLAN = int(vid)
		c.addLayer("vlan")
		root.add(newField(
			fmt.Sprintf("802.1Q Virtual LAN, PRI: %d, DEI: %d, ID: %d", tci>>13, (tci>>12)&1, vid),
			"", off, 4,
		))
		et = be16(c.data[off+2 : off+4])
		off += 4
	}

	c.m.EthType = et
	c.addRoot(root)

	payload := c.data[off:]
	switch et {
	case etherTypeIPv4:
		c.dissectIPv4(payload, off)
	case etherTypeIPv6:
		c.dissectIPv6(payload, off)
	case etherTypeARP, etherTypeRARP:
		c.dissectARP(payload, off)
	default:
		if len(payload) > 0 {
			c.addRoot(newNode(fmt.Sprintf("Data (%d bytes)", len(payload)), off, len(payload)))
			c.addLayer("data")
			c.m.Payload = payload
		}
	}
}

func (c *ctx) dissectRawIP() {
	if len(c.data) == 0 {
		return
	}
	switch c.data[0] >> 4 {
	case 4:
		c.dissectIPv4(c.data, 0)
	case 6:
		c.dissectIPv6(c.data, 0)
	default:
		c.addRoot(newNode(fmt.Sprintf("Raw IP (version %d)", c.data[0]>>4), 0, len(c.data)))
	}
}

func (c *ctx) dissectSLL(v2 bool) {
	hdrLen := 16
	if v2 {
		hdrLen = 20
	}
	if len(c.data) < hdrLen {
		c.addRoot(newNode(fmt.Sprintf("Linux cooked capture (truncated, %d bytes)", len(c.data)), 0, len(c.data)))
		return
	}
	var proto uint16
	var pktType uint16
	var ifIndex uint32
	var addr []byte
	if v2 {
		proto = be16(c.data[0:2])
		ifIndex = be32(c.data[4:8])
		pktType = uint16(c.data[10])
		addr = c.data[12:20]
	} else {
		pktType = be16(c.data[0:2])
		addr = c.data[6:14]
		proto = be16(c.data[14:16])
	}

	label := "Linux cooked capture"
	if v2 {
		label = "Linux cooked capture v2"
	}
	root := newNode(fmt.Sprintf("%s, Protocol: %s (0x%04x)", label, etherTypeName(proto), proto), 0, hdrLen)
	root.add(
		newField(fmt.Sprintf("Packet type: %d", pktType), "", 0, 2),
		newField(fmt.Sprintf("Interface index: %d", ifIndex), "", 4, 4),
		newField("Link-layer address: "+macString(addr), "", 6, 8),
		newField(fmt.Sprintf("Protocol: %s (0x%04x)", etherTypeName(proto), proto), "", hdrLen-2, 2),
	)
	c.addRoot(root)
	c.addLayer("sll")
	c.m.EthType = proto
	c.m.EthSrc = macString(addr)

	payload := c.data[hdrLen:]
	switch proto {
	case etherTypeIPv4:
		c.dissectIPv4(payload, hdrLen)
	case etherTypeIPv6:
		c.dissectIPv6(payload, hdrLen)
	case etherTypeARP, etherTypeRARP:
		c.dissectARP(payload, hdrLen)
	}
}

func (c *ctx) dissectARP(b []byte, base int) {
	c.addLayer("arp")
	if len(b) < 8 {
		c.addRoot(newNode("Address Resolution Protocol (truncated)", base, len(b)))
		return
	}
	htype := be16(b[0:2])
	ptype := be16(b[2:4])
	hlen := b[4]
	plen := b[5]
	op := be16(b[6:8])

	root := newNode(fmt.Sprintf("Address Resolution Protocol (%s)", arpOpName(op)), base, len(b))
	root.add(newField(fmt.Sprintf("Hardware type: %s (%d)", arpHwName(htype), htype), "", base, 2))

	off := 8
	var srcMAC, dstMAC string
	var srcIP, dstIP netip.Addr
	if hlen == 6 && plen == 4 && len(b) >= 28 {
		srcMAC = macString(b[off : off+6])
		srcIP = netip.AddrFrom4([4]byte{b[off+6], b[off+7], b[off+8], b[off+9]})
		dstMAC = macString(b[off+10 : off+16])
		dstIP = netip.AddrFrom4([4]byte{b[off+16], b[off+17], b[off+18], b[off+19]})
		root.add(
			newField("Sender MAC address: "+srcMAC, "", base+off, 6),
			newField("Sender IP address: "+srcIP.String(), "", base+off+6, 4),
			newField("Target MAC address: "+dstMAC, "", base+off+10, 6),
			newField("Target IP address: "+dstIP.String(), "", base+off+16, 4),
		)
	}

	root.add(
		newField(fmt.Sprintf("Protocol type: %s (0x%04x)", etherTypeName(ptype), ptype), "", base+2, 2),
		newField(fmt.Sprintf("Hardware size: %d", hlen), "", base+4, 1),
		newField(fmt.Sprintf("Protocol size: %d", plen), "", base+5, 1),
		newField(fmt.Sprintf("Opcode: %s (%d)", arpOpName(op), op), "", base+6, 2),
	)
	c.addRoot(root)

	c.m.ARPOp = op
	c.m.ARPSrcIP, c.m.ARPDstIP = srcIP, dstIP
	switch op {
	case 1: // request
		c.appInfo = fmt.Sprintf("Who has %s? Tell %s", ipString(dstIP), ipString(srcIP))
	case 2: // reply
		c.appInfo = fmt.Sprintf("%s is at %s", ipString(srcIP), srcMAC)
	default:
		c.appInfo = arpOpName(op)
	}
}

func arpOpName(op uint16) string {
	switch op {
	case 1:
		return "request"
	case 2:
		return "reply"
	case 3:
		return "RARP request"
	case 4:
		return "RARP reply"
	}
	return fmt.Sprintf("opcode %d", op)
}

func arpHwName(t uint16) string {
	switch t {
	case 1:
		return "Ethernet"
	case 6:
		return "IEEE 802"
	case 31:
		return "IPsec tunnel"
	}
	return "Unknown"
}

// registerARPIPs makes ARP addresses available for the address columns and
// for host filters.
func (c *ctx) registerARPIPs() {
	if !c.m.SrcIP.IsValid() && c.m.ARPSrcIP.IsValid() {
		c.m.SrcIP = c.m.ARPSrcIP
		c.m.DstIP = c.m.ARPDstIP
	}
}

func (c *ctx) dissectData(b []byte, base int) {
	if len(b) == 0 {
		return
	}
	c.addLayer("data")
	c.m.Payload = b
	c.addRoot(newField(fmt.Sprintf("Data (%d bytes)", len(b)), hexPreview(b, 64), base, len(b)))
}
