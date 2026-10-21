package decode

import (
	"fmt"
	"net/netip"
)

func ipProtoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPv4"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	}
	return "Unknown"
}

func (c *ctx) dissectIPv4(b []byte, base int) {
	c.addLayer("ip")
	c.m.IPVersion = 4
	if len(b) < 20 {
		c.addRoot(newNode("Internet Protocol Version 4 (truncated)", base, len(b)))
		return
	}
	if b[0]>>4 != 4 {
		c.addRoot(newNode(fmt.Sprintf("Internet Protocol (version %d)", b[0]>>4), base, len(b)))
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		c.addRoot(newNode("Internet Protocol Version 4 (bad header length)", base, len(b)))
		return
	}
	totalLen := int(be16(b[2:4]))
	if totalLen == 0 || totalLen > len(b) {
		// TSO/GSO packets can report a larger length than what is captured.
		totalLen = len(b)
	}

	src := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	dst := netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	c.m.SrcIP, c.m.DstIP = src, dst
	c.m.IPProto = b[9]
	c.m.TTL = b[8]
	c.m.IPLen = totalLen

	flagsFrag := be16(b[6:8])
	flags := flagsFrag >> 13
	fragOff := flagsFrag & 0x1fff
	var flagNames string
	if flags&0x2 != 0 {
		flagNames = "Don't fragment"
	}
	if flags&0x1 != 0 {
		if flagNames != "" {
			flagNames += ", "
		}
		flagNames += "More fragments"
	}
	if flagNames == "" {
		flagNames = "None"
	}

	root := newNode(fmt.Sprintf("Internet Protocol Version 4, Src: %s, Dst: %s", src, dst), base, totalLen)
	root.add(
		newField(fmt.Sprintf("Version: %d", b[0]>>4), "", base, 1),
		newField(fmt.Sprintf("Header Length: %d bytes (%d)", ihl, b[0]&0x0f), "", base, 1),
		newField(fmt.Sprintf("Differentiated Services Field: 0x%02x (DSCP: %d, ECN: %d)", b[1], b[1]>>2, b[1]&0x3), "", base+1, 1),
		newField(fmt.Sprintf("Total Length: %d", totalLen), "", base+2, 2),
		newField(fmt.Sprintf("Identification: 0x%04x (%d)", be16(b[4:6]), be16(b[4:6])), "", base+4, 2),
		newField(fmt.Sprintf("Flags: 0x%x, %s", flags, flagNames), "", base+6, 1),
		newField(fmt.Sprintf("Fragment Offset: %d", fragOff*8), "", base+6, 2),
		newField(fmt.Sprintf("Time to Live: %d", b[8]), "", base+8, 1),
		newField(fmt.Sprintf("Protocol: %s (%d)", ipProtoName(b[9]), b[9]), "", base+9, 1),
	)

	sum := checksum(b[:ihl])
	csField := newField(fmt.Sprintf("Header Checksum: 0x%04x", be16(b[10:12])), "", base+10, 2)
	if sum == 0 {
		csField.Value = "correct"
	} else {
		csField.Value = "incorrect, should be 0x" + fmt.Sprintf("%04x", ^sum&0xffff)
		csField.Severity = "warn"
	}
	root.add(csField,
		newField("Source Address: "+src.String(), "", base+12, 4),
		newField("Destination Address: "+dst.String(), "", base+16, 4),
	)

	if ihl > 20 {
		root.add(newField(fmt.Sprintf("Options (%d bytes)", ihl-20), hexBytes(b[20:ihl], 64), base+20, ihl-20))
	}
	c.addRoot(root)

	if fragOff != 0 {
		c.addRoot(newField(fmt.Sprintf("IPv4 fragment (offset %d)", fragOff*8), "", base+6, 2))
		c.appInfo = fmt.Sprintf("Fragmented IP protocol (offset=%d)", fragOff*8)
		return
	}

	l4 := b[ihl:totalLen]
	l4base := base + ihl
	c.m.Payload = l4
	switch b[9] {
	case 6:
		c.dissectTCP(l4, l4base, src, dst, totalLen-ihl)
	case 17:
		c.dissectUDP(l4, l4base, src, dst, totalLen-ihl)
	case 1:
		c.dissectICMP(l4, l4base)
	case 2:
		c.dissectIGMP(l4, l4base)
	case 4:
		c.dissectIPv4(l4, l4base)
	case 41:
		c.dissectIPv6(l4, l4base)
	case 47:
		c.dissectGRE(l4, l4base)
	default:
		c.dissectData(l4, l4base)
	}
}

var ipv6ExtHeaders = map[uint8]bool{
	0: true, 43: true, 44: true, 51: true, 60: true, 135: true, 139: true, 140: true,
}

func (c *ctx) dissectIPv6(b []byte, base int) {
	c.addLayer("ipv6")
	c.m.IPVersion = 6
	if len(b) < 40 {
		c.addRoot(newNode("Internet Protocol Version 6 (truncated)", base, len(b)))
		return
	}
	payloadLen := int(be16(b[4:6]))
	next := b[6]
	hop := b[7]
	var srcB, dstB [16]byte
	copy(srcB[:], b[8:24])
	copy(dstB[:], b[24:40])
	src := netip.AddrFrom16(srcB)
	dst := netip.AddrFrom16(dstB)
	c.m.SrcIP, c.m.DstIP = src, dst
	c.m.IPProto = next
	c.m.TTL = hop
	totalLen := 40 + payloadLen
	if totalLen > len(b) {
		totalLen = len(b)
	}
	c.m.IPLen = totalLen

	root := newNode(fmt.Sprintf("Internet Protocol Version 6, Src: %s, Dst: %s", src, dst), base, totalLen)
	root.add(
		newField("Version: 6", "", base, 1),
		newField(fmt.Sprintf("Traffic Class: 0x%02x", (be16(b[0:2])>>4)&0xff), "", base, 2),
		newField(fmt.Sprintf("Flow Label: 0x%05x", be32(b[0:4])&0xfffff), "", base, 4),
		newField(fmt.Sprintf("Payload Length: %d", payloadLen), "", base+4, 2),
		newField(fmt.Sprintf("Next Header: %s (%d)", ipProtoName(next), next), "", base+6, 1),
		newField(fmt.Sprintf("Hop Limit: %d", hop), "", base+7, 1),
		newField("Source Address: "+src.String(), "", base+8, 16),
		newField("Destination Address: "+dst.String(), "", base+24, 16),
	)
	c.addRoot(root)

	off := 0
	for i := 0; i < 6 && ipv6ExtHeaders[next]; i++ {
		if len(b) < off+8 {
			return
		}
		switch next {
		case 44: // fragment header
			fragOff := be16(b[off+2:off+4]) >> 3
			more := be16(b[off+2:off+4])&1 != 0
			c.addRoot(newField(fmt.Sprintf("IPv6 Fragment Header (offset=%d, more=%t)", fragOff*8, more), "", base+off, 8))
			if fragOff != 0 {
				c.appInfo = fmt.Sprintf("IPv6 fragment (offset=%d)", fragOff*8)
				return
			}
			next = b[off]
			off += 8
		case 51: // authentication header
			hlen := (int(b[off+1]) + 2) * 4
			next = b[off]
			off += hlen
		default:
			hlen := (int(b[off+1]) + 1) * 8
			next = b[off]
			off += hlen
		}
		if off < 0 || off > len(b) {
			return
		}
	}
	c.m.IPProto = next
	c.m.Payload = b[off:]

	l4 := b[off:]
	l4base := base + off
	switch next {
	case 6:
		c.dissectTCP(l4, l4base, src, dst, len(l4))
	case 17:
		c.dissectUDP(l4, l4base, src, dst, len(l4))
	case 58:
		c.dissectICMPv6(l4, l4base, src, dst)
	default:
		c.dissectData(l4, l4base)
	}
}
