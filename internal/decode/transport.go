package decode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

func onesComplementSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksum returns 0 when the ones-complement checksum over b is valid.
func checksum(b []byte) uint16 {
	return foldChecksum(onesComplementSum(b))
}

func pseudoHeaderSumV4(src, dst netip.Addr, proto uint8, length int) uint32 {
	var b [12]byte
	s4 := src.As4()
	d4 := dst.As4()
	copy(b[0:4], s4[:])
	copy(b[4:8], d4[:])
	b[9] = proto
	binary.BigEndian.PutUint16(b[10:12], uint16(length))
	return onesComplementSum(b[:])
}

func pseudoHeaderSumV6(src, dst netip.Addr, proto uint8, length int) uint32 {
	var b [40]byte
	s16 := src.As16()
	d16 := dst.As16()
	copy(b[0:16], s16[:])
	copy(b[16:32], d16[:])
	binary.BigEndian.PutUint32(b[32:36], uint32(length))
	b[39] = proto
	return onesComplementSum(b[:])
}

func (c *ctx) transportChecksum(b []byte, base int, sport, dport uint16, proto uint8, l4len int, csOff int) *Field {
	field := c.newField(fmt.Sprintf("Checksum: 0x%04x", be16(b[csOff:csOff+2])), "", base+csOff, 2)
	if len(b) < l4len {
		field.Value = "unverified (capture truncated)"
		return field
	}
	var pseudo uint32
	if c.m.IPVersion == 6 {
		pseudo = pseudoHeaderSumV6(c.m.SrcIP, c.m.DstIP, proto, l4len)
	} else {
		pseudo = pseudoHeaderSumV4(c.m.SrcIP, c.m.DstIP, proto, l4len)
	}
	if checksumPseudoWith(pseudo, b[:l4len]) == 0 {
		field.Value = "correct"
	} else {
		field.Value = "incorrect (or checksum offload)"
		field.Severity = "warn"
	}
	if proto == 17 && c.m.IPVersion == 4 && be16(b[csOff:csOff+2]) == 0 {
		field.Value = "not present (IPv4 UDP)"
		field.Severity = ""
	}
	return field
}

func checksumPseudoWith(pseudo uint32, b []byte) uint16 {
	return foldChecksum(pseudo + onesComplementSum(b))
}

var tcpFlagDefs = []struct {
	bit  uint8
	name string
}{
	{0x01, "FIN"},
	{0x02, "SYN"},
	{0x04, "RST"},
	{0x08, "PSH"},
	{0x10, "ACK"},
	{0x20, "URG"},
	{0x40, "ECE"},
	{0x80, "CWR"},
}

func tcpFlagNames(flags uint8) []string {
	var out []string
	for _, f := range tcpFlagDefs {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

func (c *ctx) dissectTCP(b []byte, base int, src, dst netip.Addr, l4len int) {
	c.addLayer("tcp")
	if len(b) < 20 {
		c.addRoot(c.newNode("Transmission Control Protocol (truncated)", base, len(b)))
		return
	}
	if l4len > len(b) {
		l4len = len(b)
	}
	sport := be16(b[0:2])
	dport := be16(b[2:4])
	seq := be32(b[4:8])
	ack := be32(b[8:12])
	doff := int(b[12]>>4) * 4
	flags := b[13]
	win := be16(b[14:16])
	payload := []byte{}
	if doff >= 20 && doff <= len(b) {
		payload = b[doff:l4len]
	} else if doff >= 20 {
		payload = []byte{}
	} else {
		doff = 20
	}

	c.m.SrcPort, c.m.DstPort = sport, dport
	c.m.TCPFlags = flags
	c.m.TCPSeq = seq
	c.m.TCPAck = ack
	c.m.TCPWin = win
	c.m.TCPPayLen = len(payload)
	c.m.TCPPayload = payload
	c.m.Payload = payload

	if !c.noFields {
		root := c.newNode(fmt.Sprintf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Len: %d", sport, dport, seq, len(payload)), base, min(l4len, len(b)))
		root.add(
			c.newField(fmt.Sprintf("Source Port: %d", sport), "", base, 2),
			c.newField(fmt.Sprintf("Destination Port: %d", dport), "", base+2, 2),
			c.newField(fmt.Sprintf("Sequence Number (raw): %d", seq), "", base+4, 4),
			c.newField(fmt.Sprintf("Acknowledgment Number (raw): %d", ack), "", base+8, 4),
			c.newField(fmt.Sprintf("Header Length: %d bytes (%d)", doff, b[12]>>4), "", base+12, 1),
		)

		flagNode := c.newField(fmt.Sprintf("Flags: 0x%03x", int(b[12]&1)<<8|int(flags)), "", base+12, 2)
		for _, f := range tcpFlagDefs {
			flagNode.add(c.newField(fmt.Sprintf("%s: %d", f.name, boolInt(flags&f.bit != 0)), "", base+13, 1))
		}
		root.add(flagNode,
			c.newField(fmt.Sprintf("Window: %d", win), "", base+14, 2),
			c.transportChecksum(b, base, sport, dport, 6, l4len, 16),
			c.newField(fmt.Sprintf("Urgent Pointer: %d", be16(b[18:20])), "", base+18, 2),
		)

		if doff > 20 && len(b) >= doff {
			root.add(c.tcpOptions(b[20:doff], base+20))
		}
		if len(payload) > 0 {
			p := c.newField(fmt.Sprintf("TCP payload (%d bytes)", len(payload)), hexPreview(payload, 32), base+doff, len(payload))
			root.add(p)
		}
		c.addRoot(root)
	}

	srcPort, dstPort := sport, dport
	info := fmt.Sprintf("%d → %d [%s]", srcPort, dstPort, strings.Join(tcpFlagNames(flags), ", "))
	if strings.HasSuffix(info, "[]") {
		info = fmt.Sprintf("%d → %d", srcPort, dstPort)
	}
	var parts []string
	parts = append(parts, info)
	if len(tcpFlagNames(flags)) > 0 {
		parts = append(parts, fmt.Sprintf("Seq=%d", seq))
	}
	if flags&0x10 != 0 {
		parts = append(parts, fmt.Sprintf("Ack=%d", ack))
	}
	parts = append(parts, fmt.Sprintf("Win=%d", win), fmt.Sprintf("Len=%d", len(payload)))
	c.appInfo = strings.Join(parts, " ")

	c.dissectTCPPayload(payload, base+doff, sport, dport)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c *ctx) tcpOptions(b []byte, base int) *Field {
	node := c.newNode(fmt.Sprintf("Options: (%d bytes)", len(b)), base, len(b))
	off := 0
	for off < len(b) {
		kind := b[off]
		switch kind {
		case 0:
			node.add(c.newField("End of Option List (EOL)", "", base+off, 1))
			return node
		case 1:
			node.add(c.newField("No-Operation (NOP)", "", base+off, 1))
			off++
		case 2:
			if off+4 > len(b) {
				return node
			}
			node.add(c.newField(fmt.Sprintf("Maximum Segment Size: %d bytes", be16(b[off+2:off+4])), "", base+off, 4))
			off += 4
		case 3:
			if off+3 > len(b) {
				return node
			}
			node.add(c.newField(fmt.Sprintf("Window Scale: %d (multiply by %d)", b[off+2], 1<<b[off+2]), "", base+off, 3))
			off += 3
		case 4:
			node.add(c.newField("SACK permitted", "", base+off, 2))
			off += 2
		case 5:
			if off+2 > len(b) {
				return node
			}
			l := int(b[off+1])
			if l < 2 || off+l > len(b) {
				return node
			}
			node.add(c.newField(fmt.Sprintf("SACK: %d blocks", (l-2)/8), hexBytes(b[off+2:off+l], 64), base+off, l))
			off += l
		case 8:
			if off+10 > len(b) {
				return node
			}
			node.add(c.newField(fmt.Sprintf("Timestamps: TSval %d, TSecr %d", be32(b[off+2:off+6]), be32(b[off+6:off+10])), "", base+off, 10))
			off += 10
		default:
			if off+2 > len(b) {
				return node
			}
			l := int(b[off+1])
			if l < 2 || off+l > len(b) {
				return node
			}
			node.add(c.newField(fmt.Sprintf("Unknown option %d (%d bytes)", kind, l), hexBytes(b[off+2:off+l], 32), base+off, l))
			off += l
		}
	}
	return node
}

func (c *ctx) dissectUDP(b []byte, base int, src, dst netip.Addr, l4len int) {
	c.addLayer("udp")
	if len(b) < 8 {
		c.addRoot(c.newNode("User Datagram Protocol (truncated)", base, len(b)))
		return
	}
	sport := be16(b[0:2])
	dport := be16(b[2:4])
	udpLen := int(be16(b[4:6]))
	if udpLen < 8 || udpLen > len(b) {
		udpLen = len(b)
	}
	c.m.SrcPort, c.m.DstPort = sport, dport
	c.m.UDPLen = udpLen - 8
	c.m.IPProto = 17

	payload := b[8:udpLen]
	c.m.Payload = payload

	if !c.noFields {
		root := c.newNode(fmt.Sprintf("User Datagram Protocol, Src Port: %d, Dst Port: %d", sport, dport), base, udpLen)
		root.add(
			c.newField(fmt.Sprintf("Source Port: %d", sport), "", base, 2),
			c.newField(fmt.Sprintf("Destination Port: %d", dport), "", base+2, 2),
			c.newField(fmt.Sprintf("Length: %d", udpLen), "", base+4, 2),
			c.transportChecksum(b, base, sport, dport, 17, udpLen, 6),
		)
		if len(payload) > 0 {
			root.add(c.newField(fmt.Sprintf("UDP payload (%d bytes)", len(payload)), hexPreview(payload, 32), base+8, len(payload)))
		}
		c.addRoot(root)
	}

	c.appInfo = fmt.Sprintf("%d → %d Len=%d", sport, dport, len(payload))

	if !c.dissectUDPPayload(payload, base+8, sport, dport) && len(payload) > 0 && !c.noFields {
		c.addLayer("data")
		c.addRoot(c.newField(fmt.Sprintf("Data (%d bytes)", len(payload)), hexPreview(payload, 64), base+8, len(payload)))
	}
}

func (c *ctx) dissectICMP(b []byte, base int) {
	c.addLayer("icmp")
	if len(b) < 8 {
		c.addRoot(c.newNode("Internet Control Message Protocol (truncated)", base, len(b)))
		return
	}
	typ, code := b[0], b[1]
	c.m.ICMPType, c.m.ICMPCode = typ, code

	root := c.newNode(fmt.Sprintf("Internet Control Message Protocol (%s)", icmpTypeName(typ, code)), base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Type: %d (%s)", typ, icmpTypeName(typ, code)), "", base, 1),
		c.newField(fmt.Sprintf("Code: %d", code), "", base+1, 1),
	)
	cs := c.newField(fmt.Sprintf("Checksum: 0x%04x", be16(b[2:4])), "", base+2, 2)
	if checksum(b) == 0 {
		cs.Value = "correct"
	} else {
		cs.Value = "incorrect"
		cs.Severity = "warn"
	}
	root.add(cs)

	switch typ {
	case 0, 8:
		id := be16(b[4:6])
		seq := be16(b[6:8])
		root.add(
			c.newField(fmt.Sprintf("Identifier: 0x%04x (%d)", id, id), "", base+4, 2),
			c.newField(fmt.Sprintf("Sequence Number: %d", seq), "", base+6, 2),
		)
		if typ == 8 {
			c.appInfo = fmt.Sprintf("Echo (ping) request  id=0x%04x, seq=%d", id, seq)
		} else {
			c.appInfo = fmt.Sprintf("Echo (ping) reply    id=0x%04x, seq=%d", id, seq)
		}
	case 3:
		root.add(c.newField(fmt.Sprintf("Unused: 0x%08x", be32(b[4:8])), "", base+4, 4))
		c.appInfo = fmt.Sprintf("Destination unreachable (%s)", icmpCodeName(typ, code))
	case 11:
		c.appInfo = "Time-to-live exceeded"
	case 5:
		root.add(c.newField("Gateway address: "+ip4String(be32(b[4:8])), "", base+4, 4))
		c.appInfo = "Redirect"
	default:
		c.appInfo = icmpTypeName(typ, code)
	}
	c.addRoot(root)

	if len(b) > 8 {
		c.dissectData(b[8:], base+8)
	}
}

func (c *ctx) dissectICMPv6(b []byte, base int, src, dst netip.Addr) {
	c.addLayer("icmpv6")
	if len(b) < 4 {
		c.addRoot(c.newNode("Internet Control Message Protocol v6 (truncated)", base, len(b)))
		return
	}
	typ, code := b[0], b[1]
	c.m.ICMPType, c.m.ICMPCode = typ, code

	root := c.newNode(fmt.Sprintf("Internet Control Message Protocol v6 (%s)", icmpv6TypeName(typ, code)), base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Type: %d (%s)", typ, icmpv6TypeName(typ, code)), "", base, 1),
		c.newField(fmt.Sprintf("Code: %d", code), "", base+1, 1),
	)
	cs := c.newField(fmt.Sprintf("Checksum: 0x%04x", be16(b[2:4])), "", base+2, 2)
	pseudo := pseudoHeaderSumV6(src, dst, 58, len(b))
	if checksumPseudoWith(pseudo, b) == 0 {
		cs.Value = "correct"
	} else {
		cs.Value = "incorrect"
		cs.Severity = "warn"
	}
	root.add(cs)

	if (typ == 128 || typ == 129) && len(b) >= 8 {
		id := be16(b[4:6])
		seq := be16(b[6:8])
		root.add(
			c.newField(fmt.Sprintf("Identifier: 0x%04x (%d)", id, id), "", base+4, 2),
			c.newField(fmt.Sprintf("Sequence Number: %d", seq), "", base+6, 2),
		)
		if typ == 128 {
			c.appInfo = fmt.Sprintf("Echo (ping) request  id=0x%04x, seq=%d", id, seq)
		} else {
			c.appInfo = fmt.Sprintf("Echo (ping) reply    id=0x%04x, seq=%d", id, seq)
		}
	} else {
		c.appInfo = icmpv6TypeName(typ, code)
	}
	c.addRoot(root)
}

func icmpTypeName(typ, code uint8) string {
	switch typ {
	case 0:
		return "Echo (ping) reply"
	case 3:
		return "Destination unreachable (" + icmpCodeName(typ, code) + ")"
	case 5:
		return "Redirect"
	case 8:
		return "Echo (ping) request"
	case 11:
		return "Time-to-live exceeded"
	case 13:
		return "Timestamp request"
	case 14:
		return "Timestamp reply"
	}
	return fmt.Sprintf("Type %d", typ)
}

func icmpCodeName(typ, code uint8) string {
	if typ == 3 {
		switch code {
		case 0:
			return "net unreachable"
		case 1:
			return "host unreachable"
		case 2:
			return "protocol unreachable"
		case 3:
			return "port unreachable"
		case 4:
			return "fragmentation needed"
		case 13:
			return "communication administratively filtered"
		}
	}
	return fmt.Sprintf("code %d", code)
}

func icmpv6TypeName(typ, code uint8) string {
	switch typ {
	case 1:
		return "Destination unreachable"
	case 2:
		return "Packet too big"
	case 3:
		return "Time exceeded"
	case 4:
		return "Parameter problem"
	case 128:
		return "Echo (ping) request"
	case 129:
		return "Echo (ping) reply"
	case 133:
		return "Router solicitation"
	case 134:
		return "Router advertisement"
	case 135:
		return "Neighbor solicitation"
	case 136:
		return "Neighbor advertisement"
	}
	return fmt.Sprintf("Type %d, code %d", typ, code)
}
