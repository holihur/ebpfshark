//go:build full

package decode

import "fmt"

var mpegTSStreamTypes = map[byte]string{
	0x01: "MPEG-1 Video", 0x02: "MPEG-2 Video", 0x03: "MPEG-1 Audio", 0x04: "MPEG-2 Audio",
	0x0f: "AAC ADTS", 0x11: "AAC LATM", 0x1b: "H.264", 0x24: "H.265", 0x81: "AC-3",
	0x87: "E-AC-3", 0x90: "PGS", 0x94: "Opus",
}

func looksLikeMPEGTS(b []byte) bool {
	if len(b) < 188 || b[0] != 0x47 {
		return false
	}
	if len(b) >= 376 && b[188] != 0x47 {
		return false
	}
	return true
}

func mpegPTS(b []byte) uint64 {
	if len(b) < 5 {
		return 0
	}
	return (uint64(b[0]>>1)&7)<<30 | uint64(b[1])<<22 | (uint64(b[2]>>1)&0x7f)<<15 | uint64(b[3])<<7 | uint64(b[4]>>1)
}

func (c *ctx) dissectMPEGTS(b []byte, base int) bool {
	if !looksLikeMPEGTS(b) {
		return false
	}
	c.addLayer("mpegts")
	c.proto = "mpegts"
	root := newNode("MPEG-2 Transport Stream", base, len(b))
	packets := 0
	info := "MPEG-TS"
	for off := 0; off+188 <= len(b) && packets < 16; off += 188 {
		p := b[off : off+188]
		if p[0] != 0x47 {
			break
		}
		packets++
		pusi := p[1]&0x40 != 0
		pid := int(p[1]&0x1f)<<8 | int(p[2])
		afc := (p[3] >> 4) & 3
		cc := p[3] & 0x0f
		pkt := c.newNode(fmt.Sprintf("TS Packet PID=0x%04x", pid), base+off, 188)
		pkt.add(c.newField(fmt.Sprintf("PID: %d (0x%04x)", pid, pid), "", base+off+1, 2),
			c.newField(fmt.Sprintf("PUSI: %d", boolInt(pusi)), "", base+off+1, 1),
			c.newField(fmt.Sprintf("Adaptation Field Control: %d", afc), "", base+off+3, 1),
			c.newField(fmt.Sprintf("Continuity Counter: %d", cc), "", base+off+3, 1))
		payloadOff := off + 4
		if p[3]&0x20 != 0 {
			afLen := int(p[4])
			pkt.add(c.newField(fmt.Sprintf("Adaptation Field: %d bytes", afLen), "", base+off+4, 1+afLen))
			if afLen > 0 && 5 < len(p) {
				flags := p[5]
				if flags&0x10 != 0 && afLen >= 7 {
					pcrBase := uint64(p[6])<<25 | uint64(p[7])<<17 | uint64(p[8])<<9 | uint64(p[9])<<1 | uint64(p[10]>>7)
					pkt.add(c.newField(fmt.Sprintf("PCR: %d", pcrBase), "", base+off+6, 6))
				}
			}
			payloadOff = off + 5 + afLen
		}
		if payloadOff >= off+188 || payloadOff >= len(b) {
			root.add(pkt)
			continue
		}
		payload := b[payloadOff : off+188]
		if pusi && pid == 0 && len(payload) >= 8 {
			parseMPEGTSPAT(c, payload, base+payloadOff, pkt, &info)
		}
		if pusi && len(payload) >= 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 1 {
			parseMPEGTSPES(c, payload, base+payloadOff, pkt, &info)
		} else if pusi && len(payload) > 12 && payload[0] == 0 && payload[1] == 0x02 {
			parseMPEGTSPMT(c, payload, base+payloadOff, pkt, &info)
		}
		root.add(pkt)
	}
	root.Label = fmt.Sprintf("MPEG-2 Transport Stream (%d packets)", packets)
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func parseMPEGTSPAT(c *ctx, payload []byte, base int, root *Field, info *string) {
	ptr := int(payload[0])
	if 1+ptr+8 > len(payload) {
		return
	}
	s := payload[1+ptr:]
	if s[0] != 0x00 {
		return
	}
	sectionLen := int(s[1]&0x0f)<<8 | int(s[2])
	if 3+sectionLen > len(s) {
		sectionLen = len(s) - 3
	}
	root.add(c.newField(fmt.Sprintf("PAT Transport Stream ID: %d", be16(s[3:5])), "", base+1+ptr+3, 2))
	end := 3 + sectionLen - 4
	for i := 8; i+4 <= end && i+4 <= len(s); i += 4 {
		program := be16(s[i : i+2])
		pmt := int(s[i+2]&0x1f)<<8 | int(s[i+3])
		root.add(c.newField(fmt.Sprintf("Program %d -> PMT PID 0x%04x", program, pmt), "", base+1+ptr+i, 4))
		*info = fmt.Sprintf("MPEG-TS PAT program=%d", program)
	}
}

func parseMPEGTSPMT(c *ctx, payload []byte, base int, root *Field, info *string) {
	ptr := int(payload[0])
	if 1+ptr+12 > len(payload) {
		return
	}
	s := payload[1+ptr:]
	if s[0] != 0x02 {
		return
	}
	sectionLen := int(s[1]&0x0f)<<8 | int(s[2])
	if 3+sectionLen > len(s) {
		sectionLen = len(s) - 3
	}
	pcr := int(s[8]&0x1f)<<8 | int(s[9])
	progInfo := int(s[10]&0x0f)<<8 | int(s[11])
	root.add(c.newField(fmt.Sprintf("Program Number: %d", be16(s[3:5])), "", base+1+ptr+3, 2),
		c.newField(fmt.Sprintf("PCR PID: 0x%04x", pcr), "", base+1+ptr+8, 2))
	i := 12 + progInfo
	end := 3 + sectionLen - 4
	for i+5 <= end && i+5 <= len(s) {
		st := s[i]
		esPID := int(s[i+1]&0x1f)<<8 | int(s[i+2])
		esInfo := int(s[i+3]&0x0f)<<8 | int(s[i+4])
		name := mpegTSStreamTypes[st]
		if name == "" {
			name = fmt.Sprintf("stream type 0x%02x", st)
		}
		root.add(c.newField(fmt.Sprintf("%s PID 0x%04x", name, esPID), "", base+1+ptr+i, 5))
		*info = "MPEG-TS PMT " + name
		i += 5 + esInfo
	}
}

func parseMPEGTSPES(c *ctx, payload []byte, base int, root *Field, info *string) {
	if len(payload) < 9 {
		return
	}
	streamID := payload[3]
	pesLen := int(be16(payload[4:6]))
	root.add(c.newField(fmt.Sprintf("PES Stream ID: 0x%02x", streamID), "", base+3, 1),
		c.newField(fmt.Sprintf("PES Length: %d", pesLen), "", base+4, 2))
	flags := payload[7]
	if flags&0x80 != 0 && len(payload) >= 14 {
		root.add(c.newField(fmt.Sprintf("PTS: %d", mpegPTS(payload[9:14])), "", base+9, 5))
		if flags&0x40 != 0 && len(payload) >= 19 {
			root.add(c.newField(fmt.Sprintf("DTS: %d", mpegPTS(payload[14:19])), "", base+14, 5))
		}
	}
	*info = fmt.Sprintf("MPEG-TS PES stream=0x%02x len=%d", streamID, pesLen)
}

func init() {
	RegisterPlugin(pluginSpec{Name: "mpegts", Priority: 125, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 1234 || dport == 1234 || looksLikeMPEGTS(b)) && looksLikeMPEGTS(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectMPEGTS(b, base) }, Display: "MPEG-TS"})
}
