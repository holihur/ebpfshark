//go:build full

package decode

import "fmt"

var rtpStaticPayload = map[byte]string{
	0: "PCMU/8000", 3: "GSM/8000", 4: "G723/8000", 5: "DVI4/8000", 6: "DVI4/16000",
	7: "LPC/8000", 8: "PCMA/8000", 9: "G722/8000", 10: "L16/44100", 11: "L16/44100",
	12: "QCELP/8000", 13: "CN/8000", 14: "MPA/90000", 15: "G728/8000", 16: "DVI4/11025",
	17: "DVI4/22050", 18: "G729/8000", 25: "CelB/90000", 26: "JPEG/90000",
	28: "nv/90000", 31: "H261/90000", 32: "MPV/90000", 33: "MP2T/90000",
	34: "H263/90000",
}

func rtpPayloadName(pt byte) string {
	if name := rtpStaticPayload[pt]; name != "" {
		return name
	}
	return fmt.Sprintf("dynamic-%d", pt)
}

var h264NALNames = map[byte]string{
	1: "non-IDR slice", 2: "slice data A", 3: "slice data B", 4: "slice data C",
	5: "IDR slice", 6: "SEI", 7: "SPS", 8: "PPS", 9: "AUD", 10: "end sequence",
	11: "end stream", 12: "filler", 13: "SPS extension", 14: "prefix NAL", 15: "subset SPS",
}

func h264TypeName(t byte) string {
	if n := h264NALNames[t]; n != "" {
		return n
	}
	return fmt.Sprintf("NAL type %d", t)
}

func h264NAL(p []byte) (byte, bool) {
	if len(p) < 1 || p[0]&0x80 != 0 {
		return 0, false
	}
	t := p[0] & 0x1f
	if t == 0 || t > 23 && t != 24 && t != 28 && t != 29 {
		return 0, false
	}
	return t, true
}

func (c *ctx) dissectH264(p []byte, base int, root *Field) bool {
	t, ok := h264NAL(p)
	if !ok {
		return false
	}
	c.addLayer("h264")
	c.proto = "rtp"
	n := c.newField("H.264 RTP payload", "", base, len(p))
	switch {
	case t == 24 && len(p) >= 3: // STAP-A
		n.add(c.newField("Aggregation: STAP-A", "", base, 1))
		for off := 1; off+2 <= len(p); {
			l := int(be16(p[off : off+2]))
			off += 2
			if l <= 0 || off+l > len(p) {
				break
			}
			nt := p[off] & 0x1f
			n.add(c.newField("NAL: "+h264TypeName(nt), "", base+off, l))
			off += l
		}
	case (t == 28 || t == 29) && len(p) >= 2: // FU-A / FU-B
		fu := p[1]
		orig := fu & 0x1f
		n.add(c.newField("Fragmentation Unit", "", base, 2),
			c.newField(fmt.Sprintf("Start: %d End: %d", (fu>>7)&1, (fu>>6)&1), "", base+1, 1),
			c.newField("Original NAL: "+h264TypeName(orig), "", base+1, 1))
	default:
		n.add(c.newField("NAL: "+h264TypeName(t), "", base, 1))
		if t == 7 && len(p) >= 4 {
			n.add(c.newField(fmt.Sprintf("SPS Profile: %d", p[1]), "", base+1, 1),
				c.newField(fmt.Sprintf("SPS Level: %d", p[3]), "", base+3, 1))
		}
		if t == 8 && len(p) >= 2 {
			n.add(c.newField(fmt.Sprintf("PPS ID: %d", p[1]&0x3f), "", base+1, 1))
		}
	}
	root.add(n)
	return true
}

func h265NAL(p []byte) (byte, bool) {
	if len(p) < 2 || p[0]&0x80 != 0 {
		return 0, false
	}
	t := (p[0] >> 1) & 0x3f
	if t > 40 && t < 48 || t > 50 {
		return 0, false
	}
	return t, true
}

var h265NAMES = map[byte]string{32: "VPS", 33: "SPS", 34: "PPS", 35: "AUD", 39: "SEI", 48: "Aggregation", 49: "Fragmentation", 50: "PACI"}

func (c *ctx) dissectH265(p []byte, base int, root *Field) bool {
	t, ok := h265NAL(p)
	if !ok {
		return false
	}
	c.addLayer("h265")
	c.proto = "rtp"
	name := h265NAMES[t]
	if name == "" {
		name = fmt.Sprintf("NAL type %d", t)
	}
	n := c.newField("H.265 RTP payload", "", base, len(p))
	n.add(c.newField("NAL: "+name, "", base, 1))
	if t == 48 && len(p) >= 4 { // AP
		for off := 2; off+2 <= len(p); {
			l := int(be16(p[off : off+2]))
			off += 2
			if l <= 0 || off+l > len(p) {
				break
			}
			nt := (p[off] >> 1) & 0x3f
			n.add(c.newField("NAL: "+h265NAMES[nt], "", base+off, l))
			off += l
		}
	} else if t == 49 && len(p) >= 3 { // FU
		fu := p[2]
		n.add(c.newField(fmt.Sprintf("Start: %d End: %d", (fu>>7)&1, (fu>>6)&1), "", base+2, 1),
			c.newField(fmt.Sprintf("Original NAL: %d", fu&0x3f), "", base+2, 1))
	}
	root.add(n)
	return true
}

func (c *ctx) dissectVP8(p []byte, base int, root *Field) bool {
	if len(p) < 2 || p[0]&0x10 == 0 {
		return false
	} // S bit, beginning of frame
	if p[0]&0x0f > 7 {
		return false
	}
	c.addLayer("vp8")
	c.proto = "rtp"
	n := c.newField("VP8 RTP payload", "", base, len(p))
	n.add(c.newField(fmt.Sprintf("Non-reference: %d", (p[0]>>5)&1), "", base, 1),
		c.newField(fmt.Sprintf("Start of Partition: %d", (p[0]>>4)&1), "", base, 1),
		c.newField(fmt.Sprintf("Partition ID: %d", p[0]&0x0f), "", base, 1))
	if len(p) > 1 {
		n.add(c.newField(fmt.Sprintf("Key Frame: %d", boolInt(p[1]&1 == 0)), "", base+1, 1))
	}
	root.add(n)
	return true
}

func (c *ctx) dissectVP9(p []byte, base int, root *Field) bool {
	if len(p) < 1 || p[0]&0x01 != 0 {
		return false
	} // Z bit must be 0
	c.addLayer("vp9")
	c.proto = "rtp"
	n := c.newField("VP9 RTP payload", "", base, len(p))
	n.add(c.newField(fmt.Sprintf("Inter-picture: %d", (p[0]>>7)&1), "", base, 1),
		c.newField(fmt.Sprintf("Start: %d", (p[0]>>4)&1), "", base, 1))
	root.add(n)
	return true
}

func (c *ctx) dissectAAC(p []byte, base int, root *Field) bool {
	if len(p) < 4 {
		return false
	}
	off := 0
	var units []string
	for off+2 <= len(p) && len(units) < 16 {
		v := be16(p[off : off+2])
		size := int(v >> 3)
		index := v & 7
		if size == 0 || off+2+size > len(p) {
			return false
		}
		units = append(units, fmt.Sprintf("%d bytes (index %d)", size, index))
		off += 2 + size
	}
	if len(units) == 0 {
		return false
	}
	c.addLayer("aac")
	c.proto = "rtp"
	n := c.newField("AAC RTP payload", "", base, len(p))
	for i, u := range units {
		n.add(c.newField(fmt.Sprintf("AU %d: %s", i+1, u), "", base, 0))
	}
	root.add(n)
	return true
}

func (c *ctx) dissectOpus(p []byte, base int, root *Field) bool {
	if len(p) < 1 {
		return false
	}
	toc := p[0]
	config := toc >> 3
	frames := int(toc & 3)
	c.addLayer("opus")
	c.proto = "rtp"
	n := c.newField("Opus RTP payload", "", base, len(p))
	n.add(c.newField(fmt.Sprintf("TOC Config: %d", config), "", base, 1),
		c.newField(fmt.Sprintf("Stereo: %d", (toc>>2)&1), "", base, 1),
		c.newField(fmt.Sprintf("Frame Count: %d", frames+1), "", base, 1))
	root.add(n)
	return true
}

func (c *ctx) dissectRTPMedia(pt byte, p []byte, base int, root *Field) {
	if len(p) == 0 {
		return
	}
	// H.264/H.265 are recognizable from their NAL headers.
	if c.dissectH264(p, base, root) {
		return
	}
	if c.dissectH265(p, base, root) {
		return
	}
	// VP8/VP9 payload descriptors only claim packets that start a frame.
	if c.dissectVP8(p, base, root) {
		return
	}
	if pt == 98 && c.dissectVP9(p, base, root) {
		return
	}
	// Dynamic payload types are convention-based hints, not SDP resolution.
	if (pt == 97 || pt == 98) && c.dissectAAC(p, base, root) {
		return
	}
	if pt == 111 || pt == 112 {
		c.dissectOpus(p, base, root)
	}
}
