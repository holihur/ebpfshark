//go:build full

package decode

import "fmt"

// ---------------------------------------------------------------- RTP/RTCP

func looksLikeRTP(b []byte) bool {
	if len(b) < 12 || b[0]>>6 != 2 {
		return false
	}
	pt := b[1] & 0x7f
	if pt > 127 {
		return false
	}
	cc := int(b[0] & 0x0f)
	if 12+cc*4 > len(b) {
		return false
	}
	return true
}

func (c *ctx) dissectRTP(b []byte, base int) bool {
	if !looksLikeRTP(b) {
		return false
	}
	if pt := b[1] & 0x7f; pt >= 72 && pt <= 76 {
		return c.dissectRTCP(b, base)
	}
	c.addLayer("rtp")
	c.proto = "rtp"
	cc := int(b[0] & 0x0f)
	ext := b[0]&0x10 != 0
	pad := b[0]&0x20 != 0
	off := 12 + cc*4
	if off > len(b) {
		return false
	}
	root := newNode(fmt.Sprintf("RTP PT=%d", b[1]&0x7f), base, len(b))
	root.add(newField(fmt.Sprintf("Version: %d", b[0]>>6), "", base, 1), newField(fmt.Sprintf("Payload Type: %d", b[1]&0x7f), "", base+1, 1), newField(fmt.Sprintf("Sequence: %d", be16(b[2:4])), "", base+2, 2), newField(fmt.Sprintf("Timestamp: %d", be32(b[4:8])), "", base+4, 4), newField(fmt.Sprintf("SSRC: 0x%08x", be32(b[8:12])), "", base+8, 4))
	if cc > 0 {
		root.add(newField(fmt.Sprintf("CSRC: %d", cc), "", base+12, cc*4))
	}
	if ext && off+4 <= len(b) {
		xlen := int(be16(b[off+2:off+4])) * 4
		root.add(newField(fmt.Sprintf("Extension (%d bytes)", xlen), "", base+off, 4+xlen))
		off += 4 + xlen
		if off > len(b) {
			off = len(b)
		}
	}
	if pad && len(b) > off {
		padLen := int(b[len(b)-1])
		if padLen > len(b)-off {
			off = len(b)
		} else {
			off = len(b) - padLen
		}
	}
	if off < len(b) {
		payload := b[off:]
		root.add(newField(fmt.Sprintf("Payload (%d bytes, %s)", len(payload), rtpPayloadName(b[1]&0x7f)), hexPreview(payload, 32), base+off, len(payload)))
		c.dissectRTPMedia(b[1]&0x7f, payload, base+off, root)
	}
	c.addRoot(root)
	c.appInfo = fmt.Sprintf("RTP PT=%d seq=%d", b[1]&0x7f, be16(b[2:4]))
	return true
}

func (c *ctx) dissectRTCP(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	pt := b[1]
	names := map[byte]string{200: "Sender Report", 201: "Receiver Report", 202: "SDES", 203: "BYE", 204: "APP"}
	name := names[pt]
	if name == "" {
		return false
	}
	l := (int(be16(b[2:4])) + 1) * 4
	if l > len(b) {
		l = len(b)
	}
	c.addLayer("rtcp")
	c.proto = "rtcp"
	root := newNode("RTCP "+name, base, l)
	root.add(newField(fmt.Sprintf("Version: %d", b[0]>>6), "", base, 1), newField("Packet Type: "+name, "", base+1, 1), newField(fmt.Sprintf("Length: %d", l), "", base+2, 2), newField(fmt.Sprintf("SSRC: 0x%08x", be32(b[4:8])), "", base+4, 4))
	c.addRoot(root)
	c.appInfo = "RTCP " + name
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "rtp", Priority: 130, Transport: TransportUDP | TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 5004 || dport == 5004 || sport == 5005 || dport == 5005) && looksLikeRTP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectRTP(b, base) }, Display: "RTP"})
}
