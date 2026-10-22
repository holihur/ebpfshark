//go:build full

package decode

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- MySQL

func le24(b []byte) int { return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 }

func mysqlCString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	if i := strings.IndexByte(string(b[off:]), 0); i >= 0 {
		return string(b[off : off+i]), off + i + 1, true
	}
	return string(b[off:]), len(b), true
}

func mysqlLenEnc(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, off, false
	}
	switch b[off] {
	case 0xfc:
		if off+3 > len(b) {
			return 0, off, false
		}
		return uint64(be16(b[off+1 : off+3])), off + 3, true
	case 0xfd:
		if off+4 > len(b) {
			return 0, off, false
		}
		return uint64(le24(b[off+1 : off+4])), off + 4, true
	case 0xfe:
		if off+9 > len(b) {
			return 0, off, false
		}
		return be64(b[off+1 : off+9]), off + 9, true
	case 0xfb:
		return 0, off + 1, true
	}
	return uint64(b[off]), off + 1, true
}

func (c *ctx) dissectMySQL(b []byte, base int) bool {
	if len(b) < 5 {
		return false
	}
	l := le24(b)
	if l < 1 || l > 16<<20 || 4+l > len(b) {
		return false
	}
	seq := b[3]
	payload := b[4 : 4+l]
	c.addLayer("mysql")
	c.proto = "mysql"
	root := newNode("MySQL", base, 4+l)
	root.add(
		newField(fmt.Sprintf("Packet Length: %d", l), "", base, 3),
		newField(fmt.Sprintf("Sequence ID: %d", seq), "", base+3, 1),
	)
	info := "MySQL"
	p := 0
	switch payload[0] {
	case 0x00:
		root.add(newField("OK Packet", "", base+4, 1))
		info = "MySQL OK"
	case 0xff:
		code := be16(payload[1:3])
		msg, _, _ := mysqlCString(payload, 3)
		root.add(newField(fmt.Sprintf("Error Code: %d", code), "", base+5, 2), newField("SQL State / Message: "+shorten(msg, 120), "", 0, 0))
		info = fmt.Sprintf("MySQL Error %d", code)
	case 0x0a:
		ver, n, _ := mysqlCString(payload, 1)
		root.add(newField("Protocol Version: 10", "", base+4, 1), newField("Server Version: "+ver, "", base+5, n-1))
		if n+4+8+1+2 <= len(payload) {
			p = n + 4 + 8 + 1
			caps := be16(payload[p : p+2])
			root.add(newField(fmt.Sprintf("Capabilities: 0x%04x", caps), "", base+4+p, 2))
		}
		info = "MySQL Handshake " + ver
	case 0x03:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_QUERY: "+shorten(q, 200), "", base+4, len(payload)-1))
		info = "MySQL Query " + shorten(q, 80)
	case 0x02:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_INIT_DB: "+q, "", base+4, len(payload)-1))
		info = "MySQL Init DB " + q
	case 0x16:
		q, _, _ := mysqlCString(payload, 1)
		root.add(newField("COM_STMT_PREPARE: "+shorten(q, 200), "", base+4, len(payload)-1))
		info = "MySQL Prepare " + shorten(q, 80)
	case 0x17:
		root.add(newField(fmt.Sprintf("COM_STMT_EXECUTE (%d bytes)", len(payload)), "", base+4, len(payload)))
		info = "MySQL Execute"
	default:
		root.add(newField(fmt.Sprintf("Command: 0x%02x", payload[0]), hexPreview(payload[1:], 48), base+4, len(payload)))
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

// ---------------------------------------------------------------- RADIUS

var radiusCodes = map[byte]string{1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client"}

var radiusAttrs = map[byte]string{1: "User-Name", 2: "User-Password", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type", 7: "Framed-Protocol", 8: "Framed-IP-Address", 18: "Reply-Message", 24: "State", 25: "Class", 26: "Vendor-Specific", 27: "Session-Timeout", 28: "Idle-Timeout", 30: "Called-Station-Id", 31: "Calling-Station-Id", 32: "NAS-Identifier", 40: "Acct-Status-Type", 44: "Acct-Session-Id", 55: "Event-Timestamp", 79: "EAP-Message", 80: "Message-Authenticator"}

func (c *ctx) dissectRADIUS(b []byte, base int) bool {
	if len(b) < 20 {
		return false
	}
	code, id := b[0], b[1]
	l := int(be16(b[2:4]))
	if l < 20 || l > len(b) {
		return false
	}
	name := radiusCodes[code]
	if name == "" {
		return false
	}
	c.addLayer("radius")
	c.proto = "radius"
	root := newNode("RADIUS "+name, base, l)
	root.add(newField("Code: "+name, "", base, 1), newField(fmt.Sprintf("Identifier: %d", id), "", base+1, 1), newField(fmt.Sprintf("Length: %d", l), "", base+2, 2), newField("Authenticator: "+hexPreview(b[4:20], 16), "", base+4, 16))
	info := "RADIUS " + name
	for off := 20; off+2 <= l; {
		t, al := b[off], int(b[off+1])
		if al < 2 || off+al > l {
			break
		}
		v := b[off+2 : off+al]
		an := radiusAttrs[t]
		if an == "" {
			an = fmt.Sprintf("Attribute-%d", t)
		}
		val := string(v)
		if t == 1 || t == 18 || t == 30 || t == 31 || t == 44 {
			info += " " + val
		}
		if t == 2 || t == 4 || t == 8 {
			val = hexPreview(v, 16)
		}
		root.add(newField(an+": "+shorten(val, 120), "", base+off, al))
		off += al
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

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
		root.add(newField(fmt.Sprintf("Payload (%d bytes)", len(b)-off), hexPreview(b[off:], 32), base+off, len(b)-off))
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

// -------------------------------------------------------------- WebSocket

func looksLikeWebSocketFrame(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	op := b[0] & 0x0f
	if op > 10 || op == 3 || op == 4 || op == 5 || op == 6 || op == 7 {
		return false
	}
	if b[1]&0x80 != 0 {
		return true
	}
	return op == 1 || op == 2 || op == 8 || op == 9 || op == 10
}

func (c *ctx) dissectWebSocket(b []byte, base int) bool {
	if !looksLikeWebSocketFrame(b) {
		return false
	}
	op := b[0] & 0x0f
	names := map[byte]string{0: "Continuation", 1: "Text", 2: "Binary", 8: "Close", 9: "Ping", 10: "Pong"}
	name := names[op]
	if name == "" {
		return false
	}
	masked := b[1]&0x80 != 0
	l := int(b[1] & 0x7f)
	off := 2
	if l == 126 {
		if len(b) < 4 {
			return false
		}
		l, off = int(be16(b[2:4])), 4
	} else if l == 127 {
		if len(b) < 10 {
			return false
		}
		l, off = int(be64(b[2:10])), 10
	}
	var mask []byte
	if masked {
		if off+4 > len(b) {
			return false
		}
		mask = b[off : off+4]
		off += 4
	}
	if off+l > len(b) {
		l = len(b) - off
	}
	payload := append([]byte(nil), b[off:off+l]...)
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	c.addLayer("websocket")
	c.proto = "websocket"
	root := newNode("WebSocket "+name, base, off+l)
	root.add(newField(fmt.Sprintf("FIN: %d", (b[0]>>7)&1), "", base, 1), newField("Opcode: "+name, "", base, 1), newField(fmt.Sprintf("Masked: %d", boolInt(masked)), "", base+1, 1), newField(fmt.Sprintf("Payload Length: %d", l), "", base+1, 1))
	if op == 1 || op == 8 {
		root.add(newField("Payload: "+shorten(string(payload), 240), "", base+off, l))
	} else {
		root.add(newField("Payload: "+hexPreview(payload, 48), "", base+off, l))
	}
	c.addRoot(root)
	c.appInfo = "WebSocket " + name
	return true
}

var _ = strconv.Itoa
