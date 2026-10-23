//go:build full

package decode

import (
	"encoding/binary"
	"fmt"
)

var rtmpChunkTypes = map[byte]string{1: "Set Chunk Size", 2: "Abort", 3: "Acknowledgment", 5: "Window Acknowledgement Size", 6: "Set Peer Bandwidth", 8: "Audio", 9: "Video", 15: "AMF3 Data", 17: "AMF3 Command", 18: "AMF0 Data", 20: "AMF0 Command"}

func looksLikeRTMP(b []byte) bool {
	if len(b) >= 1537 && b[0] == 3 {
		return true
	}
	if len(b) < 1 {
		return false
	}
	csid := b[0] & 0x3f
	return csid > 0 && csid < 64
}

func (c *ctx) dissectRTMP(b []byte, base int) bool {
	if len(b) >= 1537 && b[0] == 3 {
		c.addLayer("rtmp")
		c.proto = "rtmp"
		root := newNode("Real Time Messaging Protocol Handshake", base, len(b))
		root.add(c.newField(fmt.Sprintf("Version: %d", b[0]), "", base, 1),
			c.newField(fmt.Sprintf("Time: %d", be32(b[1:5])), "", base+1, 4),
			c.newField(fmt.Sprintf("Zero: %d", be32(b[5:9])), "", base+5, 4),
			c.newField("Random: "+hexPreview(b[9:41], 32), "", base+9, 32))
		c.addRoot(root)
		c.appInfo = "RTMP handshake"
		return true
	}
	c.addLayer("rtmp")
	c.proto = "rtmp"
	root := newNode("RTMP Chunk Stream", base, len(b))
	info := "RTMP chunk"
	off := 0
	for i := 0; i < 16 && off < len(b); i++ {
		start := off
		first := b[off]
		fmtType := first >> 6
		csid := int(first & 0x3f)
		off++
		if csid == 0 {
			if off >= len(b) {
				break
			}
			csid = 64 + int(b[off])
			off++
		} else if csid == 1 {
			if off+2 > len(b) {
				break
			}
			csid = 64 + int(b[off]) + int(b[off+1])*256
			off += 2
		}
		msgLen, msgType, ts := 0, byte(0), uint32(0)
		if fmtType == 0 {
			if off+11 > len(b) {
				break
			}
			ts = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
			msgLen = int(b[off+3])<<16 | int(b[off+4])<<8 | int(b[off+5])
			msgType = b[off+6]
			off += 11
		} else if fmtType == 1 {
			if off+7 > len(b) {
				break
			}
			ts = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
			msgLen = int(b[off+3])<<16 | int(b[off+4])<<8 | int(b[off+5])
			msgType = b[off+6]
			off += 7
		} else if fmtType == 2 {
			if off+3 > len(b) {
				break
			}
			ts = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
			off += 3
		} else if fmtType == 3 {
			// continuation; header is already known from the stream state.
			break
		}
		if msgLen < 0 || off+msgLen > len(b) {
			break
		}
		name := rtmpChunkTypes[msgType]
		if name == "" {
			name = fmt.Sprintf("type %d", msgType)
		}
		n := c.newField(fmt.Sprintf("Chunk fmt=%d csid=%d %s", fmtType, csid, name), "", base+start, off-start+msgLen)
		n.add(c.newField(fmt.Sprintf("Timestamp: %d", ts), "", base+start, 3),
			c.newField(fmt.Sprintf("Message Length: %d", msgLen), "", base+start, 3),
			c.newField("Message Type: "+name, "", base+start, 1))
		if msgType == 20 || msgType == 18 {
			if s, ok := amf0FirstString(b[off : off+msgLen]); ok {
				n.add(c.newField("AMF0: "+s, "", base+off, len(s)))
				info = "RTMP " + s
			}
		}
		root.add(n)
		off += msgLen
	}
	c.addRoot(root)
	c.appInfo = info
	return true
}

func amf0FirstString(b []byte) (string, bool) {
	if len(b) < 3 || b[1] < 1 {
		return "", false
	}
	if b[0] == 0x02 || b[0] == 0x0b || b[0] == 0x0f {
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if n > 0 && 3+n <= len(b) {
			return string(b[3 : 3+n]), true
		}
	}
	return "", false
}

func init() {
	RegisterPlugin(pluginSpec{Name: "rtmp", Priority: 35, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 1935 || dport == 1935) && looksLikeRTMP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectRTMP(b, base) }, Display: "RTMP"})
}
