package decode

import (
	"fmt"
	"net/netip"
	"strings"
)

var sctpChunkNames = map[byte]string{0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 12: "SHUTDOWN_COMPLETE"}

func (c *ctx) dissectSCTP(b []byte, base int) {
	c.addLayer("sctp")
	c.proto = "sctp"
	if len(b) < 12 {
		c.addRoot(c.newNode("SCTP (truncated)", base, len(b)))
		return
	}
	sport, dport := be16(b[0:2]), be16(b[2:4])
	vtag := be32(b[4:8])
	c.m.SrcPort, c.m.DstPort = sport, dport
	c.m.IPProto = 132
	root := c.newNode(fmt.Sprintf("SCTP, Src Port: %d, Dst Port: %d", sport, dport), base, len(b))
	root.add(newField(fmt.Sprintf("Source Port: %d", sport), "", base, 2), newField(fmt.Sprintf("Destination Port: %d", dport), "", base+2, 2), newField(fmt.Sprintf("Verification Tag: 0x%08x", vtag), "", base+4, 4), newField("Checksum: "+hexPreview(b[8:12], 4), "", base+8, 4))
	off := 12
	var chunks []string
	for i := 0; i < 64 && off+4 <= len(b); i++ {
		typ, flags := b[off], b[off+1]
		l := int(be16(b[off+2 : off+4]))
		if l < 4 || off+l > len(b) {
			break
		}
		name := sctpChunkNames[typ]
		if name == "" {
			name = fmt.Sprintf("Chunk %d", typ)
		}
		f := c.newField(fmt.Sprintf("%s (length %d)", name, l), "", base+off, l)
		f.add(newField(fmt.Sprintf("Type: %s (%d)", name, typ), "", base+off, 1), newField(fmt.Sprintf("Flags: 0x%02x", flags), "", base+off+1, 1))
		body := b[off+4 : off+l]
		switch typ {
		case 0:
			if len(body) >= 12 {
				f.add(newField(fmt.Sprintf("TSN: %d", be32(body[0:4])), "", base+off+4, 4), newField(fmt.Sprintf("Stream ID: %d", be16(body[4:6])), "", base+off+8, 2), newField(fmt.Sprintf("Stream Sequence: %d", be16(body[6:8])), "", base+off+10, 2), newField(fmt.Sprintf("PPID: %d", be32(body[8:12])), "", base+off+12, 4), newField(fmt.Sprintf("Payload (%d bytes)", len(body)-12), printablePreview(body[12:], 120), base+off+16, len(body)-12))
			}
		case 1, 2:
			if len(body) >= 16 {
				f.add(newField(fmt.Sprintf("Initiate Tag: 0x%08x", be32(body[0:4])), "", 0, 0), newField(fmt.Sprintf("Advertised Receiver Window: %d", be32(body[4:8])), "", 0, 0), newField(fmt.Sprintf("Outbound Streams: %d", be16(body[8:10])), "", 0, 0), newField(fmt.Sprintf("Inbound Streams: %d", be16(body[10:12])), "", 0, 0), newField(fmt.Sprintf("Initial TSN: %d", be32(body[12:16])), "", 0, 0))
				p := 16
				for p+4 <= len(body) {
					pt, pl := be16(body[p:p+2]), int(be16(body[p+2:p+4]))
					if pl < 4 || p+pl > len(body) {
						break
					}
					pn := map[uint16]string{5: "IPv4 Address", 6: "IPv6 Address", 0xc000: "Forward TSN Supported"}[pt]
					if pn == "" {
						pn = fmt.Sprintf("Parameter %d", pt)
					}
					val := hexPreview(body[p+4:p+pl], 24)
					if pt == 5 && pl >= 8 {
						val = netip.AddrFrom4([4]byte{body[p+4], body[p+5], body[p+6], body[p+7]}).String()
					}
					f.add(newField(pn+": "+val, "", base+off+4+p, pl))
					p += (pl + 3) &^ 3
				}
			}
		case 3:
			if len(body) >= 12 {
				f.add(newField(fmt.Sprintf("Cumulative TSN ACK: %d", be32(body[0:4])), "", 0, 0), newField(fmt.Sprintf("Advertised Window: %d", be32(body[4:8])), "", 0, 0), newField(fmt.Sprintf("Gap ACK Blocks: %d", be16(body[8:10])), "", 0, 0), newField(fmt.Sprintf("Duplicate TSNs: %d", be16(body[10:12])), "", 0, 0))
			}
		case 6, 9:
			if len(body) >= 4 {
				f.add(newField("Cause/Error Code: "+hexPreview(body[0:4], 4), "", 0, 0))
			}
		}
		root.add(f)
		chunks = append(chunks, name)
		off += (l + 3) &^ 3
	}
	c.addRoot(root)
	c.appInfo = fmt.Sprintf("SCTP %d → %d %s", sport, dport, strings.Join(chunks, ", "))
}
