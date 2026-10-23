//go:build full

package decode

import (
	"bytes"
	"fmt"
)

// ------------------------------------------------------------------ HTTP/2

var http2Types = []string{"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func http2SettingName(id uint16) string {
	names := map[uint16]string{1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES"}
	if n := names[id]; n != "" {
		return n
	}
	return fmt.Sprintf("Setting 0x%04x", id)
}

func http2ErrorName(code uint32) string {
	names := map[uint32]string{0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
	if n := names[code]; n != "" {
		return n
	}
	return fmt.Sprintf("Error %d", code)
}

func (c *ctx) dissectHTTP2(b []byte, base int) bool {
	hasPreface := bytes.HasPrefix(b, http2Preface)
	off := 0
	if hasPreface {
		off = len(http2Preface)
	}
	if !hasPreface && !looksLikeHTTP2Frame(b) {
		return false
	}
	flow := h2FlowFor(c)
	if hasPreface {
		flow.observeClient(c)
	}
	c.addLayer("http2")
	c.proto = "http2"
	root := c.newNode("HTTP/2", base, len(b))
	if hasPreface {
		root.add(c.newField("Client Connection Preface", "", base, len(http2Preface)))
	}
	info := "HTTP2"
	for i := 0; i < 128 && off+9 <= len(b); i++ {
		length := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		typ := b[off+3]
		flags := b[off+4]
		stream := be32(b[off+5:off+9]) & 0x7fffffff
		if off+9+length > len(b) {
			break
		}
		name := "UNKNOWN"
		if int(typ) < len(http2Types) {
			name = http2Types[typ]
		}
		f := c.newField(fmt.Sprintf("%s (stream %d, length %d)", name, stream, length), "", base+off, 9+length)
		f.add(
			c.newField(fmt.Sprintf("Length: %d", length), "", base+off, 3),
			c.newField(fmt.Sprintf("Type: %s (%d)", name, typ), "", base+off+3, 1),
			c.newField(fmt.Sprintf("Flags: 0x%02x", flags), "", base+off+4, 1),
			c.newField(fmt.Sprintf("Stream Identifier: %d", stream), "", base+off+5, 4),
		)
		body := b[off+9 : off+9+length]
		consumed := 0
		switch typ {
		case 4: // SETTINGS
			if flags&1 != 0 {
				f.add(c.newField("ACK: 1", "", base+off+4, 1))
			}
			for p := 0; p+6 <= len(body); p += 6 {
				id := be16(body[p : p+2])
				val := be32(body[p+2 : p+6])
				f.add(c.newField(fmt.Sprintf("%s: %d", http2SettingName(id), val), "", base+off+9+p, 6))
			}
		case 6: // PING
			if len(body) == 8 {
				f.add(c.newField("Opaque Data: "+hexPreview(body, 8), "", base+off+9, 8))
			}
			if flags&1 != 0 {
				f.add(c.newField("ACK: 1", "", base+off+4, 1))
			}
		case 7: // GOAWAY
			if len(body) >= 8 {
				f.add(c.newField(fmt.Sprintf("Last Stream ID: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4))
				code := be32(body[4:8])
				f.add(c.newField(fmt.Sprintf("Error Code: %s (%d)", http2ErrorName(code), code), "", base+off+9+4, 4))
				if len(body) > 8 {
					f.add(c.newField("Debug Data: "+printablePreview(body[8:], 160), "", base+off+9+8, len(body)-8))
				}
			}
		case 3: // RST_STREAM
			if len(body) >= 4 {
				code := be32(body[0:4])
				f.add(c.newField(fmt.Sprintf("Error Code: %s (%d)", http2ErrorName(code), code), "", base+off+9, 4))
			}
		case 8: // WINDOW_UPDATE
			if len(body) >= 4 {
				f.add(c.newField(fmt.Sprintf("Window Size Increment: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4))
			}
		case 2: // PRIORITY
			if len(body) >= 5 {
				f.add(c.newField(fmt.Sprintf("Exclusive: %d", body[0]>>7), "", base+off+9, 1), c.newField(fmt.Sprintf("Depends On: %d", be32(body[0:4])&0x7fffffff), "", base+off+9, 4), c.newField(fmt.Sprintf("Weight: %d", int(body[4])+1), "", base+off+9+4, 1))
			}
		case 0, 1, 9, 5: // DATA / HEADERS / CONTINUATION / PUSH_PROMISE
			hdrOff := 0
			block := body
			if typ == 1 {
				if flags&0x08 != 0 && len(block) > 0 {
					pad := int(block[0])
					hdrOff++
					if pad <= len(block)-1 {
						block = block[1 : len(block)-pad]
					}
				}
				if flags&0x20 != 0 && len(block) >= 5 {
					f.add(c.newField(fmt.Sprintf("Exclusive: %d", block[0]>>7), "", base+off+9+hdrOff, 1), c.newField(fmt.Sprintf("Stream Dependency: %d", be32(block[0:4])&0x7fffffff), "", base+off+9+hdrOff, 4), c.newField(fmt.Sprintf("Weight: %d", int(block[4])+1), "", base+off+9+hdrOff+4, 1))
					block = block[5:]
					hdrOff += 5
				}
			} else if typ == 5 {
				if len(block) < 4 {
					break
				}
				f.add(c.newField(fmt.Sprintf("Promised Stream ID: %d", be32(block[0:4])&0x7fffffff), "", base+off+9, 4))
				block = block[4:]
				hdrOff = 4
			}
			if typ == 0 {
				f.add(c.newField(fmt.Sprintf("Payload (%d bytes)", len(body)), printablePreview(body, 300), base+off+9, len(body)))
				if summary, ok := c.dissectGRPC(body, base+off+9, f); ok {
					info = summary
				} else {
					path, ct := flow.meta(stream)
					if summary, ok := c.dissectAI(body, base+off+9, f, path, ct, false); ok {
						info = summary
					}
				}
				break
			}
			seq, blockOff := c.m.TCPSeq, base+off+9+hdrOff
			if typ == 9 {
				combined, pseq, poff, ready := flow.continuePending(stream, block, flags&0x4 != 0)
				if !ready {
					f.add(c.newField(fmt.Sprintf("Header block fragment (%d bytes)", len(block)), hexPreview(block, 48), blockOff, len(block)))
					break
				}
				block, seq, blockOff = combined, pseq, poff
			}
			// HEADERS may be followed by CONTINUATION frames in the same TCP segment.
			if typ == 1 {
				q := off + 9 + length
				endSeen := flags&0x4 != 0
				for q+9 <= len(b) && b[q+3] == 9 {
					cl := int(b[q])<<16 | int(b[q+1])<<8 | int(b[q+2])
					cs := be32(b[q+5:q+9]) & 0x7fffffff
					if cs != stream || q+9+cl > len(b) {
						break
					}
					block = append(block, b[q+9:q+9+cl]...)
					if b[q+4]&0x4 != 0 {
						endSeen = true
					}
					f.add(c.newField(fmt.Sprintf("CONTINUATION (length %d)", cl), "", base+q, 9+cl))
					q += 9 + cl
				}
				consumed = q - off
				if !endSeen {
					flow.startPending(stream, block, c.m.TCPSeq, blockOff)
					f.add(c.newField(fmt.Sprintf("Header block fragment (%d bytes)", len(block)), hexPreview(block, 48), blockOff, len(block)))
					break
				}
			}
			fields, err := flow.decodeHeaders(c, block, seq, blockOff)
			if err != nil {
				f.add(c.newField("HPACK decode error: "+err.Error(), hexPreview(block, 64), base+off+9+hdrOff, len(block)))
				break
			}
			hn := c.newField(fmt.Sprintf("Decoded Headers (%d)", len(fields)), "", base+off+9+hdrOff, len(block))
			var h2Path, h2CT string
			for _, hf := range fields {
				hn.add(c.newField(hf.Name+": "+hf.Value, "", 0, 0))
				if hf.Name == ":path" {
					h2Path = hf.Value
				}
				if hf.Name == "content-type" {
					h2CT = hf.Value
				}
				if hf.Name == ":method" || hf.Name == ":path" || hf.Name == ":status" || hf.Name == ":authority" {
					if info == "HTTP2" {
						info += " " + hf.Name + "=" + hf.Value
					}
				}
			}
			f.add(hn)
			if h2Path != "" || h2CT != "" {
				flow.setMeta(stream, h2Path, h2CT)
			}
		}
		root.add(f)
		if i == 0 {
			info += " " + name
		}
		if consumed > 0 {
			off += consumed
		} else {
			off += 9 + length
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func looksLikeHTTP2Frame(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	l := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	typ := b[3]
	stream := be32(b[5:9]) & 0x7fffffff
	if l > 1<<20 || typ > 9 {
		return false
	}
	if (typ == 4 || typ == 6) && stream != 0 {
		return false
	}
	if stream >= 1<<31 {
		return false
	}
	return b[4] < 0x40
}

func init() {
	RegisterPlugin(pluginSpec{Name: "http2", Priority: 20, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return looksLikeHTTP2(b) || ((httpPorts[sport] || httpPorts[dport]) && looksLikeHTTP2Frame(b))
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectHTTP2(b, base) }, Display: "HTTP/2"})
	RegisterPlugin(pluginSpec{Name: "http2", Priority: 20, Decrypted: true,
		Match: func(_ *ctx, _, _ uint16, b []byte) bool {
			return bytesHasPrefixFold(b, "PRI * HTTP/2.0") || looksLikeHTTP2Frame(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectHTTP2(b, base) }, Display: "HTTP/2"})
}
