//go:build full

package decode

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// CoAP (RFC 7252) over UDP. DTLS (5684) is parsed only when the payload is
// already plaintext; the dissector never attempts to decrypt DTLS.
var coapCodes = map[byte]string{
	1: "GET", 2: "POST", 3: "PUT", 4: "DELETE",
	65: "2.01 Created", 66: "2.02 Deleted", 67: "2.03 Valid", 68: "2.04 Changed", 69: "2.05 Content",
	128: "4.00 Bad Request", 132: "4.04 Not Found", 133: "4.05 Method Not Allowed", 143: "4.13 Request Entity Too Large",
	160: "5.00 Internal Server Error", 161: "5.01 Not Implemented", 163: "5.03 Service Unavailable",
}

func coapTypeName(t byte) string {
	switch t {
	case 0:
		return "CON"
	case 1:
		return "NON"
	case 2:
		return "ACK"
	case 3:
		return "RST"
	}
	return fmt.Sprintf("type%d", t)
}

func coapCodeName(code byte) string {
	if s := coapCodes[code]; s != "" {
		return s
	}
	return fmt.Sprintf("%d.%02d", code>>5, code&0x1f)
}

func coapOptionName(n int) string {
	switch n {
	case 1:
		return "If-Match"
	case 3:
		return "Uri-Host"
	case 4:
		return "ETag"
	case 5:
		return "If-None-Match"
	case 6:
		return "Observe"
	case 7:
		return "Uri-Port"
	case 8:
		return "Location-Path"
	case 11:
		return "Uri-Path"
	case 12:
		return "Content-Format"
	case 14:
		return "Max-Age"
	case 15:
		return "Uri-Query"
	case 17:
		return "Accept"
	case 20:
		return "Location-Query"
	case 23:
		return "Block2"
	case 27:
		return "Block1"
	case 28:
		return "Size2"
	case 35:
		return "Proxy-Uri"
	case 39:
		return "Proxy-Scheme"
	case 60:
		return "Size1"
	}
	return fmt.Sprintf("Option-%d", n)
}

func looksLikeCoAP(b []byte) bool {
	if len(b) < 4 || b[0]>>6 != 1 {
		return false
	}
	tkl := int(b[0] & 0x0f)
	if tkl > 8 || len(b) < 4+tkl {
		return false
	}
	return b[1] != 0 // codes 0.00 are empty/reserved
}

func (c *ctx) dissectCoAP(b []byte, base int) bool {
	if !looksLikeCoAP(b) {
		return false
	}
	tkl := int(b[0] & 0x0f)
	typ := (b[0] >> 4) & 3
	code := b[1]
	msgID := be16(b[2:4])
	off := 4 + tkl
	if off > len(b) {
		return false
	}
	c.addLayer("coap")
	c.proto = "coap"
	root := newNode("Constrained Application Protocol", base, len(b))
	root.add(c.newField("Version: 1", "", base, 1),
		c.newField("Type: "+coapTypeName(typ), "", base, 1),
		c.newField(fmt.Sprintf("Token Length: %d", tkl), "", base, 1),
		c.newField("Code: "+coapCodeName(code), "", base+1, 1),
		c.newField(fmt.Sprintf("Message ID: %d", msgID), "", base+2, 2))
	if tkl > 0 {
		root.add(c.newField("Token: "+hexPreview(b[4:off], 16), "", base+4, tkl))
	}

	var path, query []string
	prev := 0
	for off < len(b) && b[off] != 0xff {
		h := b[off]
		off++
		delta, length := int(h>>4), int(h&0x0f)
		if delta == 13 {
			if off >= len(b) {
				return false
			}
			delta = int(b[off]) + 13
			off++
		} else if delta == 14 {
			if off+2 > len(b) {
				return false
			}
			delta = int(binary.BigEndian.Uint16(b[off:off+2])) + 269
			off += 2
		} else if delta == 15 {
			return false
		}
		if length == 13 {
			if off >= len(b) {
				return false
			}
			length = int(b[off]) + 13
			off++
		} else if length == 14 {
			if off+2 > len(b) {
				return false
			}
			length = int(binary.BigEndian.Uint16(b[off:off+2])) + 269
			off += 2
		} else if length == 15 {
			return false
		}
		if off+length > len(b) {
			return false
		}
		num := prev + delta
		val := b[off : off+length]
		off += length
		prev = num
		name := coapOptionName(num)
		text := string(val)
		switch num {
		case 11:
			path = append(path, text)
		case 15:
			query = append(query, text)
		case 12:
			if len(val) == 2 {
				text = fmt.Sprintf("%d", binary.BigEndian.Uint16(val))
			} else if len(val) == 1 {
				text = fmt.Sprintf("%d", val[0])
			}
		}
		root.add(c.newField(fmt.Sprintf("%s (%d)", name, num), hexPreview(val, 32), base+off-length, length))
	}
	if path != nil || query != nil {
		uri := "/" + strings.Join(path, "/")
		if len(query) > 0 {
			uri += "?" + strings.Join(query, "&")
		}
		root.add(c.newField("Request URI: "+uri, "", base+4+tkl, 0))
	}
	if off < len(b) && b[off] == 0xff {
		off++
		if off < len(b) {
			root.add(c.newField(fmt.Sprintf("Payload (%d bytes)", len(b)-off), printablePreview(b[off:], 120), base+off, len(b)-off))
		}
	}
	info := fmt.Sprintf("CoAP %s %s", coapTypeName(typ), coapCodeName(code))
	if len(path) > 0 {
		info += " /" + strings.Join(path, "/")
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "coap", Priority: 110, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 5683 || dport == 5683 || sport == 5684 || dport == 5684) && looksLikeCoAP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectCoAP(b, base) }, Display: "CoAP"})
}
