//go:build full

package decode

import (
	"fmt"
	"strconv"
)

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

func init() {
	RegisterPlugin(pluginSpec{Name: "websocket", Priority: 150, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (httpPorts[sport] || httpPorts[dport] || tlsPorts[sport] || tlsPorts[dport]) && looksLikeWebSocketFrame(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectWebSocket(b, base) }, Display: "WebSocket"})
	RegisterPlugin(pluginSpec{Name: "websocket", Priority: 10, Decrypted: true,
		Match:   func(_ *ctx, _, _ uint16, b []byte) bool { return looksLikeWebSocketFrame(b) },
		Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectWebSocket(b, base) }, Display: "WebSocket"})
}
