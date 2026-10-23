//go:build full

package decode

import (
	"encoding/json"
	"fmt"
)

var lorawanPacketTypes = map[byte]string{
	0x00: "PUSH_DATA", 0x01: "PUSH_ACK", 0x02: "PULL_DATA", 0x03: "PULL_RESP",
	0x04: "PULL_ACK", 0x05: "TX_ACK",
}

func looksLikeLoRaWAN(b []byte) bool {
	if len(b) < 4 || b[0] != 2 {
		return false
	}
	_, ok := lorawanPacketTypes[b[3]]
	return ok
}

func (c *ctx) dissectLoRaWAN(b []byte, base int) bool {
	if !looksLikeLoRaWAN(b) {
		return false
	}
	typ := b[3]
	name := lorawanPacketTypes[typ]
	c.addLayer("lorawan")
	c.proto = "lorawan"
	root := newNode("LoRaWAN Packet Forwarder "+name, base, len(b))
	root.add(c.newField(fmt.Sprintf("Version: %d", b[0]), "", base, 1),
		c.newField(fmt.Sprintf("Token: 0x%04x", be16(b[1:3])), "", base+1, 2),
		c.newField("Identifier: "+name, "", base+3, 1))
	off := 4
	info := "LoRaWAN " + name
	if typ != 0x01 && typ != 0x04 && len(b) >= 12 {
		root.add(c.newField("Gateway EUI: "+hexPreview(b[4:12], 8), "", base+4, 8))
		off = 12
	}
	if typ == 0x00 || typ == 0x03 || typ == 0x05 {
		if off < len(b) {
			var obj map[string]any
			if err := json.Unmarshal(b[off:], &obj); err == nil {
				if rx, ok := obj["rxpk"].([]any); ok && len(rx) > 0 {
					info += fmt.Sprintf(" rxpk=%d", len(rx))
					if m, ok := rx[0].(map[string]any); ok {
						addLoRaJSONField(c, root, m, "time", base+off)
						addLoRaJSONField(c, root, m, "freq", base+off)
						addLoRaJSONField(c, root, m, "datr", base+off)
						addLoRaJSONField(c, root, m, "codr", base+off)
						addLoRaJSONField(c, root, m, "rssi", base+off)
						addLoRaJSONField(c, root, m, "lsnr", base+off)
					}
				}
				if stat, ok := obj["stat"].(map[string]any); ok {
					addLoRaJSONField(c, root, stat, "time", base+off)
					addLoRaJSONField(c, root, stat, "rxnb", base+off)
					addLoRaJSONField(c, root, stat, "txnb", base+off)
				}
				root.add(c.newField("JSON Payload", printablePreview(b[off:], 240), base+off, len(b)-off))
			} else {
				root.add(c.newField("Payload", printablePreview(b[off:], 120), base+off, len(b)-off))
			}
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func addLoRaJSONField(c *ctx, root *Field, m map[string]any, key string, base int) {
	if v, ok := m[key]; ok {
		root.add(c.newField(key+": "+fmt.Sprint(v), "", base, 0))
	}
}

func init() {
	RegisterPlugin(pluginSpec{Name: "lorawan", Priority: 115, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 1700 || dport == 1700) && looksLikeLoRaWAN(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectLoRaWAN(b, base) }, Display: "LoRaWAN"})
}
