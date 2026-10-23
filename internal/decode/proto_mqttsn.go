//go:build full

package decode

import "fmt"

var mqttsnTypes = map[byte]string{
	0x00: "ADVERTISE", 0x01: "SEARCHGW", 0x02: "GWINFO", 0x04: "CONNECT", 0x05: "CONNACK",
	0x06: "WILLTOPICREQ", 0x07: "WILLTOPIC", 0x08: "WILLMSGREQ", 0x09: "WILLMSG",
	0x0a: "REGISTER", 0x0b: "REGACK", 0x0c: "PUBLISH", 0x0d: "PUBACK", 0x0e: "PUBCOMP",
	0x0f: "PUBREC", 0x10: "PUBREL", 0x12: "SUBSCRIBE", 0x13: "SUBACK",
	0x14: "UNSUBSCRIBE", 0x15: "UNSUBACK", 0x16: "PINGREQ", 0x17: "PINGRESP",
	0x18: "DISCONNECT", 0x1a: "WILLTOPICUPD", 0x1b: "WILLTOPICRESP",
	0x1c: "WILLMSGUPD", 0x1d: "WILLMSGRESP",
}

func looksLikeMQTTSN(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	off := 1
	if b[0] == 0x01 {
		if len(b) < 4 {
			return false
		}
		off = 3
	}
	if off >= len(b) {
		return false
	}
	_, ok := mqttsnTypes[b[off]]
	return ok
}

func (c *ctx) dissectMQTTSN(b []byte, base int) bool {
	if !looksLikeMQTTSN(b) {
		return false
	}
	off := 1
	var length int
	if b[0] == 0x01 {
		if len(b) < 4 {
			return false
		}
		length = int(be16(b[1:3]))
		off = 3
	} else {
		length = int(b[0])
	}
	typ := b[off]
	name := mqttsnTypes[typ]
	off++
	c.addLayer("mqttsn")
	c.proto = "mqttsn"
	root := newNode("MQTT-SN "+name, base, min(len(b), length))
	root.add(c.newField(fmt.Sprintf("Length: %d", length), "", base, 1),
		c.newField("Message Type: "+name, "", base+off-1, 1))
	info := "MQTT-SN " + name
	// Flags are present in CONNECT/PUBLISH/SUBSCRIBE/UNSUBSCRIBE/WILLTOPIC.
	if len(b) > off && (typ == 0x04 || typ == 0x0c || typ == 0x12 || typ == 0x14 || typ == 0x07) {
		flags := b[off]
		root.add(c.newField(fmt.Sprintf("Flags: 0x%02x", flags), "", base+off, 1))
		off++
		if typ == 0x04 && len(b) >= off+4 {
			root.add(c.newField(fmt.Sprintf("Protocol ID: %d", b[off]), "", base+off, 1),
				c.newField(fmt.Sprintf("Duration: %d", be16(b[off+1:off+3])), "", base+off+1, 2))
			off += 3
		}
		if typ == 0x0c && len(b) >= off+4 {
			root.add(c.newField(fmt.Sprintf("Topic ID: %d", be16(b[off:off+2])), "", base+off, 2),
				c.newField(fmt.Sprintf("Message ID: %d", be16(b[off+2:off+4])), "", base+off+2, 2))
			info += fmt.Sprintf(" topic=%d", be16(b[off:off+2]))
			off += 4
		} else if (typ == 0x12 || typ == 0x14) && len(b) >= off+4 {
			root.add(c.newField(fmt.Sprintf("Message ID: %d", be16(b[off:off+2])), "", base+off, 2))
			off += 2
		}
	}
	if off < len(b) {
		root.add(c.newField(fmt.Sprintf("Payload (%d bytes)", len(b)-off), printablePreview(b[off:], 120), base+off, len(b)-off))
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "mqttsn", Priority: 75, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 1883 || dport == 1883 || sport == 1884 || dport == 1884) && looksLikeMQTTSN(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectMQTTSN(b, base) }, Display: "MQTT-SN"})
}
