//go:build full

package decode

import (
	"fmt"
	"strconv"
)

// ------------------------------------------------------------------ MQTT

var mqttTypes = []string{"RESERVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT"}

func mqttTypeName(t byte) string {
	if int(t) < len(mqttTypes) {
		return mqttTypes[t]
	}
	return fmt.Sprintf("type %d", t)
}

func mqttRemainingLength(b []byte) (int, int, bool) {
	mult, value := 1, 0
	for i := 0; i < 4 && i < len(b); i++ {
		value += int(b[i]&0x7f) * mult
		mult *= 128
		if b[i]&0x80 == 0 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
}

type mqttPropDef struct {
	name string
	kind byte // 1=byte 2=u16 4=u32 v=varint s=string b=binary p=pair
}

var mqttPropDefs = map[byte]mqttPropDef{
	0x01: {"Payload Format Indicator", 1}, 0x02: {"Message Expiry Interval", 4},
	0x03: {"Content Type", 's'}, 0x08: {"Response Topic", 's'},
	0x09: {"Correlation Data", 'b'}, 0x0b: {"Subscription Identifier", 'v'},
	0x11: {"Session Expiry Interval", 4}, 0x12: {"Assigned Client Identifier", 's'},
	0x13: {"Server Keep Alive", 2}, 0x15: {"Authentication Method", 's'},
	0x16: {"Authentication Data", 'b'}, 0x17: {"Request Problem Information", 1},
	0x18: {"Will Delay Interval", 4}, 0x19: {"Request Response Information", 1},
	0x1a: {"Response Information", 's'}, 0x1c: {"Server Reference", 's'},
	0x1f: {"Reason String", 's'}, 0x21: {"Receive Maximum", 2},
	0x22: {"Topic Alias Maximum", 2}, 0x23: {"Topic Alias", 2},
	0x24: {"Maximum QoS", 1}, 0x25: {"Retain Available", 1},
	0x26: {"User Property", 'p'}, 0x27: {"Maximum Packet Size", 4},
	0x28: {"Wildcard Subscription Available", 1}, 0x29: {"Subscription Identifier Available", 1},
	0x2a: {"Shared Subscription Available", 1},
}

func mqttVarint(b []byte, off int) (int, int, bool) {
	mult, value := 1, 0
	for i := 0; i < 4 && off+i < len(b); i++ {
		value += int(b[off+i]&0x7f) * mult
		mult *= 128
		if b[off+i]&0x80 == 0 {
			return value, off + i + 1, true
		}
	}
	return 0, off, false
}

func mqttString(b []byte, off int) (string, int, bool) {
	if off+2 > len(b) {
		return "", off, false
	}
	l := int(be16(b[off : off+2]))
	off += 2
	if off+l > len(b) {
		return "", off, false
	}
	return string(b[off : off+l]), off + l, true
}

func mqttBinary(b []byte, off int) ([]byte, int, bool) {
	if off+2 > len(b) {
		return nil, off, false
	}
	l := int(be16(b[off : off+2]))
	off += 2
	if off+l > len(b) {
		return nil, off, false
	}
	return b[off : off+l], off + l, true
}

func mqttLooksLikeProps(b []byte, off int) bool {
	l, n, ok := mqttVarint(b, off)
	if !ok {
		return false
	}
	if l == 0 {
		// Empty properties are valid in MQTT v5, but treating a v4 payload
		// starting with 0x00 as empty properties corrupts the payload. Require
		// a non-empty, known property for the stateless heuristic.
		return false
	}
	if n >= len(b) {
		return false
	}
	_, known := mqttPropDefs[b[n]]
	return known
}

func mqttParseProps(c *ctx, b []byte, off int) ([]*Field, int) {
	var out []*Field
	propsLen, next, ok := mqttVarint(b, off)
	if !ok || next+propsLen > len(b) {
		return out, off
	}
	end := next + propsLen
	p := next
	for p < end {
		id := b[p]
		p++
		def, ok := mqttPropDefs[id]
		if !ok {
			return out, end
		}
		f := c.newField(fmt.Sprintf("%s (id 0x%02x)", def.name, id), "", 0, 0)
		switch def.kind {
		case 1:
			if p >= end {
				return out, end
			}
			f.Value = strconv.Itoa(int(b[p]))
			p++
		case 2:
			if p+2 > end {
				return out, end
			}
			f.Value = strconv.Itoa(int(be16(b[p : p+2])))
			p += 2
		case 4:
			if p+4 > end {
				return out, end
			}
			f.Value = strconv.FormatUint(uint64(be32(b[p:p+4])), 10)
			p += 4
		case 'v':
			v, n, ok := mqttVarint(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = strconv.Itoa(v)
			p = n
		case 's':
			v, n, ok := mqttString(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = v
			p = n
		case 'b':
			v, n, ok := mqttBinary(b[:end], p)
			if !ok {
				return out, end
			}
			f.Value = hexPreview(v, 48)
			p = n
		case 'p':
			k, n, ok := mqttString(b[:end], p)
			if !ok {
				return out, end
			}
			v, n2, ok := mqttString(b[:end], n)
			if !ok {
				return out, end
			}
			f.Label = k
			f.Value = v
			p = n2
		}
		out = append(out, f)
	}
	return out, end
}

func mqttReason(code byte) string {
	switch code {
	case 0x00:
		return "Success"
	case 0x80:
		return "Unspecified error"
	case 0x81:
		return "Malformed Packet"
	case 0x82:
		return "Protocol Error"
	case 0x83:
		return "Implementation specific error"
	case 0x84:
		return "Unsupported Protocol Version"
	case 0x85:
		return "Client Identifier not valid"
	case 0x86:
		return "Bad User Name or Password"
	case 0x87:
		return "Not authorized"
	case 0x88:
		return "Server unavailable"
	case 0x89:
		return "Server busy"
	case 0x8a:
		return "Banned"
	case 0x8b:
		return "Server shutting down"
	case 0x8c:
		return "Bad authentication method"
	case 0x8d:
		return "Keep Alive timeout"
	case 0x8e:
		return "Session taken over"
	case 0x8f:
		return "Topic Filter invalid"
	case 0x90:
		return "Topic Name invalid"
	case 0x91:
		return "Packet Identifier in use"
	case 0x92:
		return "Packet Identifier not found"
	case 0x93:
		return "Receive Maximum exceeded"
	case 0x94:
		return "Topic Alias invalid"
	case 0x95:
		return "Packet too large"
	case 0x96:
		return "Message rate too high"
	case 0x97:
		return "Quota exceeded"
	case 0x98:
		return "Administrative action"
	case 0x99:
		return "Payload format invalid"
	case 0x9a:
		return "Retain not supported"
	case 0x9b:
		return "QoS not supported"
	case 0x9c:
		return "Use another server"
	case 0x9d:
		return "Server moved"
	case 0x9e:
		return "Shared Subscriptions not supported"
	case 0x9f:
		return "Connection rate exceeded"
	case 0xa0:
		return "Maximum connect time"
	case 0xa1:
		return "Subscription Identifiers not supported"
	case 0xa2:
		return "Wildcard Subscriptions not supported"
	}
	return fmt.Sprintf("Reason 0x%02x", code)
}

func (c *ctx) dissectMQTT(b []byte, base int) bool {
	if len(b) < 2 {
		return false
	}
	pktType := b[0] >> 4
	if pktType == 0 || pktType > 15 {
		return false
	}
	rem, hl, ok := mqttVarint(b, 1)
	if !ok {
		return false
	}
	off := hl
	if off+rem > len(b) {
		rem = len(b) - off
	}
	body := b[off : off+rem]
	c.addLayer("mqtt")
	c.proto = "mqtt"
	root := c.newNode(fmt.Sprintf("MQ Telemetry Transport (%s)", mqttTypeName(pktType)), base, off+rem)
	root.add(
		c.newField(fmt.Sprintf("Packet Type: %s (%d)", mqttTypeName(pktType), pktType), "", base, 1),
		c.newField(fmt.Sprintf("Flags: 0x%x", b[0]&0xf), "", base, 1),
		c.newField(fmt.Sprintf("Remaining Length: %d", rem), "", base+1, hl-1),
	)
	info := "MQTT " + mqttTypeName(pktType)
	p := 0

	switch pktType {
	case 1: // CONNECT
		proto, n, ok := mqttString(body, 0)
		if ok && n < len(body) {
			level := body[n]
			flags := body[n+1]
			keepalive := be16(body[n+2 : n+4])
			root.add(
				c.newField("Protocol Name: "+proto, "", base+off, n),
				c.newField(fmt.Sprintf("Protocol Level: %d", level), "", base+off+n, 1),
				c.newField(fmt.Sprintf("Connect Flags: 0x%02x (username=%d password=%d willRetain=%d willQoS=%d will=%d cleanStart=%d)",
					flags, (flags>>7)&1, (flags>>6)&1, (flags>>5)&1, (flags>>3)&3, (flags>>2)&1, (flags>>1)&1), "", base+off+n+1, 1),
				c.newField(fmt.Sprintf("Keep Alive: %d s", keepalive), "", base+off+n+2, 2),
			)
			p = n + 4
			if level >= 5 {
				props, np := mqttParseProps(c, body, p)
				if len(props) > 0 {
					pn := c.newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			if id, np, ok := mqttString(body, p); ok {
				root.add(c.newField("Client ID: "+id, "", base+off+p, 2+len(id)))
				info += " client=" + id
				p = np
			}
			if flags&0x04 != 0 { // will
				wprops := []*Field(nil)
				if level >= 5 {
					var np int
					wprops, np = mqttParseProps(c, body, p)
					p = np
				}
				wtopic, np, ok := mqttString(body, p)
				if ok {
					wf := c.newField("Will Topic: "+wtopic, "", base+off+p, 2+len(wtopic))
					wf.Children = wprops
					p = np
					if wb, np2, ok := mqttBinary(body, p); ok {
						wf.add(c.newField(fmt.Sprintf("Will Payload (%d bytes)", len(wb)), hexPreview(wb, 32), base+off+p, len(wb)))
						p = np2
					}
					root.add(wf)
				}
			}
			if flags&0x80 != 0 {
				if u, np, ok := mqttString(body, p); ok {
					root.add(c.newField("Username: "+u, "", base+off+p, 2+len(u)))
					info += " user=" + u
					p = np
				}
			}
			if flags&0x40 != 0 {
				if pw, np, ok := mqttBinary(body, p); ok {
					root.add(c.newField(fmt.Sprintf("Password (%d bytes)", len(pw)), hexPreview(pw, 24), base+off+p, len(pw)))
					p = np
				}
			}
		}
	case 2: // CONNACK
		if len(body) >= 2 {
			root.add(c.newField(fmt.Sprintf("Session Present: %d", body[0]&1), "", base+off, 1))
			root.add(c.newField(fmt.Sprintf("Reason Code: %s", mqttReason(body[1])), "", base+off+1, 1))
			p = 2
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(c, body, p)
				if len(props) > 0 {
					pn := c.newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			info = fmt.Sprintf("MQTT CONNACK %s", mqttReason(body[1]))
		}
	case 3: // PUBLISH
		topic, n, ok := mqttString(body, 0)
		if ok {
			qos := (b[0] >> 1) & 3
			retain := b[0] & 1
			root.add(
				c.newField("Topic: "+topic, "", base+off, n),
				c.newField(fmt.Sprintf("QoS: %d", qos), "", base, 1),
				c.newField(fmt.Sprintf("Retain: %d", retain), "", base, 1),
			)
			p = n
			if qos > 0 && p+2 <= len(body) {
				root.add(c.newField(fmt.Sprintf("Packet ID: %d", be16(body[p:p+2])), "", base+off+p, 2))
				p += 2
			}
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(c, body, p)
				if len(props) > 0 {
					pn := c.newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			payload := body[min(p, len(body)):]
			root.add(c.newField(fmt.Sprintf("Payload (%d bytes)", len(payload)), hexPreview(payload, 48), base+off+p, len(payload)))
			info = fmt.Sprintf("MQTT PUBLISH topic=%s (%d bytes)", topic, len(payload))
		}
	case 4, 5, 6, 7, 9, 11: // PUBACK/PUBREC/PUBREL/PUBCOMP/SUBACK/UNSUBACK
		if len(body) >= 2 {
			root.add(c.newField(fmt.Sprintf("Packet ID: %d", be16(body[0:2])), "", base+off, 2))
			p = 2
			if p < len(body) {
				root.add(c.newField("Reason Code: "+mqttReason(body[p]), "", base+off+p, 1))
				p++
			}
			props, np := mqttParseProps(c, body, p)
			if len(props) > 0 {
				pn := c.newField("Properties", "", 0, 0)
				pn.Children = props
				root.add(pn)
			}
			p = np
			for i := 0; p < len(body); i++ {
				root.add(c.newField(fmt.Sprintf("Reason Code %d: %s", i+1, mqttReason(body[p])), "", base+off+p, 1))
				p++
			}
		}
	case 8, 10: // SUBSCRIBE / UNSUBSCRIBE
		if len(body) >= 2 {
			root.add(c.newField(fmt.Sprintf("Packet ID: %d", be16(body[0:2])), "", base+off, 2))
			p = 2
			if mqttLooksLikeProps(body, p) {
				props, np := mqttParseProps(c, body, p)
				if len(props) > 0 {
					pn := c.newField("Properties", "", 0, 0)
					pn.Children = props
					root.add(pn)
				}
				p = np
			}
			for i := 0; p+2 <= len(body); i++ {
				topic, np, ok := mqttString(body, p)
				if !ok {
					break
				}
				f := c.newField(fmt.Sprintf("Topic Filter %d: %s", i+1, topic), "", base+off+p, 2+len(topic))
				p = np
				if pktType == 8 && p < len(body) {
					f.add(c.newField(fmt.Sprintf("Options: 0x%02x (QoS %d)", body[p], body[p]&3), "", base+off+p, 1))
					p++
				}
				root.add(f)
			}
		}
	case 12, 13: // PINGREQ/PINGRESP
	case 14, 15: // DISCONNECT/AUTH
		if p < len(body) {
			root.add(c.newField("Reason Code: "+mqttReason(body[p]), "", base+off+p, 1))
			p++
		}
		props, np := mqttParseProps(c, body, p)
		if len(props) > 0 {
			pn := c.newField("Properties", "", 0, 0)
			pn.Children = props
			root.add(pn)
		}
		p = np
	}
	_ = p
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "mqtt", Priority: 70, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{1883: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectMQTT(b, base) }})
}
